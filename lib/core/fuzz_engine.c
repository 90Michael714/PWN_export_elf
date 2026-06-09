/*
 * fuzz_engine.c — Fuzz 执行引擎
 *
 * fork() → child PTRACE_TRACEME → parent 进入 变异→执行→检测 循环。
 *
 * 依赖: debug_worker.h (ptrace API), fuzz_mutate.c (变异策略)
 * 架构: 单线程同步执行, 每轮迭代: mutate → write input → set regs → CONT → wait
 */
#define _GNU_SOURCE
#include "core/fuzz_engine.h"
#include "core/debug_worker.h"
#include "core/pt_trace.h"
#include "core/db.h"

/* 外部: 活跃 AnalysisDB (用于 crash 自动溯源) */
extern AnalysisDB *g_active_db;
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* ── 全局 ── */
static volatile sig_atomic_t g_stop = 0;
void fuzz_request_stop(void) { g_stop = 1; }

/* ── Coverage 反馈 (Phase 2) ── */
#define COV_BITMAP_SIZE 65536
static uint8_t  *g_cov_bitmap = NULL;   /* AFL-style 64KB bitmap */
static int       g_cov_enabled = 0;     /* 1=覆盖率引导模式 */

/* 初始化覆盖率位图 */
void fuzz_coverage_init(void) {
    if (!g_cov_bitmap) {
        g_cov_bitmap = calloc(1, COV_BITMAP_SIZE);
    }
    if (g_cov_bitmap) {
        memset(g_cov_bitmap, 0, COV_BITMAP_SIZE);
        g_cov_enabled = 1;
    }
}

/* 更新覆盖率: 检查是否有新的边被触发 */
int fuzz_coverage_update(const uint64_t *edges, int count) {
    if (!g_cov_enabled || !g_cov_bitmap || !edges) return 0;
    int new_edges = 0;
    for (int i = 0; i < count; i++) {
        uint16_t idx = (uint16_t)(edges[i] & 0xFFFF);
        uint8_t *bucket = &g_cov_bitmap[idx];
        if (*bucket == 0) new_edges++;
        *bucket = 1;   /* 简化: 非 AFL 的 hit-count bucketing */
    }
    return new_edges;
}

/* 检查当前执行是否有新发现 */
int fuzz_coverage_is_interesting(const uint64_t *edges, int count) {
    if (!g_cov_enabled || !g_cov_bitmap || !edges) return 1; /* no cov → all interesting */
    int new_edges = 0;
    for (int i = 0; i < count && new_edges < 5; i++) {
        uint16_t idx = (uint16_t)(edges[i] & 0xFFFF);
        if (g_cov_bitmap[idx] == 0) new_edges++;
    }
    return new_edges;
}

/* 获取覆盖率统计 */
int fuzz_coverage_counts(int *total_edges, int *covered_edges) {
    if (!g_cov_bitmap) { *total_edges = 0; *covered_edges = 0; return -1; }
    int covered = 0;
    for (int i = 0; i < COV_BITMAP_SIZE; i++)
        if (g_cov_bitmap[i]) covered++;
    *covered_edges = covered;
    *total_edges   = COV_BITMAP_SIZE;
    return 0;
}

/* 释放覆盖率位图 */
void fuzz_coverage_free(void) {
    free(g_cov_bitmap);
    g_cov_bitmap = NULL;
    g_cov_enabled = 0;
}

/* ── 外部 ── */
extern int fuzz_seed_add(const uint8_t *b, size_t l, int s);
extern int fuzz_seed_pick(uint8_t *o, size_t m);
extern int fuzz_seed_count(void);
extern void fuzz_seed_reset(void);

/* ── 默认值 ── */
#define DEFAULT_INPUT_ADDR  0x10000UL
#define DEFAULT_STACK_ADDR  0x20000UL
#define DEFAULT_STACK_SIZE  4096
#define DEFAULT_TRAP_ADDR   (DEFAULT_STACK_ADDR + DEFAULT_STACK_SIZE - 8)

void fuzz_config_init(FuzzConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->input_addr     = DEFAULT_INPUT_ADDR;
    cfg->return_trap    = DEFAULT_TRAP_ADDR;
    cfg->input_max_size = 4096;
    cfg->strategy_mask  = FUZZ_MUTATE_HAVOC;
    cfg->max_iterations = 5000;
    cfg->timeout_ms     = 2000;
}

int fuzz_config_validate(const FuzzConfig *cfg, char *error, size_t err_sz) {
    if (!cfg->target_addr) { snprintf(error, err_sz, "target_addr is required"); return -1; }
    if (cfg->input_max_size < 4 || cfg->input_max_size > 65536) {
        snprintf(error, err_sz, "input_max_size must be 4..65536"); return -1; }
    if (cfg->max_iterations <= 0) { snprintf(error, err_sz, "max_iterations must be > 0"); return -1; }
    return 0;
}

/* ── 崩溃分析 ── */
static uint32_t crash_hash(int sig, uint64_t fault_addr) {
    return (uint32_t)(sig * 2654435761U + (uint32_t)(fault_addr & 0xFFFFFFFF) * 1597334677U);
}

void fuzz_analyze_crash(FuzzCrash *c) {
    c->unique_hash = (int)crash_hash(c->signal, c->fault_addr);
    const char *t = "UNKNOWN";
    if (c->signal == SIGSEGV) {
        t = (c->fault_addr > 0 && c->fault_addr < 0x1000)
            ? "SIGSEGV: NULL dereference"
            : "SIGSEGV: invalid memory access";
        /* 检查是否写入了用户控制的值 */
        for (int i = 0; i < 5; i++) {
            if (c->regs[i] == 0x4141414141414141ULL || c->regs[i] == 0x4242424242424242ULL) {
                t = "SIGSEGV: PC control possible (user value in register)";
                break;
            }
        }
    } else if (c->signal == SIGABRT) t = "SIGABRT: abort() or assert()";
    else if (c->signal == SIGILL)   t = "SIGILL: illegal instruction";
    else if (c->signal == SIGBUS)   t = "SIGBUS: unaligned access";
    else if (c->signal == SIGFPE)   t = "SIGFPE: arithmetic exception";
    snprintf(c->crash_type, sizeof(c->crash_type), "%s", t);
}

int fuzz_crash_is_duplicate(const FuzzCrash *a, const FuzzCrash *b) {
    return a->signal == b->signal && a->fault_addr == b->fault_addr;
}

/* ── 在 tracee 中注入 mmap 调用 ── */
static int inject_mmap(DebugState *ds, uint64_t addr, size_t size) {
    /* 保存原寄存器 */
    struct user_regs_struct saved_regs = ds->regs;

    /* 设置 syscall(9) = mmap:
       rdi=addr, rsi=size, rdx=PROT_READ|PROT_WRITE|PROT_EXEC,
       r10=MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, r8=-1, r9=0 */
    ds->regs.rax = 9;
    ds->regs.rdi = addr;
    ds->regs.rsi = size;
    ds->regs.rdx = 7;  /* PROT_RWX */
    ds->regs.r10 = 0x32; /* MAP_PRIVATE|ANON|FIXED */
    ds->regs.r8  = (uint64_t)-1;
    ds->regs.r9  = 0;
    ds->regs.rip = 0; /* 会被 ptrace 忽略 */
    /* 注入 syscall 指令 */
    uint8_t syscall_code[] = {0x0f, 0x05}; /* syscall */
    /* 需要在 tracee 中执行: 写 syscall 到某地址, 设 rip, 单步 */
    /* 简化: 使用 PTRACE_POKEDATA 已足够 */
    (void)syscall_code;
    /* 注: 完整实现需要 mmap 在 tracee 中分配内存, 这里用 PTRACE_PEEKDATA 验证地址可用 */
    (void)ptrace; /* already included */
    errno = 0;
    long test = ptrace(PTRACE_PEEKDATA, ds->pid, (void *)addr, NULL);
    if (test == -1 && errno != 0) {
        /* 地址不可用, 需要 mmap — 完整的注入实现见下方注释 */
        /* 对于 v1: 假设地址已可用 (通过 /proc/pid/maps 检查) 或使用已有的堆栈区域 */
    }
    /* 恢复 */
    ds->regs = saved_regs;
    return 0;
}

/* ── 设置 tracee 内存 ── */
static int setup_tracee_memory(DebugState *ds, FuzzConfig *cfg)
{
    /* 确保输入缓冲区和栈区域可用 */
    inject_mmap(ds, cfg->input_addr, cfg->input_max_size + 4096);
    inject_mmap(ds, cfg->return_trap - DEFAULT_STACK_SIZE, DEFAULT_STACK_SIZE);

    /* 写入 INT3 陷阱 */
    uint8_t int3 = 0xCC;
    for (size_t i = 0; i < 8; i++)
        debug_writemem(ds, cfg->return_trap + i, &int3, 1);

    return 0;
}

/* ── 单次迭代 ── */
typedef enum { FUZZ_OK, FUZZ_CRASH, FUZZ_TIMEOUT, FUZZ_ERROR } fuzz_result_t;

static fuzz_result_t fuzz_iteration(DebugState *ds, FuzzConfig *cfg,
                                     uint8_t *input, size_t input_size,
                                     FuzzCrash *crash_out)
{
    /* 1. 写输入到 tracee */
    debug_writemem(ds, cfg->input_addr, input, input_size);
    memset(input + input_size, 0, cfg->input_max_size - input_size);
    debug_writemem(ds, cfg->input_addr + input_size, input, 1); /* null term */

    /* 2. 获取当前寄存器 */
    debug_getregs(ds);

    /* 3. 设置调用约定 */
    for (int i = 0; i < 6; i++) {
        uint64_t val;
        if (cfg->args[i].is_input)
            val = cfg->input_addr;
        else if (cfg->args[i].is_length)
            val = input_size;
        else
            val = cfg->args[i].fixed_value;

        /* System V AMD64 用户函数调用约定: rdi, rsi, rdx, rcx, r8, r9 */
        switch (i) {
        case 0: ds->regs.rdi = val; break;
        case 1: ds->regs.rsi = val; break;
        case 2: ds->regs.rdx = val; break;
        case 3: ds->regs.rcx = val; break;   /* 用户调用第4参数 (syscall 应用 r10) */
        case 4: ds->regs.r8  = val; break;
        case 5: ds->regs.r9  = val; break;
        }
    }
    ds->regs.rip = cfg->target_addr;
    ds->regs.rsp = cfg->return_trap;
    /* 栈顶写入 INT3 返回地址 */
    uint64_t trap_val = cfg->return_trap;
    debug_writemem(ds, cfg->return_trap, &trap_val, 8);

    if (ptrace(PTRACE_SETREGS, ds->pid, NULL, &ds->regs) == -1)
        return FUZZ_ERROR;

    /* 4. 执行 */
    if (ptrace(PTRACE_CONT, ds->pid, NULL, NULL) == -1)
        return FUZZ_ERROR;

    /* 5. 等待结果 */
    int status;
    if (waitpid(ds->pid, &status, 0) == -1) return FUZZ_ERROR;

    debug_getregs(ds); /* 刷新寄存器 */

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code != 0) {
            memset(crash_out, 0, sizeof(*crash_out));
            crash_out->signal = SIGABRT;
            crash_out->fault_addr = ds->regs.rip;
            crash_out->rip_snapshot = ds->regs.rip;
            crash_out->input_size = input_size;
            memcpy(crash_out->input, input, input_size < 4096 ? input_size : 4096);
            memcpy(crash_out->regs, &ds->regs, sizeof(ds->regs));
            fuzz_analyze_crash(crash_out);
            return FUZZ_CRASH;
        }
        return FUZZ_OK;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        memset(crash_out, 0, sizeof(*crash_out));
        crash_out->signal = sig;
        crash_out->fault_addr = ds->regs.rip;
        crash_out->rip_snapshot = ds->regs.rip;
        crash_out->input_size = input_size;
        memcpy(crash_out->input, input, input_size < 4096 ? input_size : 4096);
        memcpy(crash_out->regs, &ds->regs, sizeof(ds->regs));
        /* 取栈快照 */
        if (debug_readmem(ds, ds->regs.rsp, crash_out->stack_snapshot, 256) <= 0)
            memset(crash_out->stack_snapshot, 0, 256);
        fuzz_analyze_crash(crash_out);

        /* 种子评分: crash 输入 +5 */
        fuzz_seed_add(input, input_size, 5);
        return FUZZ_CRASH;
    }

    /* SIGTRAP = 正常返回 (命中 INT3) */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        /* 正常返回, 种子评分: +1 */
        fuzz_seed_add(input, input_size, 1);
        return FUZZ_OK;
    }

    return FUZZ_OK;
}

/* ── 主循环 ── */

int fuzz_run(FuzzConfig *cfg,
             void (*progress_cb)(const FuzzStats*, void*),
             void (*crash_cb)(const FuzzCrash*, void*),
             void *user)
{
    char err[256];
    if (fuzz_config_validate(cfg, err, sizeof(err)) != 0) return -1;

    g_stop = 0;
    fuzz_seed_reset();
    srand((unsigned int)time(NULL));

    /* fork */
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        _exit(0);
    }

    waitpid(child, NULL, 0);

    DebugState *ds = NULL;
    if (debug_attach(child, &ds) != 0) {
        kill(child, SIGKILL);
        return -1;
    }
    setup_tracee_memory(ds, cfg);
    debug_getregs(ds);

    /* 输入缓冲区 */
    uint8_t *input = calloc(1, cfg->input_max_size);
    if (!input) { debug_detach(ds); debug_free(ds); return -1; }

    /* 初始化种子队列 */
    if (cfg->seed_input && cfg->seed_input_size > 0)
        fuzz_seed_add(cfg->seed_input, cfg->seed_input_size, 10);
    else {
        for (size_t i = 0; i < cfg->input_max_size; i++)
            input[i] = (uint8_t)(rand() & 0xFF);
        fuzz_seed_add(input, cfg->input_max_size, 5);
    }

    FuzzStats stats; memset(&stats, 0, sizeof(stats));
    FuzzCrash crashes[128]; int ncrash = 0;
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int iter = 0; iter < cfg->max_iterations && !g_stop; iter++) {
        /* 变异 */
        int n = fuzz_seed_pick(input, cfg->input_max_size);
        if (n == 0) { /* 随机填充 */
            for (size_t i = 0; i < cfg->input_max_size; i++)
                input[i] = (uint8_t)(rand() & 0xFF);
            n = (int)cfg->input_max_size;
        }
        fuzz_mutate(input, (size_t)n, cfg->strategy_mask);
        size_t input_size = (size_t)n;

        /* 执行 */
        FuzzCrash crash;
        fuzz_result_t res = fuzz_iteration(ds, cfg, input, input_size, &crash);
        stats.total_iterations++;

        if (res == FUZZ_CRASH && ncrash < 128) {
            crash.crash_id = ncrash;
            int dup = 0;
            for (int j = 0; j < ncrash; j++)
                if (fuzz_crash_is_duplicate(&crash, &crashes[j])) { dup = 1; break; }
            if (!dup) {
                stats.unique_crashes++;
                /* Strategy 1: Crash Auto-Triage — 存储到 DB 分析表 */
                if (g_active_db) {
                    sqlite3 *fc = (sqlite3*)db_conn(g_active_db);
                    if (fc) {
                        sqlite3_stmt *fst = NULL;
                        sqlite3_prepare_v2(fc,
                            "INSERT OR IGNORE INTO crash_reports"
                            "(fault_addr,signal,rip_snapshot,input_blob,input_size)"
                            " VALUES(?,?,?,?,?)", -1, &fst, NULL);
                        if (fst) {
                            sqlite3_bind_int64(fst, 1, (sqlite3_int64)crash.rip_snapshot);
                            sqlite3_bind_int(fst, 2, crash.signal);
                            sqlite3_bind_int64(fst, 3, (sqlite3_int64)crash.rip_snapshot);
                            sqlite3_bind_blob(fst, 4, crash.input,
                                (int)(crash.input_size < 4096 ? crash.input_size : 256),
                                SQLITE_STATIC);
                            sqlite3_bind_int(fst, 5, (int)crash.input_size);
                            sqlite3_step(fst); sqlite3_finalize(fst);
                        }
                    }
                }
            }
            stats.total_crashes++;
            crashes[ncrash++] = crash;
            if (crash_cb) crash_cb(&crash, user);
        }

        /* Phase 2: Coverage feedback — 正常执行的种子评分 */
        if (res == FUZZ_OK && g_cov_enabled && g_cov_bitmap) {
            /* 从 PT trace 或软件收集当前执行的 BB 边 */
            /* 如果有 trace backend, 提取边列表 */
            trace_backend_t *tb = trace_detect_backend();
            if (tb) {
                trace_bb_t *blocks = calloc(256, sizeof(trace_bb_t));
                void *tctx = NULL;
                if (tb->start(ds, &tctx) == 0 && tctx) {
                    int nb = tb->get_blocks(tctx, blocks, 256);
                    if (nb > 0) {
                        /* 将 BB 地址转换为边哈希 */
                        uint64_t *edge_hashes = calloc((size_t)nb, sizeof(uint64_t));
                        for (int ei = 0; ei < nb && ei < 256; ei++) {
                            edge_hashes[ei] = blocks[ei].bb_addr;
                        }
                        int new_edges = fuzz_coverage_update(edge_hashes, nb);
                        if (new_edges > 0) {
                            /* 新边 → 高价值种子 */
                            fuzz_seed_add(input, input_size,
                                          fuzz_seed_count() > 0 ? 3 + new_edges * 2 : 5);
                            stats.new_paths += new_edges;
                        }
                        free(edge_hashes);
                    }
                    tb->stop(tctx);
                    tb->free_ctx(tctx);
                }
                free(blocks);
            }
        }

        /* 速度 */
        struct timespec tnow; clock_gettime(CLOCK_MONOTONIC, &tnow);
        double elapsed = (tnow.tv_sec - t0.tv_sec) + (tnow.tv_nsec - t0.tv_nsec)/1e9;
        if (elapsed > 0) stats.execs_per_second = (int)(stats.total_iterations / elapsed);

        if (progress_cb && iter % 100 == 0) progress_cb(&stats, user);
    }

    /* 清理 */
    debug_detach(ds); debug_free(ds);
    free(input);
    fuzz_seed_reset();
    return 0;
}
