/*
 * heap_trace.c — 堆事件追踪引擎 (ptrace syscall 拦截)
 *
 * 原理: 在 malloc/free/realloc 的 PLT 入口设置软件断点,
 *       触发时记录参数/返回值, 然后继续执行。
 *
 * 也可使用 LD_PRELOAD hook 方案 (通过设置环境变量),
 * 或 /proc/pid/mem 直接读取 libc 内部数据结构。
 *
 * 事件记录到 heap_events 表，支持时间轴回放和布局模拟。
 */

#include "core/heap_analyzer.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ================================================================== */
/* 常量定义                                                            */
/* ================================================================== */

#define MAX_HEAP_EVENTS  10000
#define HEAP_HOOK_COUNT  4

/* 需要 hook 的函数及其参数/返回值语义 */
typedef struct {
    const char *name;
    int         arg0_reg;     /* 参数寄存器索引 (0=rdi,1=rsi,2=rdx) */
    int         arg1_reg;
    int         is_alloc;     /* 1=分配函数, 0=释放函数 */
} heap_hook_t;

static const heap_hook_t HOOK_TABLE[] = {
    {"malloc",  0, -1, 1},   /* malloc(size) → rax = ptr */
    {"calloc",  0,  1, 1},   /* calloc(nmemb, size) → rax = ptr */
    {"realloc", 0,  1, 1},   /* realloc(ptr, size) → rax = new_ptr */
    {"free",    0, -1, 0},   /* free(ptr) → void */
};
#define N_HOOKS (int)(sizeof(HOOK_TABLE) / sizeof(HOOK_TABLE[0]))

/* ================================================================== */
/* 堆事件记录                                                          */
/* ================================================================== */

typedef struct {
    uint64_t  timestamp;     /* 相对时间戳 (从开始追踪算起, ns) */
    int       event_type;    /* 0=malloc, 1=calloc, 2=realloc, 3=free */
    uint64_t  chunk_addr;    /* 返回的用户数据地址 (free 时为释放的地址) */
    uint64_t  size;          /* 请求大小 (free 时为 0) */
    uint64_t  return_addr;   /* 调用者的 RIP */
    uint64_t  arg1;          /* 额外参数 (calloc 的 nmemb, realloc 的 old_ptr) */
} heap_event_t;

typedef struct {
    int          pid;
    int          session_id;
    heap_event_t events[MAX_HEAP_EVENTS];
    int          event_count;
    uint64_t     start_time;
    int          running;

    /* 在 tracee 中 hook 的地址 (PLT entries) */
    uint64_t     hook_addrs[N_HOOKS];
    int          hook_active[N_HOOKS];
    uint8_t      hook_saved[N_HOOKS][1]; /* 原始指令字节 (INT3 覆盖了 1 字节) */

    uint64_t     last_fault_addr;  /* 最后一次异常地址 (用于判断是 hook 还是 crash) */

    /* 返回地址临时断点 */
    uint64_t     ret_bp_addr;      /* 临时断点地址 (分配函数返回点) */
    uint8_t      ret_bp_saved[1];  /* 返回地址处保存的原始字节 */
    int          ret_bp_active;    /* 1=有活跃的返回断点需要恢复 */
} heap_trace_ctx_t;

/* ================================================================== */
/* 生命周期                                                            */
/* ================================================================== */

/* 从 PLT 或符号表解析 hook 目标地址 */
static int resolve_hook_addrs(AnalysisDB *adb, Elf64_Ctx *ctx,
                               heap_trace_ctx_t *htx)
{
    (void)ctx;  /* 保留以支持未来通过 ELF 上下文直接解析 hook 地址 */
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    for (int h = 0; h < N_HOOKS; h++) {
        htx->hook_addrs[h]  = 0;
        htx->hook_active[h] = 0;

        /* 从 symbols 表查找 */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT address FROM symbols WHERE name LIKE ?1 AND table_name='dynsym' LIMIT 1",
            -1, &st, NULL);
        if (st) {
            char pattern[64];
            snprintf(pattern, sizeof(pattern), "%%%s%%", HOOK_TABLE[h].name);
            sqlite3_bind_text(st, 1, pattern, -1, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW) {
                htx->hook_addrs[h] = (uint64_t)sqlite3_column_int64(st, 0);
            }
            sqlite3_finalize(st);
        }

        /* 也尝试 PLT 格式: name@plt */
        if (htx->hook_addrs[h] == 0) {
            sqlite3_prepare_v2(c,
                "SELECT i.address FROM instructions i "
                "JOIN xrefs x ON i.address=x.to_addr "
                "JOIN symbols s ON x.from_addr=s.address "
                "WHERE s.name LIKE ?1 AND i.mnemonic='jmp' LIMIT 1",
                -1, &st, NULL);
            if (st) {
                char pattern[64];
                snprintf(pattern, sizeof(pattern), "%%%s%%", HOOK_TABLE[h].name);
                sqlite3_bind_text(st, 1, pattern, -1, SQLITE_STATIC);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    htx->hook_addrs[h] = (uint64_t)sqlite3_column_int64(st, 0);
                }
                sqlite3_finalize(st);
            }
        }
    }
    return 0;
}

int heap_trace_start(struct DebugState *ds, AnalysisDB *adb,
                     Elf64_Ctx *ctx, void **out)
{
    if (!ds || !out) return -1;

    heap_trace_ctx_t *htx = calloc(1, sizeof(heap_trace_ctx_t));
    if (!htx) return -1;

    htx->pid    = ds->pid;
    htx->running = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    htx->start_time = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    /* 解析 hook 地址 */
    if (adb && ctx)
        resolve_hook_addrs(adb, ctx, htx);

    /* 设置 INT3 断点 */
    for (int h = 0; h < N_HOOKS; h++) {
        if (htx->hook_addrs[h] == 0) continue;
        /* 保存原始字节, 写入 0xCC */
        if (debug_readmem(ds, htx->hook_addrs[h], htx->hook_saved[h], 1) == 1) {
            uint8_t int3 = 0xCC;
            if (debug_writemem(ds, htx->hook_addrs[h], &int3, 1) == 1) {
                htx->hook_active[h] = 1;
            }
        }
    }

    *out = htx;
    return 0;
}

int heap_trace_record(heap_trace_ctx_t *htx, int event_type,
                      uint64_t chunk_addr, uint64_t size,
                      uint64_t return_addr, uint64_t extra_arg)
{
    if (!htx || !htx->running) return -1;
    if (htx->event_count >= MAX_HEAP_EVENTS) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    heap_event_t *ev = &htx->events[htx->event_count++];
    ev->timestamp   = now - htx->start_time;
    ev->event_type  = event_type;
    ev->chunk_addr  = chunk_addr;
    ev->size        = size;
    ev->return_addr = return_addr;
    ev->arg1        = extra_arg;

    return htx->event_count;
}

int heap_trace_stop(heap_trace_ctx_t *htx, struct DebugState *ds)
{
    if (!htx) return -1;
    htx->running = 0;

    /* 恢复原始指令 */
    if (ds) {
        for (int h = 0; h < N_HOOKS; h++) {
            if (htx->hook_active[h]) {
                debug_writemem(ds, htx->hook_addrs[h], htx->hook_saved[h], 1);
            }
        }
    }

    return htx->event_count;
}

/* 将事件刷新到 DB */
int heap_trace_flush_db(heap_trace_ctx_t *htx, AnalysisDB *adb, int session_id)
{
    if (!htx || !adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_exec(c, "BEGIN", NULL, NULL, NULL);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO heap_events(session_id, timestamp, event_type,"
        " chunk_addr, size, return_addr, extra_arg)"
        " VALUES(?,?,?,?,?,?,?)",
        -1, &st, NULL);

    if (!st) { sqlite3_exec(c, "COMMIT", NULL, NULL, NULL); return -1; }

    const char *etype_names[] = {"malloc", "calloc", "realloc", "free"};

    for (int i = 0; i < htx->event_count; i++) {
        sqlite3_reset(st);
        sqlite3_bind_int(st,     1, session_id);
        sqlite3_bind_int64(st,   2, (sqlite3_int64)htx->events[i].timestamp);
        sqlite3_bind_text(st,    3,
            etype_names[htx->events[i].event_type % 4], -1, SQLITE_STATIC);
        sqlite3_bind_int64(st,   4, (sqlite3_int64)htx->events[i].chunk_addr);
        sqlite3_bind_int64(st,   5, (sqlite3_int64)htx->events[i].size);
        sqlite3_bind_int64(st,   6, (sqlite3_int64)htx->events[i].return_addr);
        sqlite3_bind_int64(st,   7, (sqlite3_int64)htx->events[i].arg1);
        sqlite3_step(st);
    }

    sqlite3_finalize(st);
    sqlite3_exec(c, "COMMIT", NULL, NULL, NULL);

    return htx->event_count;
}

void heap_trace_free(heap_trace_ctx_t *htx)
{
    free(htx);
}

/* 检测当前 RIP 是否命中了 hook 地址 */
int heap_trace_is_hook_hit(heap_trace_ctx_t *htx, uint64_t rip, int *hook_idx_out)
{
    if (!htx) return 0;
    for (int h = 0; h < N_HOOKS; h++) {
        if (htx->hook_active[h] && htx->hook_addrs[h] == rip) {
            if (hook_idx_out) *hook_idx_out = h;
            return 1;
        }
    }
    return 0;
}

/* 在 hook 命中时处理: 记录事件, 设置临时断点在返回地址 */
int heap_trace_handle_hook(heap_trace_ctx_t *htx, struct DebugState *ds,
                           int hook_idx, AnalysisDB *adb, int session_id)
{
    (void)adb; (void)session_id;
    if (!htx || !ds || hook_idx < 0 || hook_idx >= N_HOOKS) return -1;

    uint64_t rip = ds->regs.rip;
    uint64_t ret_addr = 0;
    /* 读取返回地址 (栈顶) */
    debug_readmem(ds, ds->regs.rsp, &ret_addr, 8);

    /* 根据 hook 类型提取参数 */
    const heap_hook_t *hk = &HOOK_TABLE[hook_idx];
    uint64_t arg_regs[] = { ds->regs.rdi, ds->regs.rsi, ds->regs.rdx };

    /* Free 的 size 为 0; 记录的是要释放的地址 */
    uint64_t chunk_addr = hk->is_alloc ? 0 : arg_regs[0];

    /* 记录事件 (分配的实际地址在函数返回后才知道 — 这里记录请求) */
    if (!hk->is_alloc) {
        heap_trace_record(htx, 3, chunk_addr, 0, rip, 0);
    }

    /* 在返回地址设置临时断点 (以捕获分配函数的返回值) */
    if (hk->is_alloc && ret_addr > 0 && ret_addr < 0x7fffffffffffULL) {
        /* 保存返回地址处的原始字节, 写入 INT3 */
        if (debug_readmem(ds, ret_addr, htx->ret_bp_saved, 1) == 1) {
            uint8_t int3 = 0xCC;
            if (debug_writemem(ds, ret_addr, &int3, 1) == 1) {
                htx->ret_bp_addr  = ret_addr;
                htx->ret_bp_active = 1;
            }
        }
        htx->last_fault_addr = ret_addr; /* 标记为临时断点 */
    }

    return 0;
}

/* 处理分配函数返回 (在返回地址的临时断点命中时调用) */
int heap_trace_handle_return(heap_trace_ctx_t *htx, struct DebugState *ds)
{
    if (!htx || !ds) return -1;

    /* 恢复返回地址处的原始字节 (移除临时 INT3 断点) */
    if (htx->ret_bp_active) {
        debug_writemem(ds, htx->ret_bp_addr, htx->ret_bp_saved, 1);
        htx->ret_bp_active = 0;
    }

    uint64_t alloc_size = 0;
    int ev_type = -1;

    /* 判断是哪种分配: 检查 hook_addrs */
    for (int h = 0; h < N_HOOKS; h++) {
        if (htx->hook_active[h] && HOOK_TABLE[h].is_alloc) {
            ev_type = h;
            if (h == 0)      alloc_size = ds->regs.rdi;      /* malloc(size) */
            else if (h == 1) alloc_size = ds->regs.rdi * ds->regs.rsi; /* calloc */
            else if (h == 2) alloc_size = ds->regs.rsi;      /* realloc(ptr,size) */
            break;
        }
    }

    if (ev_type >= 0) {
        heap_trace_record(htx, ev_type, ds->regs.rax,
                          alloc_size, ds->regs.rip, 0);
    }

    return 0;
}
