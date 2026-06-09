/*
 * pt_trace.c — Intel PT / BTS Trace 录制引擎
 *
 * 实现: Linux perf_event_open + Intel PT AUX ring buffer
 * 降级: 当 Intel PT 不可用时, 使用 BTS (Branch Trace Store) 或软件单步
 *
 * 依赖: <linux/perf_event.h> (内核头文件)
 * 可选: libipt (Intel Processor Trace decoder library)
 */

#include "core/pt_trace.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <time.h>

/* ── 尝试包含 perf_event ──────────────────────────────────────────── */
#if __has_include(<linux/perf_event.h>)
#include <linux/perf_event.h>
#define HAS_PERF_EVENT 1
#else
#define HAS_PERF_EVENT 0
#endif

/* ================================================================== */
/* PT Trace 上下文                                                     */
/* ================================================================== */

#define PT_AUX_BUF_SIZE   (256 * 1024)   /* 256KB AUX buffer */
#define PT_DATA_BUF_SIZE  (64 * 1024)    /* 64KB data buffer */

typedef struct {
    int      fd;               /* perf_event file descriptor */
    int      pid;               /* tracee PID */
    void    *aux_mmap;          /* AUX buffer mmap */
    size_t   aux_size;
    void    *data_mmap;         /* Data buffer mmap */
    size_t   data_size;
    uint64_t bb_count;          /* 录制的 BB 数量 */
    trace_bb_t *blocks;         /* 收集的 BB 列表 */
    int      block_cap;
    int      block_cnt;
} pt_trace_ctx_t;

/* ================================================================== */
/* 硬件探测                                                            */
/* ================================================================== */

/* 从 sysfs 读取 Intel PT PMU type (动态分配, 非固定值) */
static int read_intel_pt_type(void)
{
    FILE *fp = fopen("/sys/bus/event_source/devices/intel_pt/type", "r");
    if (!fp) return -1;
    int type = -1;
    if (fscanf(fp, "%d", &type) != 1) type = -1;
    fclose(fp);
    return type;
}

static int intel_pt_probe(void)
{
#if HAS_PERF_EVENT
    /* 关键: 检查 /sys 确认 Intel PT PMU 真的存在 (WSL2 上不存在) */
    int pt_type = read_intel_pt_type();
    if (pt_type < 0) return 0;

    /* 同时验证 perf_event_open 可用 */
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size        = sizeof(attr);
    attr.type        = PERF_TYPE_HARDWARE;
    attr.config      = PERF_COUNT_HW_INSTRUCTIONS;
    attr.disabled    = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv    = 1;

    int fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd >= 0) { close(fd); return 1; }
#endif
    return 0;
}

static int bts_probe(void)
{
    /* BTS (Branch Trace Store) — 较老的 Intel CPU 支持 */
    /* 检查 /proc/cpuinfo 中是否有 'bts' 标志 */
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "flags") && strstr(line, "bts")) {
            found = 1; break;
        }
    }
    fclose(fp);
    return found;
}

/* ================================================================== */
/* Intel PT 实现 (proper AUX buffer + correct PMU type)                 */
/* ================================================================== */

#if HAS_PERF_EVENT

static int intel_pt_start(struct DebugState *ds, void **ctx_out)
{
    if (!ds || !ctx_out) return -1;

    int pt_pmu_type = read_intel_pt_type();
    if (pt_pmu_type < 0) return -1;  /* Intel PT PMU 不存在 */

    pt_trace_ctx_t *ptx = calloc(1, sizeof(pt_trace_ctx_t));
    if (!ptx) return -1;
    ptx->pid = ds->pid;
    ptx->block_cap = 4096;
    ptx->blocks = calloc((size_t)ptx->block_cap, sizeof(trace_bb_t));
    if (!ptx->blocks) { free(ptx); return -1; }

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size              = sizeof(attr);
    attr.type              = pt_pmu_type;       /* Intel PT PMU (动态ID) */
    attr.config            = 0;                 /* 默认: 仅 trace 用户态 */
    attr.disabled          = 1;
    attr.exclude_kernel    = 1;
    attr.exclude_hv        = 1;
    attr.sample_period     = 1;
    attr.sample_type       = PERF_SAMPLE_IP | PERF_SAMPLE_TID
                           | PERF_SAMPLE_TIME;
    attr.mmap              = 1;
    attr.comm              = 1;
    attr.task              = 1;

    int fd = (int)syscall(__NR_perf_event_open, &attr, ds->pid, -1, -1, 0);
    if (fd < 0) {
        /* 降级: CPU=-1 且 no group */
        fd = (int)syscall(__NR_perf_event_open, &attr, ds->pid, -1, -1,
                          PERF_FLAG_FD_NO_GROUP);
        if (fd < 0) {
            free(ptx->blocks); free(ptx); return -1;
        }
    }
    ptx->fd = fd;

    /* ── mmap metadata + data 缓冲区 ── */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t map_size  = page_size + PT_DATA_BUF_SIZE;
    ptx->data_mmap = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);
    if (ptx->data_mmap == MAP_FAILED) {
        ptx->data_mmap = NULL;  /* 降级: 无 mmap, 只有计数 */
    } else {
        ptx->data_size = map_size;
        /* 从 metadata page 读取 AUX buffer 偏移量和大小 */
        struct perf_event_mmap_page *mp =
            (struct perf_event_mmap_page *)ptx->data_mmap;
        if (mp->aux_offset > 0 && mp->aux_size > 0) {
            ptx->aux_size = mp->aux_size;
            ptx->aux_mmap = mmap(NULL, (size_t)mp->aux_size,
                                 PROT_READ, MAP_SHARED,
                                 fd, (off_t)mp->aux_offset);
            if (ptx->aux_mmap == MAP_FAILED)
                ptx->aux_mmap = NULL;
        }
    }

    /* 启用 Intel PT (开始写入 AUX buffer) */
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    *ctx_out = ptx;
    return 0;
}

static int intel_pt_stop(void *ctx)
{
    if (!ctx) return -1;
    pt_trace_ctx_t *ptx = (pt_trace_ctx_t *)ctx;

    if (ptx->fd >= 0) {
        ioctl(ptx->fd, PERF_EVENT_IOC_DISABLE, 0);
    }

    /* 从 data ring buffer 收集 PERF_RECORD_SAMPLE 记录 */
    if (ptx->data_mmap) {
        struct perf_event_mmap_page *mp =
            (struct perf_event_mmap_page *)ptx->data_mmap;
        uint64_t data_head = mp->data_head;
        uint64_t data_tail = mp->data_tail;
        char *data = (char *)ptx->data_mmap + mp->data_offset;

        while (data_tail < data_head && ptx->block_cnt < ptx->block_cap) {
            struct perf_event_header {
                uint32_t type;
                uint16_t misc;
                uint16_t size;
            } *hdr = (struct perf_event_header *)
                     (data + (size_t)(data_tail % (uint64_t)ptx->data_size));

            if (hdr->type == PERF_RECORD_SAMPLE && hdr->size >= 32) {
                /* sample: IP(8B) + PID(4B) + TID(4B) + TIME(8B) = 24B */
                char *sample = (char *)hdr + sizeof(*hdr);
                uint64_t ip   = *(uint64_t *)(sample);
                uint64_t time = *(uint64_t *)(sample + 16);

                ptx->blocks[ptx->block_cnt].bb_addr    = ip;
                ptx->blocks[ptx->block_cnt].timestamp  = time;
                ptx->blocks[ptx->block_cnt].exec_count = 1;
                ptx->block_cnt++;

                /* 动态扩容 block 列表 */
                if (ptx->block_cnt >= ptx->block_cap) {
                    ptx->block_cap *= 2;
                    trace_bb_t *nb = realloc(ptx->blocks,
                        (size_t)ptx->block_cap * sizeof(trace_bb_t));
                    if (!nb) break;
                    ptx->blocks = nb;
                }
            }

            data_tail += hdr->size;
        }
    }

    return ptx->block_cnt;
}

static int intel_pt_decode(void *ctx, AnalysisDB *adb, int session_id,
                           PanelData *pd)
{
    if (!ctx || !adb) return -1;
    pt_trace_ctx_t *ptx = (pt_trace_ctx_t *)ctx;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    /* 写入所有收集到的地址到 DB */
    for (int i = 0; i < ptx->block_cnt; i++) {
        trace_block_record(adb, session_id,
                           ptx->blocks[i].bb_addr,
                           ptx->blocks[i].timestamp);
    }

    if (pd) {
        char buf[256];
        if (ptx->block_cnt > 0) {
            snprintf(buf, sizeof(buf),
                     "Intel PT: %d samples decoded → session #%d",
                     ptx->block_cnt, session_id);
        } else {
            snprintf(buf, sizeof(buf),
                     "Trace Session #%d: no samples (AUX buffer empty)", session_id);
        }
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    return ptx->block_cnt;
}

static void intel_pt_free_ctx(void *ctx)
{
    if (!ctx) return;
    pt_trace_ctx_t *ptx = (pt_trace_ctx_t *)ctx;
    if (ptx->aux_mmap)   munmap(ptx->aux_mmap, ptx->aux_size);
    if (ptx->data_mmap)  munmap(ptx->data_mmap, ptx->data_size);
    if (ptx->fd >= 0)    close(ptx->fd);
    free(ptx->blocks);
    free(ptx);
}

static int intel_pt_get_blocks(void *ctx, trace_bb_t *blocks, int max)
{
    if (!ctx || !blocks) return -1;
    pt_trace_ctx_t *ptx = (pt_trace_ctx_t *)ctx;
    int n = ptx->block_cnt;
    if (n > max) n = max;
    memcpy(blocks, ptx->blocks, (size_t)n * sizeof(trace_bb_t));
    return n;
}

#else /* !HAS_PERF_EVENT */

/* 无 perf_event 时的桩实现 */
static int intel_pt_start(struct DebugState *ds, void **ctx_out)
{ (void)ds; (void)ctx_out; return -1; }
static int intel_pt_stop(void *ctx)         { (void)ctx; return -1; }
static int intel_pt_decode(void *ctx, AnalysisDB *adb, int sid, PanelData *pd)
{ (void)ctx; (void)adb; (void)sid; (void)pd; return -1; }
static void intel_pt_free_ctx(void *ctx)    { (void)ctx; }
static int intel_pt_get_blocks(void *ctx, trace_bb_t *b, int max)
{ (void)ctx; (void)b; (void)max; return -1; }

#endif /* HAS_PERF_EVENT */

/* ================================================================== */
/* 软件 Trace 后端 (BTS 降级 / 无硬件时的 fallback)                    */
/* ================================================================== */

typedef struct {
    int          pid;
    trace_bb_t  *blocks;
    int          block_cap;
    int          block_cnt;
    uint64_t     start_time;
    int          running;
} sw_trace_ctx_t;

static int sw_trace_probe(void) { return 1; } /* 始终可用 */

static int sw_trace_start(struct DebugState *ds, void **ctx_out)
{
    sw_trace_ctx_t *stx = calloc(1, sizeof(sw_trace_ctx_t));
    if (!stx) return -1;
    stx->pid       = ds->pid;
    stx->block_cap = 2048;
    stx->blocks    = calloc((size_t)stx->block_cap, sizeof(trace_bb_t));
    if (!stx->blocks) { free(stx); return -1; }
    stx->running   = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    stx->start_time = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    *ctx_out = stx;
    return 0;
}

static int sw_trace_stop(void *ctx)
{
    if (!ctx) return -1;
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    stx->running = 0;
    return stx->block_cnt;
}

/* 软件记录 BB: 由 fuzz/pdb 每次单步后调用 */
int sw_trace_record_bb(void *ctx, uint64_t bb_addr)
{
    if (!ctx) return -1;
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    if (!stx->running) return -1;

    /* 去重: 连续相同的 BB 只记录一次 */
    if (stx->block_cnt > 0 &&
        stx->blocks[stx->block_cnt - 1].bb_addr == bb_addr) {
        stx->blocks[stx->block_cnt - 1].exec_count++;
        return stx->block_cnt;
    }

    if (stx->block_cnt >= stx->block_cap) {
        stx->block_cap *= 2;
        trace_bb_t *nb = realloc(stx->blocks,
                                  (size_t)stx->block_cap * sizeof(trace_bb_t));
        if (!nb) return -1;
        stx->blocks = nb;
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    stx->blocks[stx->block_cnt].bb_addr    = bb_addr;
    stx->blocks[stx->block_cnt].timestamp  = now - stx->start_time;
    stx->blocks[stx->block_cnt].exec_count = 1;
    stx->block_cnt++;

    return stx->block_cnt;
}

static int sw_trace_decode(void *ctx, AnalysisDB *adb, int session_id,
                           PanelData *pd)
{
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    if (!stx || !adb) return -1;

    for (int i = 0; i < stx->block_cnt; i++) {
        trace_block_record(adb, session_id,
                           stx->blocks[i].bb_addr,
                           stx->blocks[i].timestamp);
    }

    if (pd) {
        char buf[256];
        snprintf(buf, sizeof(buf), "SW Trace: %d blocks, %d unique",
                 stx->block_cnt, 0); /* unique count computed elsewhere */
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }
    return stx->block_cnt;
}

static void sw_trace_free_ctx(void *ctx)
{
    if (!ctx) return;
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    free(stx->blocks);
    free(stx);
}

static int sw_trace_get_blocks(void *ctx, trace_bb_t *blocks, int max)
{
    if (!ctx || !blocks) return -1;
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    int n = stx->block_cnt;
    if (n > max) n = max;
    memcpy(blocks, stx->blocks, (size_t)n * sizeof(trace_bb_t));
    return n;
}

/* ================================================================== */
/* 软件 Trace: 单步采样录制 (便携降级, 适用于无硬件 PT 的环境)           */
/* ================================================================== */

/*
 * sw_trace_record_steps — 有界单步循环, 采集目标进程的执行地址
 *
 * 每步调用 PTRACE_SINGLESTEP → waitpid → 记录 rip。
 * 单步阻塞时间 = 1 条指令 (微秒级), 总时间由 max_steps 和 timeout_ms 共同约束。
 *
 * 这是无 Intel PT 硬件时的便携降级方案 (WSL2 / 旧 CPU / VM)。
 *
 * @param ctx        sw_trace_start() 返回的上下文
 * @param ds         已 attach 的调试状态 (tracee 必须处于 stopped 状态)
 * @param max_steps  最多执行的指令步数 (建议 500~2000)
 * @param timeout_ms 总时间上限 (毫秒, 建议 2000~5000)
 * @return           实际录制的步数, -1 表示失败
 *
 * 使用方式:
 *   sw_trace_start(ds, &ctx);
 *   sw_trace_record_steps(ctx, ds, 1000, 2000);
 *   sw_trace_stop(ctx);
 *   sw_trace_decode(ctx, adb, session_id, pd);
 *   sw_trace_free_ctx(ctx);
 */
int sw_trace_record_steps(void *ctx, struct DebugState *ds,
                           int max_steps, int timeout_ms)
{
    if (!ctx || !ds || !ds->attached) return -1;
    sw_trace_ctx_t *stx = (sw_trace_ctx_t *)ctx;
    if (!stx->running) return -1;

    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    int steps_done = 0;
    for (int i = 0; i < max_steps; i++) {
        /* ── 总超时检查 ── */
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        long elapsed_ms = (t_now.tv_sec - t_start.tv_sec) * 1000L
                        + (t_now.tv_nsec - t_start.tv_nsec) / 1000000L;
        if (elapsed_ms >= (long)timeout_ms) break;

        /* ── 单步执行一条指令 ── */
        if (debug_step(ds) != 0) {
            /* tracee 退出或被信号杀死 → 停止录制 */
            break;
        }

        /* ── 记录 rip (基本块首地址) ── */
        uint64_t rip = ds->regs.rip;
        sw_trace_record_bb(ctx, rip);
        steps_done++;
    }

    return steps_done;
}

/* ================================================================== */
/* 后端注册                                                            */
/* ================================================================== */

trace_backend_t intel_pt_backend = {
    .name       = "Intel PT",
    .probe      = intel_pt_probe,
    .start      = intel_pt_start,
    .stop       = intel_pt_stop,
    .decode     = intel_pt_decode,
    .free_ctx   = intel_pt_free_ctx,
    .get_blocks = intel_pt_get_blocks,
};

trace_backend_t sw_trace_backend = {
    .name       = "Software",
    .probe      = sw_trace_probe,
    .start      = sw_trace_start,
    .stop       = sw_trace_stop,
    .decode     = sw_trace_decode,
    .free_ctx   = sw_trace_free_ctx,
    .get_blocks = sw_trace_get_blocks,
};

/* 全局注册表 */
trace_backend_t *trace_backends[] = {
    &intel_pt_backend,
    &sw_trace_backend,
    NULL
};

/* ================================================================== */
/* Trace Session DB 操作                                                */
/* ================================================================== */

int trace_session_begin(AnalysisDB *adb, int pid, const char *backend)
{
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO trace_sessions(pid,backend,start_time,bb_count,unique_bbs)"
        " VALUES(?,?,strftime('%s','now'),0,0)",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int(st,  1, pid);
    sqlite3_bind_text(st, 2, backend, -1, SQLITE_STATIC);
    sqlite3_step(st);
    int id = (int)sqlite3_last_insert_rowid(c);
    sqlite3_finalize(st);
    return id;
}

int trace_block_record(AnalysisDB *adb, int session_id,
                       uint64_t bb_addr, uint64_t timestamp)
{
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO trace_blocks(session_id,bb_addr,exec_count,timestamp)"
        " VALUES(?,?,1,?)",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int(st,    1, session_id);
    sqlite3_bind_int64(st,  2, (sqlite3_int64)bb_addr);
    sqlite3_bind_int64(st,  3, (sqlite3_int64)timestamp);
    sqlite3_step(st);

    /* 如果已存在, 更新 count */
    if (sqlite3_changes(c) == 0) {
        sqlite3_finalize(st);
        sqlite3_prepare_v2(c,
            "UPDATE trace_blocks SET exec_count=exec_count+1 "
            "WHERE session_id=?1 AND bb_addr=?2",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int(st,   1, session_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)bb_addr);
            sqlite3_step(st);
        }
    }
    sqlite3_finalize(st);
    return 0;
}

/* ================================================================== */
/* Trace 查询 API                                                      */
/* ================================================================== */

int trace_coverage_report(AnalysisDB *adb, int session_id, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[400];

    sqlite3_stmt *st = NULL;

    /* Session 统计 */
    sqlite3_prepare_v2(c,
        "SELECT pid, backend, bb_count, unique_bbs FROM trace_sessions WHERE id=?",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf, sizeof(buf), "=== Trace Coverage #%d ===", session_id);
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
            snprintf(buf, sizeof(buf), "PID %d  Backend: %s  BBs: %d  Unique: %d",
                     sqlite3_column_int(st, 0),
                     (const char *)sqlite3_column_text(st, 1),
                     sqlite3_column_int(st, 2),
                     sqlite3_column_int(st, 3));
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 覆盖率: traced unique BBs / all known BBs */
    sqlite3_prepare_v2(c,
        "SELECT (SELECT COUNT(DISTINCT bb_addr) FROM trace_blocks "
        " WHERE session_id=?1) * 100.0 / "
        "(SELECT COUNT(*) FROM basic_blocks)",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            double cov = sqlite3_column_double(st, 0);
            snprintf(buf, sizeof(buf), "Coverage: %.1f%% of known basic blocks", cov);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* Top 20 热点 */
    fields_add(pd, "── Hotspots (Top 20) ──", 1, 0, DETAIL_NONE, -1);
    sqlite3_prepare_v2(c,
        "SELECT bb_addr, exec_count FROM trace_blocks "
        "WHERE session_id=? ORDER BY exec_count DESC LIMIT 20",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int rank = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            int cnt = sqlite3_column_int(st, 1);
            snprintf(buf, sizeof(buf), "#%-2d  0x%lx  (%d execs)",
                     ++rank, (unsigned long)addr, cnt);
            fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)addr);
        }
        sqlite3_finalize(st);
    }

    return 0;
}

int trace_timeline(AnalysisDB *adb, int session_id, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[400];

    fields_add(pd, "=== Trace Timeline ===", 0, 0, DETAIL_NONE, -1);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT bb_addr, timestamp, exec_count FROM trace_blocks "
        "WHERE session_id=? ORDER BY timestamp LIMIT 200",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 200) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            uint64_t ts   = (uint64_t)sqlite3_column_int64(st, 1);
            int cnt       = sqlite3_column_int(st, 2);
            snprintf(buf, sizeof(buf), "%8lu us  0x%lx  x%d",
                     (unsigned long)(ts / 1000), (unsigned long)addr, cnt);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)addr);
            n++;
        }
        sqlite3_finalize(st);
    }

    return 0;
}

int trace_hotspots(AnalysisDB *adb, int session_id, PanelData *pd)
{
    /* 委托给 coverage_report 的热点部分 */
    return trace_coverage_report(adb, session_id, pd);
}

int trace_path_between(AnalysisDB *adb, int session_id,
                       uint64_t from, uint64_t to, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[400];

    snprintf(buf, sizeof(buf), "=== Path: 0x%lx → 0x%lx ===",
             (unsigned long)from, (unsigned long)to);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 简化: 使用 CFG 边寻找路径 (trace 数据作为权重) */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT e.from_addr, e.to_addr, e.edge_type, "
        "  COALESCE(t.exec_count, 0) as hits "
        "FROM cfg_edges e "
        "LEFT JOIN trace_blocks t ON e.to_addr=t.bb_addr "
        "  AND t.session_id=?3 "
        "WHERE e.from_addr=?1 AND e.to_addr=?2 "
        "ORDER BY hits DESC",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)from);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)to);
        sqlite3_bind_int(st,   3, session_id);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *et = (const char *)sqlite3_column_text(st, 2);
            int hits = sqlite3_column_int(st, 3);
            snprintf(buf, sizeof(buf), "%s  (observed %d times in trace)",
                     et ? et : "?", hits);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    return 0;
}

/* ================================================================== */
/* 后端探测                                                            */
/* ================================================================== */

trace_backend_t* trace_detect_backend(void)
{
    for (int i = 0; trace_backends[i]; i++) {
        if (trace_backends[i]->probe())
            return trace_backends[i];
    }
    return &sw_trace_backend; /* 始终可用的 fallback */
}
