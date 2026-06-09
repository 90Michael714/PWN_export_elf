/*
 * pt_trace.h — 执行 Trace 录制接口 (Intel PT / BTS / ARM-ETM)
 *
 * 可插拔 trace 后端架构:
 *   - Intel PT:  via Linux perf_event_open (PERF_TYPE_HARDWARE)
 *   - BTS:       Branch Trace Store (fallback on older Intel)
 *   - ARM ETM:   Embedded Trace Macrocell (future)
 *
 * 集成方式:
 *   1. trace_backend_t *tb = trace_detect_backend();
 *   2. tb->start(ds, &ctx);
 *   3. [执行目标代码 — 运行/单步/Fuzz 迭代]
 *   4. tb->stop(ctx);
 *   5. tb->decode(ctx, adb, session_id, pd);  // 解码为 BB 序列, 写入 DB
 *
 * DB 表 (在 db.c 中创建):
 *   trace_sessions:   (id, pid, backend, start_time, bb_count, ...)
 *   trace_blocks:     (session_id, bb_addr, exec_count, timestamp)
 */

#ifndef PT_TRACE_H
#define PT_TRACE_H

#include <stdint.h>
#include <stddef.h>
#include "elf_parser.h"   /* PanelData, Elf64_Ctx */
#include "db.h"           /* AnalysisDB */
#include "core/debug_worker.h"  /* DebugState */

/* ================================================================== */
/* Trace 基本块记录                                                    */
/* ================================================================== */

typedef struct {
    uint64_t  bb_addr;       /* 基本块起始地址 (RIP of first instruction) */
    uint64_t  timestamp;     /* 相对时间戳 (ns from trace start) */
    int       exec_count;    /* 该 BB 在本次 trace 中的执行次数 */
} trace_bb_t;

/* ================================================================== */
/* Trace Session                                                       */
/* ================================================================== */

typedef struct {
    int        session_id;   /* DB 中的 session ID */
    int        pid;
    char       backend[32];  /* "Intel PT", "BTS", "ARM ETM" */
    uint64_t   start_time;   /* 开始时间 (ns) */
    uint64_t   end_time;     /* 结束时间 (ns) */
    int        bb_count;     /* 录制的 BB 总数 */
    int        unique_bbs;   /* 唯一 BB 数 */
    double     coverage;     /* 覆盖率 (相对于所有已知 BB) */
} trace_session_t;

/* ================================================================== */
/* 可插拔 Trace 后端                                                  */
/* ================================================================== */

typedef struct trace_backend {
    const char *name;

    /* 硬件探测: 返回 1 如果当前 CPU 支持该后端 */
    int  (*probe)(void);

    /* 开始录制: 返回 >=0 的 fd 或 -1 */
    int  (*start)(struct DebugState *ds, void **ctx_out);

    /* 停止录制: 返回录制的 trace 数据大小 */
    int  (*stop)(void *ctx);

    /* 解码到 DB: trace 数据 → BB 序列 → trace_blocks 表 */
    int  (*decode)(void *ctx, AnalysisDB *adb, int session_id,
                   PanelData *pd);

    /* 释放上下文 */
    void (*free_ctx)(void *ctx);

    /* 获取录制期间的 BB 列表 (在线查询) */
    int  (*get_blocks)(void *ctx, trace_bb_t *blocks, int max);
} trace_backend_t;

/* 全局注册表 */
extern trace_backend_t *trace_backends[];

/* ================================================================== */
/* Trace 生命周期 API                                                   */
/* ================================================================== */

/* 自动探测并返回第一个可用的后端 */
trace_backend_t* trace_detect_backend(void);

/* 开始新的 trace session (返回 session_id 或 -1) */
int  trace_session_begin(AnalysisDB *adb, int pid, const char *backend);

/* 记录单条 BB 执行 */
int  trace_block_record(AnalysisDB *adb, int session_id,
                        uint64_t bb_addr, uint64_t timestamp);

/* 查询: trace 覆盖报告 */
int  trace_coverage_report(AnalysisDB *adb, int session_id, PanelData *pd);

/* 查询: trace 时间轴 */
int  trace_timeline(AnalysisDB *adb, int session_id, PanelData *pd);

/* 查询: 热点分析 (执行次数最多的 BB Top-N) */
int  trace_hotspots(AnalysisDB *adb, int session_id, PanelData *pd);

/* 查询: 路径分析 (两个地址之间的执行路径) */
int  trace_path_between(AnalysisDB *adb, int session_id,
                        uint64_t from, uint64_t to, PanelData *pd);

/* ── 软件 Trace 录制 (便携降级) ──────────────────────────────────── */

/* 有界单步采样录制: 在无 Intel PT 硬件时使用 PTRACE_SINGLESTEP
 * 采集目标进程的执行地址。返回实际步数, -1 失败。
 * max_steps: 最大指令步数 (建议 500~2000)
 * timeout_ms: 总时间上限 (毫秒, 建议 2000~5000) */
int  sw_trace_record_steps(void *ctx, struct DebugState *ds,
                            int max_steps, int timeout_ms);

#endif /* PT_TRACE_H */
