/*
 * worker.h — 异步分析 Worker 抽象层
 *
 * 每个 parser 调用包装为独立 Job，在后台线程执行。
 * 主线程通过 worker_poll() 检查完成状态，非阻塞。
 *
 * 设计约束:
 *  - Worker 线程独立内存空间，崩溃不影响主线程
 *  - Job 可取消，可超时
 *  - 零依赖，纯 pthread + 标准 C
 */

#ifndef WORKER_H
#define WORKER_H

#include <pthread.h>
#include <stdint.h>
#include "elf_parser.h"

/* Job 状态 */
typedef enum { JOB_IDLE = 0, JOB_RUNNING, JOB_DONE, JOB_ERROR } JobStatus;

/* Worker 函数签名: 所有解析器统一为 (Elf64_Ctx*, arg_int, arg_ptr) → PanelData* */
typedef PanelData* (*WorkerFn)(Elf64_Ctx *ctx, int arg_int, void *arg_ptr);

/* 分析 Job */
typedef struct Job {
    int           job_id;
    WorkerFn      fn;           /* 解析函数 */
    Elf64_Ctx    *ctx;          /* ELF 上下文 (只读, mmap) */
    int           arg_int;      /* shdr_idx 或 -1 */
    void         *arg_ptr;      /* 额外参数 (可 NULL) */

    /* 输出 (Worker 分配, 调用者释放) */
    PanelData    *result;
    volatile int  status;       /* JobStatus */
    char          error[128];   /* 错误消息 (status==JOB_ERROR 时有效) */

    /* 内部 */
    pthread_t     thread;
    int           cancelled;
} Job;

/* ================================================================
 * Worker Pool API
 * ================================================================ */

/* 初始化 Worker 线程池 (num_workers: 0=自动检测 CPU 核数) */
int  worker_pool_init(int num_workers);

/* 销毁线程池, 取消所有运行中的 Job */
void worker_pool_shutdown(void);

/* 提交 Job 到后台线程执行, 立即返回 (非阻塞) */
int  worker_submit(WorkerFn fn, Elf64_Ctx *ctx, int arg_int, void *arg_ptr, Job **out);

/* 轮询 Job 状态 (非阻塞). 返回: JOB_RUNNING=还在跑, JOB_DONE=完成, JOB_ERROR=出错 */
int  worker_poll(Job *job);

/* 阻塞等待 Job 完成 */
void worker_wait(Job *job);

/* 取消 Job */
void worker_cancel(Job *job);

/* 释放 Job 和其 result */
void job_free(Job *job);

/* ================================================================
 * 便捷宏: 所有解析函数适配为 WorkerFn
 * ================================================================ */

/* 适配无 arg_int 的解析器: parse_xxx(ctx, pd) */
#define WRAP_0ARG(fn) ((WorkerFn)(fn))

/* 适配带 shdr_idx 的解析器: parse_xxx(ctx, shdr_idx, pd) */
PanelData* wrap_disasm(Elf64_Ctx *ctx, int shdr_idx, void *unused);
PanelData* wrap_hexdump(Elf64_Ctx *ctx, int shdr_idx, void *unused);
PanelData* wrap_got_plt(Elf64_Ctx *ctx, int shdr_idx, void *unused);
PanelData* wrap_gadget(Elf64_Ctx *ctx, int shdr_idx, void *unused);
PanelData* wrap_cfg_view(Elf64_Ctx *ctx, int shdr_idx, void *unused);
PanelData* wrap_init_array(Elf64_Ctx *ctx, int shdr_idx, void *unused);

#endif
