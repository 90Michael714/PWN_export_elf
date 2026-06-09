/*
 * worker.c — 异步分析 Worker 线程池实现
 */

#include "core/worker.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_WORKERS 8
#define MAX_JOBS    32

static pthread_t   workers[MAX_WORKERS];
static int         worker_count = 0;
static int         pool_running = 0;

static Job        *job_queue[MAX_JOBS];
static int         job_head = 0, job_tail = 0;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  queue_cond  = PTHREAD_COND_INITIALIZER;

/* ── Worker 线程主循环 ── */
static void *worker_thread(void *arg)
{
    (void)arg;
    while (pool_running) {
        /* 从队列取 Job */
        pthread_mutex_lock(&queue_lock);
        while (job_head == job_tail && pool_running)
            pthread_cond_wait(&queue_cond, &queue_lock);
        if (!pool_running) { pthread_mutex_unlock(&queue_lock); break; }

        Job *job = job_queue[job_head];
        job_head = (job_head + 1) % MAX_JOBS;
        pthread_mutex_unlock(&queue_lock);

        /* 执行分析函数 */
        job->status = JOB_RUNNING;
        job->result = job->fn(job->ctx, job->arg_int, job->arg_ptr);
        if (job->result)
            job->status = JOB_DONE;
        else {
            job->status = JOB_ERROR;
            snprintf(job->error, sizeof(job->error),
                     "analysis function returned NULL");
        }
    }
    return NULL;
}

/* ── 线程池管理 ── */
int worker_pool_init(int num_workers)
{
    if (num_workers <= 0) num_workers = 2;  /* 默认 2 个 Worker */
    if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;

    pool_running = 1;
    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) == 0)
            worker_count++;
    }
    return worker_count;
}

void worker_pool_shutdown(void)
{
    pool_running = 0;
    pthread_cond_broadcast(&queue_cond);
    for (int i = 0; i < worker_count; i++)
        pthread_join(workers[i], NULL);
    worker_count = 0;
}

/* ── Job 提交/轮询/等待 ── */
int worker_submit(WorkerFn fn, Elf64_Ctx *ctx, int arg_int,
                  void *arg_ptr, Job **out)
{
    Job *job = calloc(1, sizeof(Job));
    if (!job) return -1;

    static int next_id = 1;
    job->job_id   = next_id++;
    job->fn       = fn;
    job->ctx      = ctx;
    job->arg_int  = arg_int;
    job->arg_ptr  = arg_ptr;
    job->status   = JOB_IDLE;

    pthread_mutex_lock(&queue_lock);
    int next = (job_tail + 1) % MAX_JOBS;
    if (next == job_head) {
        pthread_mutex_unlock(&queue_lock);
        free(job);
        return -1;  /* 队列满 */
    }
    job_queue[job_tail] = job;
    job_tail = next;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_lock);

    if (out) *out = job;
    return job->job_id;
}

int worker_poll(Job *job)
{
    if (!job) return JOB_ERROR;
    return job->status;
}

void worker_wait(Job *job)
{
    if (!job) return;
    while (job->status == JOB_IDLE || job->status == JOB_RUNNING) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 };
        nanosleep(&ts, NULL);
    }
}

void worker_cancel(Job *job)
{
    if (!job) return;
    job->cancelled = 1;
    /* 注意: 无法强制杀死正在运行的 Worker 线程。
       如果 job 已经出队执行, 只能等它自己完成。*/
    if (job->status == JOB_IDLE) {
        job->status = JOB_ERROR;
        snprintf(job->error, sizeof(job->error), "cancelled before execution");
    }
}

void job_free(Job *job)
{
    if (!job) return;
    if (job->result) {
        fields_free(job->result->fields, job->result->count);
        free(job->result);
    }
    free(job);
}

/* ── Wrapper 函数: 适配不同签名的解析器 ── */

PanelData* wrap_disasm(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_disasm(ctx, shdr_idx, pd); return pd; }

PanelData* wrap_hexdump(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_hexdump(ctx, shdr_idx, pd); return pd; }

PanelData* wrap_got_plt(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_got_plt(ctx, shdr_idx, pd); return pd; }

PanelData* wrap_gadget(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_gadget(ctx, shdr_idx, pd); return pd; }

PanelData* wrap_cfg_view(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_cfg_view(ctx, shdr_idx, pd); return pd; }

PanelData* wrap_init_array(Elf64_Ctx *ctx, int shdr_idx, void *unused)
{ (void)unused; PanelData *pd = calloc(1, sizeof(PanelData));
  parse_init_array(ctx, shdr_idx, pd); return pd; }
