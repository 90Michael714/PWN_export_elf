/*
 * debug_worker.h — Ptrace 调试引擎接口
 *
 * 实现完整 ptrace 调试子系统: 附加/读取寄存器/单步/继续/内存读写/断点。
 * 底层共享同一 tracee 状态, ATTACH/GETREGS/CONT/STEP 统一在同一个 API 面。
 *
 * 使用方式:
 *   DebugState *ds = NULL;
 *   debug_attach(pid, &ds);      // PTRACE_ATTACH + 首轮 GETREGS
 *   debug_getregs(ds);           // 刷新寄存器快照
 *   debug_step(ds);              // PTRACE_SINGLESTEP
 *   debug_continue(ds);          // PTRACE_CONT
 *   debug_detach(ds);            // PTRACE_DETACH
 */

#ifndef DEBUG_WORKER_H
#define DEBUG_WORKER_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>
#include <stddef.h>

/* ── 断点类型 ──────────────────────────────────────────────────── */

#define DEBUG_MAX_BREAKPOINTS  16
#define DEBUG_BP_SOFTWARE       0   /* int3 (0xCC) 软件断点 */
#define DEBUG_BP_HARDWARE       1   /* DR0-DR3 硬件断点 */

typedef struct {
    uint64_t addr;
    int      type;            /* DEBUG_BP_SOFTWARE / HARDWARE */
    int      enabled;
    uint8_t  saved_byte;      /* 软件断点: 原始指令字节 */
} Breakpoint;

/* ── 调试状态 ──────────────────────────────────────────────────── */

typedef struct DebugState {
    pid_t  pid;
    int    attached;           /* 1=已附加, 0=已分离 */

    /* 寄存器快照 (最后一次 GETREGS 的结果) */
    struct user_regs_struct   regs;
    struct user_fpregs_struct fpregs;
    int                       regs_valid;    /* 快照是否有效 */
    int                       fpregs_valid;

    /* 断点表 */
    Breakpoint  breakpoints[DEBUG_MAX_BREAKPOINTS];
    int         bp_count;

    /* 最后信号信息 */
    int         last_signal;    /* 导致停止的信号 (SIGTRAP/SIGSEGV/...) */
    int         last_status;    /* waitpid status */
} DebugState;

/* ── 调试控制 API ──────────────────────────────────────────────── */

/* Attach 到进程并获取初始寄存器快照. 返回 0 成功, -1 失败 */
int  debug_attach(pid_t pid, DebugState **ds_out);

/* 继续执行直到下个断点或信号. 返回 0, -1 失败 */
int  debug_continue(DebugState *ds);

/* 单步执行一条指令 (PTRACE_SINGLESTEP). 返回 0, -1 失败 */
int  debug_step(DebugState *ds);

/* 单步跨越调用 (在 call 处设置临时断点, 等效 step-over).
 * 仅在 stop 状态时可用. 返回 0, -1 失败 */
int  debug_step_over(DebugState *ds);

/* 刷新寄存器快照 (PTRACE_GETREGS + GETFPREGS). 返回 0, -1 失败 */
int  debug_getregs(DebugState *ds);

/* 读取 tracee 内存. 返回实际读取字节数, -1 失败 */
int  debug_readmem(DebugState *ds, uint64_t addr, void *buf, size_t len);

/* 写入 tracee 内存. 返回实际写入字节数, -1 失败 */
int  debug_writemem(DebugState *ds, uint64_t addr, const void *buf,
                    size_t len);

/* 设置软件断点 (int3). 返回断点索引, -1 失败 */
int  debug_set_breakpoint(DebugState *ds, uint64_t addr);

/* 移除断点并恢复原始字节. 返回 0 成功, -1 未找到 */
int  debug_remove_breakpoint(DebugState *ds, uint64_t addr);

/* Detach 并释放资源. 返回 0, -1 失败 */
int  debug_detach(DebugState *ds);

/* 释放 DebugState 内存 (调用前必须先 detach) */
void debug_free(DebugState *ds);

/* 返回最后错误的描述字符串 */
const char *debug_error(void);

#endif /* DEBUG_WORKER_H */
