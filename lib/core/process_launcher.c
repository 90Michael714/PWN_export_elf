/*
 * process_launcher.c — fork + PTRACE_TRACEME + execve
 *
 * 经典调试器启动流程:
 *   fork()
 *     ├─ child:  ptrace(TRACEME) → raise(SIGSTOP) → execve(binary)
 *     └─ parent: waitpid → 收到 SIGSTOP → 创建 DebugState
 *                → 调用者可设断点
 *                → debug_continue → 子进程 exec → 停在入口
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "core/process_launcher.h"
#include "core/debug_worker.h"

int debug_launch(const char *path, char *const argv[],
                 char *const envp[], DebugState **ds_out)
{
    if (!path || !ds_out) return -1;
    *ds_out = NULL;

    pid_t child = fork();
    if (child < 0) {
        /* fork 失败 */
        return -1;
    }

    if (child == 0) {
        /* ── 子进程 ─────────────────────────────────────────── */
        /* 允许父进程追踪 */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            _exit(127);
        }

        /* 在 exec 前停住, 让调试器有机会设断点 */
        raise(SIGSTOP);

        /* exec 目标程序 */
        execve(path, argv, envp ? envp : (char *const *)environ);

        /* exec 失败 */
        _exit(127);
    }

    /* ── 父进程 ─────────────────────────────────────────────── */
    /* 等待子进程停在 SIGSTOP */
    int status = 0;
    if (waitpid(child, &status, 0) == -1) {
        kill(child, SIGKILL);
        return -1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        /* 子进程异常退出 */
        if (WIFEXITED(status)) {
            /* 可能是 exec 失败 */
        }
        kill(child, SIGKILL);
        return -1;
    }

    /* 分配 DebugState (子进程此时停在 raise(SIGSTOP) 之后) */
    DebugState *ds = calloc(1, sizeof(DebugState));
    if (!ds) {
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return -1;
    }

    ds->pid      = child;
    ds->attached = 1;

    /* 读取初始寄存器快照 */
    if (ptrace(PTRACE_GETREGS, child, NULL, &ds->regs) == -1) {
        /* GETREGS 失败, 仍可继续 (detach 时会释放) */
        ds->regs_valid = 0;
    } else {
        ds->regs_valid = 1;
    }

    /* FP regs: best-effort */
    if (ptrace(PTRACE_GETFPREGS, child, NULL, &ds->fpregs) == 0) {
        ds->fpregs_valid = 1;
    }

    *ds_out = ds;
    return 0;
}
