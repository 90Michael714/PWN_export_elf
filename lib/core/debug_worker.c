/*
 * debug_worker.c — Ptrace 调试引擎实现
 *
 * 完整 ptrace(2) 封装: ATTACH → GETREGS → CONT/STEP → 信号处理 → DETACH
 *
 * 状态机:
 *   [unattached] → debug_attach() → [stopped]
 *   [stopped] → debug_getregs() → [stopped] (读取寄存器)
 *   [stopped] → debug_continue() → [running] → wait → [stopped]
 *   [stopped] → debug_step() → [running] → wait → [stopped]
 *   [stopped] → debug_detach() → [unattached]
 *
 * 软件断点:
 *   set:  读原始字节 → 保存 → 写入 0xCC
 *   hit:  收到 SIGTRAP → 检查 rip-1 是否在 BP 表中 → 恢复原始字节
 *         → 回退 rip → 单步 → 重新写入 0xCC → 恢复执行
 */

#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include "core/debug_worker.h"

/* ── 内部错误状态 ───────────────────────────────────────────────── */

static char debug_err_buf[256];

const char *debug_error(void) {
    return debug_err_buf;
}

static void set_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(debug_err_buf, sizeof(debug_err_buf), fmt, ap);
    va_end(ap);
}

/* ── 信号等待辅助 ───────────────────────────────────────────────── */

static int wait_for_signal(DebugState *ds) {
    int status = 0;
    if (waitpid(ds->pid, &status, 0) == -1) {
        set_error("waitpid failed: %s", strerror(errno));
        return -1;
    }
    ds->last_status = status;

    if (WIFEXITED(status)) {
        set_error("process exited with code %d", WEXITSTATUS(status));
        ds->attached = 0;
        return -1;
    }
    if (WIFSIGNALED(status)) {
        set_error("process killed by signal %d", WTERMSIG(status));
        ds->attached = 0;
        return -1;
    }
    if (WIFSTOPPED(status)) {
        ds->last_signal = WSTOPSIG(status);
        return 0;
    }
    return 0;   /* WIFCONTINUED — rare */
}

/* ── 软件断点内部处理 ──────────────────────────────────────────── */

/* 查找地址是否命中已启用的断点 (检查 addr 和 addr-1, int3 使 rip 指向后一字节) */
static int find_bp_index(DebugState *ds, uint64_t addr) {
    for (int i = 0; i < ds->bp_count; i++) {
        if (ds->breakpoints[i].enabled &&
            ds->breakpoints[i].type == DEBUG_BP_SOFTWARE) {
            /* int3 断点触发后 rip 指向 0xCC 的下一字节, 即 bp_addr+1 */
            if (ds->breakpoints[i].addr == addr - 1 ||
                ds->breakpoints[i].addr == addr) {
                return i;
            }
        }
    }
    return -1;
}

/* 恢复断点 → 回退 rip → 单步越过 → 重新写入断点
 * 注意: PTRACE_POKEDATA 写入 8 字节, 必须用 read-modify-write 避免损坏相邻内存 */
static int handle_breakpoint_hit(DebugState *ds, int bp_idx) {
    Breakpoint *bp = &ds->breakpoints[bp_idx];

    /* 1. 写回原始字节 (使用 debug_writemem 做 read-modify-write, 只改1字节) */
    if (debug_writemem(ds, bp->addr, &bp->saved_byte, 1) != 1) {
        set_error("breakpoint restore failed");
        return -1;
    }

    /* 2. 回退 rip 到断点地址 */
    ds->regs.rip = bp->addr;
    if (ptrace(PTRACE_SETREGS, ds->pid, NULL, &ds->regs) == -1) {
        set_error("SETREGS (rip restore) failed: %s", strerror(errno));
        return -1;
    }

    /* 3. 单步越过该指令 */
    if (ptrace(PTRACE_SINGLESTEP, ds->pid, NULL, NULL) == -1) {
        set_error("SINGLESTEP after bp failed: %s", strerror(errno));
        return -1;
    }
    if (wait_for_signal(ds) != 0) return -1;

    /* 4. 重新写入 0xCC (使用 debug_writemem 做 read-modify-write) */
    uint8_t int3 = 0xCC;
    if (debug_writemem(ds, bp->addr, &int3, 1) != 1) {
        set_error("breakpoint re-insert failed");
        return -1;
    }

    /* 5. 刷新寄存器 (rip 现在指向下一条指令) */
    if (ptrace(PTRACE_GETREGS, ds->pid, NULL, &ds->regs) == -1) {
        set_error("GETREGS after bp step failed: %s", strerror(errno));
        return -1;
    }
    ds->regs_valid = 1;

    return 0;
}

/* ── 公开 API ───────────────────────────────────────────────────── */

int debug_attach(pid_t pid, DebugState **ds_out) {
    if (!ds_out) return -1;
    *ds_out = NULL;

    if (pid <= 0) {
        set_error("invalid PID %d", pid);
        return -1;
    }

    DebugState *ds = calloc(1, sizeof(DebugState));
    if (!ds) {
        set_error("malloc DebugState failed");
        return -1;
    }
    ds->pid = pid;

    /* Attach */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        set_error("PTRACE_ATTACH %d failed: %s", pid, strerror(errno));
        free(ds);
        return -1;
    }
    ds->attached = 1;

    /* Wait for stop */
    if (wait_for_signal(ds) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free(ds);
        return -1;
    }

    /* 初始寄存器快照 */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &ds->regs) == -1) {
        set_error("initial GETREGS failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free(ds);
        return -1;
    }
    ds->regs_valid = 1;

    /* Try FP regs (may fail if kernel doesn't support) */
    if (ptrace(PTRACE_GETFPREGS, pid, NULL, &ds->fpregs) == 0) {
        ds->fpregs_valid = 1;
    }

    *ds_out = ds;
    return 0;
}

int debug_continue(DebugState *ds) {
    if (!ds || !ds->attached) return -1;

    /* 如果有已启用的软件断点且 rip 指向其中某个, 先处理断点恢复 */
    int bp_idx = find_bp_index(ds, ds->regs.rip);
    if (bp_idx >= 0) {
        if (handle_breakpoint_hit(ds, bp_idx) != 0) return -1;
    }

    if (ptrace(PTRACE_CONT, ds->pid, NULL, NULL) == -1) {
        set_error("PTRACE_CONT failed: %s", strerror(errno));
        return -1;
    }

    if (wait_for_signal(ds) != 0) return -1;

    /* 关键: CONT 之后必须刷新寄存器, ds->regs.rip 已过期 */
    if (debug_getregs(ds) != 0) return -1;

    /* 检查是否命中断点 (使用刚刷新的 rip) */
    if (ds->last_signal == SIGTRAP) {
        bp_idx = find_bp_index(ds, ds->regs.rip);
        if (bp_idx >= 0) {
            return handle_breakpoint_hit(ds, bp_idx);
        }
    }

    return 0;
}

int debug_step(DebugState *ds) {
    if (!ds || !ds->attached) return -1;

    /* 处理可能存在的断点恢复 (如果停在断点上) */
    int bp_idx = find_bp_index(ds, ds->regs.rip);
    if (bp_idx >= 0) {
        if (handle_breakpoint_hit(ds, bp_idx) != 0) return -1;
    }

    if (ptrace(PTRACE_SINGLESTEP, ds->pid, NULL, NULL) == -1) {
        set_error("PTRACE_SINGLESTEP failed: %s", strerror(errno));
        return -1;
    }

    if (wait_for_signal(ds) != 0) return -1;

    /* 关键: SINGLESTEP 之后刷新寄存器 */
    if (debug_getregs(ds) != 0) return -1;

    /* 检查是否命中断点 (单步越过了 int3, 使用刚刷新的 rip) */
    if (ds->last_signal == SIGTRAP) {
        bp_idx = find_bp_index(ds, ds->regs.rip);
        if (bp_idx >= 0) {
            return handle_breakpoint_hit(ds, bp_idx);
        }
    }

    return 0;
}

int debug_step_over(DebugState *ds) {
    if (!ds || !ds->attached || !ds->regs_valid) return -1;

    /* 读取 rip 处的指令, 判断是否是 call */
    uint8_t instr[16];
    if (debug_readmem(ds, ds->regs.rip, instr, sizeof(instr)) <= 0) {
        return debug_step(ds);
    }

    /* 跳过 REX 前缀 (0x40-0x4F, 位于操作码之前) */
    int pos = 0;
    if (instr[0] >= 0x40 && instr[0] <= 0x4F)
        pos = 1;

    /* 检测 call 指令 */
    int is_call = 0;
    int call_len = 0;
    if (instr[pos] == 0xE8) {                         /* CALL rel32 */
        is_call = 1;
        call_len = pos + 5;
    } else if (instr[pos] == 0xFF && (instr[pos+1] & 0x38) == 0x10) {
        /* CALL r/m64 — ModR/M 编码, 长度 = REX(0/1) + 2(op+modrm) + 偏移 */
        is_call = 1;
        call_len = pos + 2;
        uint8_t mod = (instr[pos+1] >> 6) & 0x3;
        uint8_t rm  = instr[pos+1] & 0x7;
        if (rm == 4) call_len += 1;                    /* SIB 字节 */
        if (mod == 0 && rm == 5) call_len += 4;         /* [rip+disp32] */
        else if (mod == 1)       call_len += 1;         /* [reg+disp8] */
        else if (mod == 2)       call_len += 4;         /* [reg+disp32] */
    }

    if (is_call) {
        /* 在 call 下一条指令设置临时断点 */
        uint64_t after_call = ds->regs.rip + call_len;
        int tmp_bp = debug_set_breakpoint(ds, after_call);
        if (tmp_bp >= 0) {
            /* 继续执行到临时断点 */
            int ret = debug_continue(ds);
            debug_remove_breakpoint(ds, after_call);
            return ret;
        }
    }

    /* 不是 call 或断点设置失败 → 普通单步 */
    return debug_step(ds);
}

int debug_getregs(DebugState *ds) {
    if (!ds || !ds->attached) return -1;

    if (ptrace(PTRACE_GETREGS, ds->pid, NULL, &ds->regs) == -1) {
        set_error("GETREGS failed: %s", strerror(errno));
        return -1;
    }
    ds->regs_valid = 1;

    /* FP regs: best-effort */
    if (ptrace(PTRACE_GETFPREGS, ds->pid, NULL, &ds->fpregs) == 0) {
        ds->fpregs_valid = 1;
    } else {
        ds->fpregs_valid = 0;
    }

    return 0;
}

int debug_readmem(DebugState *ds, uint64_t addr, void *buf, size_t len) {
    if (!ds || !ds->attached || !buf) return -1;
    if (len == 0) return 0;

    /*
     * PTRACE_PEEKDATA reads one word at a time.  Use process_vm_readv
     * for bulk reads when available, fall back to PEEKDATA.
     */
    size_t total = 0;
    uint8_t *dst = buf;

    while (total < len) {
        size_t remaining = len - total;
        uint64_t aligned_addr = addr + total;
        uint64_t aligned_base = aligned_addr & ~(uint64_t)7;

        /*
         * Try process_vm_readv first (faster, handles arbitrary sizes)
         * Fall back to PTRACE_PEEKDATA for each word
         */
        struct iovec local  = { .iov_base = dst + total, .iov_len = remaining };
        struct iovec remote = { .iov_base = (void *)aligned_addr, .iov_len = remaining };
        ssize_t n = process_vm_readv(ds->pid, &local, 1, &remote, 1, 0);

        if (n > 0) {
            total += (size_t)n;
            continue;
        }

        /* Fallback: PTRACE_PEEKDATA */
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, ds->pid,
                           (void *)aligned_base, NULL);
        if (word == -1 && errno != 0) {
            if (total == 0) {
                set_error("readmem @ 0x%lx failed: %s",
                          aligned_addr, strerror(errno));
                return -1;
            }
            return (int)total;  /* partial read */
        }

        /* Copy from the word, handling unaligned start */
        size_t offset_in_word = (size_t)(aligned_addr - aligned_base);
        size_t copy_len = 8 - offset_in_word;
        if (copy_len > remaining) copy_len = remaining;
        memcpy(dst + total, ((uint8_t *)&word) + offset_in_word, copy_len);
        total += copy_len;
    }

    return (int)total;
}

int debug_writemem(DebugState *ds, uint64_t addr, const void *buf,
                   size_t len) {
    if (!ds || !ds->attached || !buf) return -1;
    if (len == 0) return 0;

    const uint8_t *src = buf;
    size_t total = 0;

    while (total < len) {
        size_t remaining = len - total;
        uint64_t cur_addr = addr + total;

        /* Try process_vm_writev first */
        struct iovec local  = { .iov_base = (void *)(src + total), .iov_len = remaining };
        struct iovec remote = { .iov_base = (void *)cur_addr, .iov_len = remaining };
        ssize_t n = process_vm_writev(ds->pid, &local, 1, &remote, 1, 0);

        if (n > 0) {
            total += (size_t)n;
            continue;
        }

        /* Fallback: PTRACE_POKEDATA for aligned word */
        uint64_t aligned_addr = cur_addr & ~(uint64_t)7;
        size_t offset_in_word = (size_t)(cur_addr - aligned_addr);
        size_t copy_len = 8 - offset_in_word;
        if (copy_len > remaining) copy_len = remaining;

        /* Read-modify-write for unaligned access */
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, ds->pid,
                           (void *)aligned_addr, NULL);
        if (word == -1 && errno != 0) {
            if (total == 0) return -1;
            return (int)total;
        }

        memcpy(((uint8_t *)&word) + offset_in_word,
               src + total, copy_len);

        if (ptrace(PTRACE_POKEDATA, ds->pid,
                   (void *)aligned_addr, (void *)word) == -1) {
            if (total == 0) {
                set_error("writemem @ 0x%lx failed: %s",
                          cur_addr, strerror(errno));
                return -1;
            }
            return (int)total;
        }
        total += copy_len;
    }

    return (int)total;
}

int debug_set_breakpoint(DebugState *ds, uint64_t addr) {
    if (!ds || !ds->attached) return -1;

    /* 检查是否已存在 */
    for (int i = 0; i < ds->bp_count; i++) {
        if (ds->breakpoints[i].addr == addr) {
            ds->breakpoints[i].enabled = 1;
            return i;
        }
    }

    if (ds->bp_count >= DEBUG_MAX_BREAKPOINTS) {
        set_error("breakpoint table full (max %d)", DEBUG_MAX_BREAKPOINTS);
        return -1;
    }

    Breakpoint *bp = &ds->breakpoints[ds->bp_count];
    bp->addr    = addr;
    bp->type    = DEBUG_BP_SOFTWARE;
    bp->enabled = 1;

    /* 读取原始字节 */
    if (debug_readmem(ds, addr, &bp->saved_byte, 1) != 1) {
        set_error("cannot read memory at breakpoint 0x%lx", addr);
        return -1;
    }

    /* 写入 int3 */
    uint8_t int3 = 0xCC;
    if (debug_writemem(ds, addr, &int3, 1) != 1) {
        set_error("cannot write int3 at 0x%lx", addr);
        return -1;
    }

    return ds->bp_count++;
}

int debug_remove_breakpoint(DebugState *ds, uint64_t addr) {
    if (!ds || !ds->attached) return -1;

    for (int i = 0; i < ds->bp_count; i++) {
        if (ds->breakpoints[i].addr == addr) {
            /* 恢复原始字节 */
            debug_writemem(ds, addr, &ds->breakpoints[i].saved_byte, 1);

            /* 从表中移除 (用最后一个元素填充空洞) */
            ds->bp_count--;
            if (i < ds->bp_count) {
                ds->breakpoints[i] = ds->breakpoints[ds->bp_count];
            }
            return 0;
        }
    }
    return -1;
}

int debug_detach(DebugState *ds) {
    if (!ds || !ds->attached) return -1;

    /* 恢复所有断点的原始字节 */
    for (int i = 0; i < ds->bp_count; i++) {
        if (ds->breakpoints[i].enabled &&
            ds->breakpoints[i].type == DEBUG_BP_SOFTWARE) {
            debug_writemem(ds, ds->breakpoints[i].addr,
                          &ds->breakpoints[i].saved_byte, 1);
        }
    }
    ds->bp_count = 0;

    if (ptrace(PTRACE_DETACH, ds->pid, NULL, NULL) == -1) {
        set_error("PTRACE_DETACH failed: %s", strerror(errno));
        return -1;
    }
    ds->attached = 0;
    return 0;
}

void debug_free(DebugState *ds) {
    if (!ds) return;
    if (ds->attached) {
        debug_detach(ds);
    }
    free(ds);
}
