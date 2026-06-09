/*
 * hw_breakpoint.c — 硬件断点引擎 (依赖: debug_worker.h)
 *
 * x86-64 提供 4 个调试寄存器: DR0-DR3 (地址), DR6 (状态), DR7 (控制)。
 * 硬件断点无需修改代码字节 (不像 int3), 支持:
 *   - 执行断点: 在指定地址执行时触发
 *   - 写入断点: 在指定地址被写入时触发 (watchpoint)
 *   - 读写断点: 在指定地址被访问时触发
 *
 * DR7 控制位布局:
 *   bit 0:     L0 (启用 DR0)
 *   bit 2:     L1 (启用 DR1)
 *   bit 4:     L2 (启用 DR2)
 *   bit 6:     L3 (启用 DR3)
 *   bit 16-17: R/W0 (00=exec 01=write 11=r/w)
 *   bit 18-19: LEN0 (00=1B 01=2B 11=4B)
 *   ...same pattern for DR1/DR2/DR3
 *
 * API:
 *   int hwbp_set(DebugState *ds, int slot, uint64_t addr, int type, int len);
 *   int hwbp_clear(DebugState *ds, int slot);
 *   int hwbp_get_triggered(DebugState *ds);  // 返回触发的 slot 编号, -1=无
 *
 * 依赖:
 *   #include <sys/ptrace.h>  (PTRACE_POKEUSER, PTRACE_PEEKUSER)
 *   #include "core/debug_worker.h" (DebugState + ds->pid)
 */
#include <sys/ptrace.h>
#include <sys/types.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "core/debug_worker.h"

/* DR 寄存器在 user 结构中的偏移 (Linux x86-64) */
#define DR_OFFSET(dr)   (offsetof(struct user, u_debugreg) + (dr)*8)

#define HWBP_EXEC  0
#define HWBP_WRITE 1
#define HWBP_RW    3

/**
 * 设置硬件断点。
 * @param ds    调试状态
 * @param slot  槽位 (0-3)
 * @param addr  断点地址 (执行断点) 或监控地址 (watchpoint)
 * @param type  HWBP_EXEC / HWBP_WRITE / HWBP_RW
 * @param len   监控长度 (1/2/4/8 字节, 执行断点忽略)
 * @return      0=成功, -1=失败
 */
int hwbp_set(struct DebugState *ds, int slot,
             uint64_t addr, int type, int len)
{
    if (!ds || slot < 0 || slot > 3) return -1;

    pid_t pid = *(const pid_t *)ds; /* ds->pid */

    /* 1. 写入地址到 DR0-DR3 */
    if (ptrace(PTRACE_POKEUSER, pid, (void *)DR_OFFSET(slot),
               (void *)addr) == -1)
        return -1;

    /* 2. 读取当前 DR7 */
    unsigned long dr7 = (unsigned long)ptrace(PTRACE_PEEKUSER, pid,
                                               (void *)DR_OFFSET(7), NULL);

    /* 3. 设置启用位 (L0-L3) */
    unsigned long enable_bit = 1UL << (slot * 2);
    dr7 |= enable_bit;

    /* 4. 设置 R/W 和 LEN */
    int rw_shift = 16 + slot * 4;
    dr7 &= ~(0x3UL << rw_shift);     /* 清除原 R/W */
    dr7 |= ((unsigned long)type << rw_shift);

    int len_shift = 18 + slot * 4;
    int len_enc = (len == 2) ? 1 : (len == 8) ? 2 : (len == 4) ? 3 : 0;
    dr7 &= ~(0x3UL << len_shift);    /* 清除原 LEN */
    dr7 |= ((unsigned long)len_enc << len_shift);

    /* 5. 写回 DR7 */
    if (ptrace(PTRACE_POKEUSER, pid, (void *)DR_OFFSET(7),
               (void *)dr7) == -1)
        return -1;

    return 0;
}

/**
 * 清除指定槽位的硬件断点。
 * @return 0=成功, -1=失败
 */
int hwbp_clear(struct DebugState *ds, int slot)
{
    if (!ds || slot < 0 || slot > 3) return -1;

    pid_t pid = *(const pid_t *)ds;

    unsigned long dr7 = (unsigned long)ptrace(PTRACE_PEEKUSER, pid,
                                               (void *)DR_OFFSET(7), NULL);
    /* 清除启用位, R/W, LEN */
    dr7 &= ~(1UL << (slot * 2));
    dr7 &= ~(0x3UL << (16 + slot * 4));
    dr7 &= ~(0x3UL << (18 + slot * 4));

    if (ptrace(PTRACE_POKEUSER, pid, (void *)DR_OFFSET(7),
               (void *)dr7) == -1)
        return -1;

    return 0;
}

/**
 * 清除所有硬件断点。
 */
void hwbp_clear_all(struct DebugState *ds)
{
    for (int i = 0; i < 4; i++) hwbp_clear(ds, i);
}

/**
 * 读取 DR6 状态寄存器, 返回触发的槽位编号。
 * @return 0-3 = 触发的槽位, -1 = 无触发
 */
int hwbp_get_triggered(struct DebugState *ds)
{
    if (!ds) return -1;
    pid_t pid = *(const pid_t *)ds;

    unsigned long dr6 = (unsigned long)ptrace(PTRACE_PEEKUSER, pid,
                                               (void *)DR_OFFSET(6), NULL);
    for (int i = 0; i < 4; i++)
        if (dr6 & (1UL << i)) return i;

    return -1;
}

/**
 * 获取槽位的硬件断点地址。
 */
uint64_t hwbp_get_addr(struct DebugState *ds, int slot)
{
    if (!ds || slot < 0 || slot > 3) return 0;
    pid_t pid = *(const pid_t *)ds;
    return (uint64_t)ptrace(PTRACE_PEEKUSER, pid,
                            (void *)DR_OFFSET(slot), NULL);
}
