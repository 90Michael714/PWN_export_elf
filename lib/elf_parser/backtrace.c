/*
 * backtrace.c — 栈回溯引擎 (依赖: debug_worker.h)
 *
 * 标准 x86-64 RBP 链式栈展开:
 *   frame[0]: 当前位置 (rip 来自 regs)
 *   frame[1]: [rbp] → saved_rbp, [rbp+8] → saved_rip
 *   ...直到 rbp==0 或超出栈范围
 *
 * API:
 *   int backtrace_unwind(DebugState *ds, bt_frame_t *frames, int max);
 *
 * 依赖:
 *   #include "core/debug_worker.h" (debug_readmem, ds->regs.rbp/rsp/rip)
 */
#include "core/debug_worker.h"
#include <string.h>
#include <stdint.h>

typedef struct {
    int      index;
    uint64_t rip;
    uint64_t rbp;
    uint64_t rsp;
} bt_frame_t;

int backtrace_unwind(DebugState *ds, bt_frame_t *frames, int max)
{
    if (!ds || !frames || max <= 0) return 0;

    uint64_t rbp = ds->regs.rbp;
    uint64_t rsp_val = ds->regs.rsp;
    uint64_t rip_val = ds->regs.rip;

    int count = 0;
    int max_depth = max < 64 ? max : 64;

    /* 帧 0: 当前位置 */
    frames[count].index = 0;
    frames[count].rip   = rip_val;
    frames[count].rbp   = rbp;
    frames[count].rsp   = rsp_val;
    count++;

    /* 帧 1..N: RBP 链 */
    for (int i = 1; i < max_depth && rbp != 0; i++) {
        uint64_t data[2];
        if (debug_readmem(ds, rbp, data, 16) != 16)
            break;

        uint64_t saved_rbp = data[0];
        uint64_t saved_rip = data[1];

        /* 合法性检查 */
        if (saved_rbp != 0 && saved_rbp <= rbp) break;
        if (saved_rip == 0 || saved_rip > 0x7fffffffffffULL) break;

        frames[count].index = i;
        frames[count].rip   = saved_rip;
        frames[count].rbp   = saved_rbp;
        frames[count].rsp   = rbp + 16;
        count++;

        rbp = saved_rbp;
    }

    return count;
}
