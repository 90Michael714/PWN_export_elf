/*
 * reg_diff.h — 寄存器差分引擎
 *
 * 每次 ptrace step/continue 后对比新旧寄存器值, 标记变化。
 * 独立模块 — 不依赖 elf_parser.h / tui.h / notcurses。
 * 仅依赖: <sys/user.h> (struct user_regs_struct)
 *
 * 使用流程:
 *   RegDiffState  diff;
 *   reg_diff_init(&diff);
 *
 *   // 每次 GETREGS 后:
 *   reg_diff_snapshot(&diff, &ds->regs);   // 保存快照 → 自动与上次对比
 *
 *   // 渲染:
 *   RegDiffResult result;
 *   reg_diff_get_result(&diff, &result, ds->regs.rip);
 *   reg_diff_format(&result, buf, sizeof(buf));   // 弹窗文本
 *   // 或
 *   reg_diff_render(&result, pd);                  // PanelData
 *
 * 设计要点:
 *   - 只对比用户态关心的寄存器 (GPRs + EFLAGS + 段寄存器)
 *   - 变化的寄存器标记 [+] 前缀
 *   - 显示 old → new 的完整转换
 *   - 支持两种输出: 弹窗纯文本 + PanelData 面板
 */

#ifndef REG_DIFF_H
#define REG_DIFF_H

#include <sys/user.h>
#include <stdint.h>
#include <stddef.h>

/* ── 差异条目 ──────────────────────────────────────────────────── */

typedef struct {
    const char *name;          /* 寄存器名称 ("RAX", "RIP", "EFLAGS" ...) */
    uint64_t    old_value;     /* 上一次快照的值 */
    uint64_t    new_value;     /* 当前快照的值 */
    uint64_t    changed_mask;  /* 哪些 bit 变了 (用于 EFLAGS 分解) */
    int         changed;       /* 1 = 该寄存器发生了变化 */
} RegDiffEntry;

/* ── 差异结果 ──────────────────────────────────────────────────── */

#define REG_DIFF_MAX_ENTRIES  32

typedef struct {
    RegDiffEntry entries[REG_DIFF_MAX_ENTRIES];
    int          entry_count;
    int          changed_count;   /* 变化了的寄存器数 */
    uint64_t     rip;             /* 当前 RIP (仅用于显示) */
} RegDiffResult;

/* ── 差分状态 (内部使用) ──────────────────────────────────────── */

typedef struct {
    struct user_regs_struct  prev_regs;   /* 上一次快照 */
    struct user_regs_struct  curr_regs;   /* 当前快照 */
    int                      has_prev;    /* 有历史数据可对比? */
    int                      has_curr;    /* 当前快照有效? */
    int                      step_count;  /* 从 init 开始的步数 */
} RegDiffState;

/* ── API ───────────────────────────────────────────────────────── */

/*
 * 初始化差分状态。必须在第一次 snapshot 前调用。
 */
void reg_diff_init(RegDiffState *state);

/*
 * 保存当前寄存器快照到差分状态。
 * 内部逻辑:
 *   如果 has_curr → curr → prev (前移)
 *   存入新 curr
 *   如果 has_prev && has_curr → 可对比
 *
 * 调用时机: debug_getregs() 成功返回后。
 */
void reg_diff_snapshot(RegDiffState *state,
                       const struct user_regs_struct *regs);

/*
 * 从差分状态生成对比结果。
 * 调用时机: 渲染前 (在 reg_diff_snapshot 之后)。
 *
 * 参数:
 *   state  — 差分状态 (至少需要 has_prev && has_curr)
 *   result — 输出结果
 *   rip    — 当前 RIP (通常来自 ds->regs.rip)
 *
 * 返回: 0 = 成功, -1 = 无可对比数据 (第一次运行)
 */
int  reg_diff_get_result(RegDiffState *state,
                         RegDiffResult *result,
                         uint64_t rip);

/*
 * 快速查询: 某个寄存器是否变化了。
 * 内部直接对比 prev vs curr 的 offset。
 *
 * 参数:
 *   state  — 差分状态
 *   name   — 寄存器名 ("RAX", "RIP", ...)
 *
 * 返回: 1 = 变化, 0 = 未变化, -1 = 无可对比数据
 */
int  reg_diff_reg_changed(RegDiffState *state, const char *name);

/*
 * 快速查询: 按字节偏移对比。
 *
 * 参数:
 *   state  — 差分状态
 *   offset — 在 struct user_regs_struct 中的字节偏移
 *
 * 返回: 1 = 变化, 0 = 未变化
 */
int  reg_diff_offset_changed(RegDiffState *state, size_t offset);

/*
 * 将差异结果格式化为弹窗友好的文本 (≤4096 字节)。
 *
 * 输出格式:
 *   === Register Diff (step 5, RIP=0x401234) ===
 *
 *   [+] RAX  0x00000000 → 0x41414141
 *   [+] RIP  0x401230   → 0x401234  (+4)
 *   [+] RSP  0x7FFF..   → 0x7FFF..  (-8, push detected)
 *   [+] EFLAGS  0x202 → 0x246  [ IF → IF ZF PF ]
 *
 *   ── Unchanged (22 regs) ──
 *   RBX  0x...  RCX  0x...  ...
 *
 * 返回: out (与参数相同, 方便链式调用)
 */
const char *reg_diff_format(const RegDiffResult *result,
                            int step_count,
                            char *out, size_t out_sz);

#endif /* REG_DIFF_H */
