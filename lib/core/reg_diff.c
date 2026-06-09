/*
 * reg_diff.c — 寄存器差分引擎实现
 *
 * 维护 prev/curr 两个寄存器快照, 每次 snapshot 自动前移。
 * 对比: 逐寄存器比较 → 标记变化 → 格式化输出。
 *
 * 依赖:
 *   <sys/user.h>       — struct user_regs_struct
 *   "core/reg_diff.h"  — 自身接口
 *
 * 当集成到 elf-tui 时, 复制到 lib/core/reg_diff.c
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "core/reg_diff.h"

/* ── x86-64 寄存器映射表 ─────────────────────────────────────────
 *
 * 每个条目: { 显示名称, 在 struct user_regs_struct 中的字节偏移 }
 * "重要"寄存器 (经常变化的) 排在前面, 段寄存器排在最后。
 */

typedef struct {
    const char *name;
    size_t      offset;
    int         is_gpr;       /* 1 = GPR, 0 = 段寄存器 / EFLAGS */
} RegMapEntry;

static const RegMapEntry reg_map[] = {
    /* GPRs (按重要性排序) */
    { "RAX",  offsetof(struct user_regs_struct, rax),     1 },
    { "RBX",  offsetof(struct user_regs_struct, rbx),     1 },
    { "RCX",  offsetof(struct user_regs_struct, rcx),     1 },
    { "RDX",  offsetof(struct user_regs_struct, rdx),     1 },
    { "RSI",  offsetof(struct user_regs_struct, rsi),     1 },
    { "RDI",  offsetof(struct user_regs_struct, rdi),     1 },
    { "R8",   offsetof(struct user_regs_struct, r8),      1 },
    { "R9",   offsetof(struct user_regs_struct, r9),      1 },
    { "R10",  offsetof(struct user_regs_struct, r10),     1 },
    { "R11",  offsetof(struct user_regs_struct, r11),     1 },
    { "R12",  offsetof(struct user_regs_struct, r12),     1 },
    { "R13",  offsetof(struct user_regs_struct, r13),     1 },
    { "R14",  offsetof(struct user_regs_struct, r14),     1 },
    { "R15",  offsetof(struct user_regs_struct, r15),     1 },
    { "RBP",  offsetof(struct user_regs_struct, rbp),     1 },
    { "RSP",  offsetof(struct user_regs_struct, rsp),     1 },

    /* Special */
    { "RIP",     offsetof(struct user_regs_struct, rip),     1 },
    { "EFLAGS",  offsetof(struct user_regs_struct, eflags),  0 },
    { "orig_RAX",offsetof(struct user_regs_struct, orig_rax),1 },

    /* 段寄存器 */
    { "CS",  offsetof(struct user_regs_struct, cs),  0 },
    { "DS",  offsetof(struct user_regs_struct, ds),  0 },
    { "ES",  offsetof(struct user_regs_struct, es),  0 },
    { "FS",  offsetof(struct user_regs_struct, fs),  0 },
    { "GS",  offsetof(struct user_regs_struct, gs),  0 },
    { "SS",  offsetof(struct user_regs_struct, ss),  0 },
};

#define REG_MAP_COUNT  (sizeof(reg_map) / sizeof(reg_map[0]))

/* ── Helper: read uint64_t from user_regs_struct at offset ─────── */

static uint64_t ureg_read(const struct user_regs_struct *u, size_t off) {
    uint64_t v = 0;
    memcpy(&v, (const unsigned char *)u + off, sizeof(v));
    return v;
}

/* ── EFLAGS bit-name 分解 ──────────────────────────────────────── */

typedef struct {
    uint64_t    bit;
    const char *name;
} EflagsBit;

static const EflagsBit eflags_bits[] = {
    { 1ULL <<  0, "CF" },
    { 1ULL <<  2, "PF" },
    { 1ULL <<  4, "AF" },
    { 1ULL <<  6, "ZF" },
    { 1ULL <<  7, "SF" },
    { 1ULL <<  8, "TF" },
    { 1ULL <<  9, "IF" },
    { 1ULL << 10, "DF" },
    { 1ULL << 11, "OF" },
    { 1ULL << 14, "NT" },
    { 1ULL << 16, "RF" },
    { 1ULL << 17, "VM" },
    { 1ULL << 18, "AC" },
    { 1ULL << 19, "VIF"},
    { 1ULL << 20, "VIP"},
    { 1ULL << 21, "ID" },
};

static void eflags_to_str(uint64_t efl, char *buf, size_t sz) {
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(eflags_bits)/sizeof(eflags_bits[0]); i++) {
        if (efl & eflags_bits[i].bit) {
            if (pos > 0) pos += (size_t)snprintf(buf + pos, sz - pos, " ");
            pos += (size_t)snprintf(buf + pos, sz - pos, "%s",
                                    eflags_bits[i].name);
        }
    }
    if (pos == 0) {
        snprintf(buf, sz, "(none)");
    }
}

/* ── Public: init ───────────────────────────────────────────────── */

void reg_diff_init(RegDiffState *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
}

/* ── Public: snapshot ───────────────────────────────────────────── */

void reg_diff_snapshot(RegDiffState *state,
                       const struct user_regs_struct *regs) {
    if (!state || !regs) return;

    /* 前移: curr → prev */
    if (state->has_curr) {
        memcpy(&state->prev_regs, &state->curr_regs,
               sizeof(struct user_regs_struct));
        state->has_prev = 1;
    }

    /* 存入新 curr */
    memcpy(&state->curr_regs, regs, sizeof(struct user_regs_struct));
    state->has_curr = 1;
    state->step_count++;
}

/* ── Public: get result ─────────────────────────────────────────── */

int reg_diff_get_result(RegDiffState *state,
                        RegDiffResult *result,
                        uint64_t rip) {
    if (!state || !result) return -1;
    if (!state->has_prev || !state->has_curr) return -1;

    memset(result, 0, sizeof(*result));
    result->rip = rip;

    for (size_t i = 0; i < REG_MAP_COUNT; i++) {
        uint64_t old_val = ureg_read(&state->prev_regs, reg_map[i].offset);
        uint64_t new_val = ureg_read(&state->curr_regs, reg_map[i].offset);

        RegDiffEntry *e = &result->entries[result->entry_count];
        e->name         = reg_map[i].name;
        e->old_value    = old_val;
        e->new_value    = new_val;
        e->changed_mask = old_val ^ new_val;   /* XOR → 变化的 bit */
        e->changed      = (old_val != new_val) ? 1 : 0;
        result->entry_count++;

        if (e->changed) result->changed_count++;
    }

    return 0;
}

/* ── Public: quick change check by name ─────────────────────────── */

int reg_diff_reg_changed(RegDiffState *state, const char *name) {
    if (!state || !name || !state->has_prev || !state->has_curr)
        return -1;

    for (size_t i = 0; i < REG_MAP_COUNT; i++) {
        if (strcmp(reg_map[i].name, name) == 0) {
            uint64_t old_val = ureg_read(&state->prev_regs, reg_map[i].offset);
            uint64_t new_val = ureg_read(&state->curr_regs, reg_map[i].offset);
            return (old_val != new_val) ? 1 : 0;
        }
    }
    return -1;  /* unknown register name */
}

/* ── Public: quick change check by offset ───────────────────────── */

int reg_diff_offset_changed(RegDiffState *state, size_t offset) {
    if (!state || !state->has_prev || !state->has_curr) return -1;

    uint64_t old_val = ureg_read(&state->prev_regs, offset);
    uint64_t new_val = ureg_read(&state->curr_regs, offset);
    return (old_val != new_val) ? 1 : 0;
}

/* ── Public: format to popup text ───────────────────────────────── */

const char *reg_diff_format(const RegDiffResult *result,
                            int step_count,
                            char *out, size_t out_sz) {
    if (!result || !out || out_sz == 0) return "";

    int pos = 0;

    pos += snprintf(out + pos, out_sz - (size_t)pos,
        "=== Register Diff (step %d, RIP=0x%llx) ===\n\n",
        step_count, (unsigned long long)result->rip);

    if (result->changed_count == 0) {
        pos += snprintf(out + pos, out_sz - (size_t)pos,
            "  No register changes since last snapshot.\n");
    } else {
        pos += snprintf(out + pos, out_sz - (size_t)pos,
            "  %d register%s changed:\n\n",
            result->changed_count,
            result->changed_count == 1 ? "" : "s");

        /* ── Changed registers first ── */
        int changed_shown = 0;
        for (int i = 0; i < result->entry_count; i++) {
            const RegDiffEntry *e = &result->entries[i];
            if (!e->changed) continue;

            if (strcmp(e->name, "EFLAGS") == 0) {
                /* EFLAGS: 分解显示变化 */
                char old_flags[128], new_flags[128];
                eflags_to_str(e->old_value, old_flags, sizeof(old_flags));
                eflags_to_str(e->new_value, new_flags, sizeof(new_flags));

                pos += snprintf(out + pos, out_sz - (size_t)pos,
                    "  [+] %-6s  0x%llx → 0x%llx\n"
                    "       %*s  [ %s ] → [ %s ]\n",
                    e->name,
                    (unsigned long long)e->old_value,
                    (unsigned long long)e->new_value,
                    12, "", old_flags, new_flags);
            } else {
                /* GPR / 段寄存器: 显示值变化 */
                int64_t delta = (int64_t)(e->new_value - e->old_value);
                char delta_str[32] = "";
                if (delta != 0 && (uint64_t)(delta > 0 ? delta : -delta) < 0x10000) {
                    snprintf(delta_str, sizeof(delta_str),
                             "  (%+ld)", (long)delta);
                }

                /* 栈操作检测 */
                const char *hint = "";
                if (strcmp(e->name, "RSP") == 0) {
                    if (delta == -8)      hint = "  [push]";
                    else if (delta == 8)  hint = "  [pop]";
                    else if (delta < -8)  hint = "  [stack growth]";
                } else if (strcmp(e->name, "RIP") == 0) {
                    if (delta > 0 && delta < 16) hint = "  [sequential]";
                }

                pos += snprintf(out + pos, out_sz - (size_t)pos,
                    "  [+] %-6s  0x%llx → 0x%llx%s%s\n",
                    e->name,
                    (unsigned long long)e->old_value,
                    (unsigned long long)e->new_value,
                    delta_str, hint);
            }
            changed_shown++;
        }
    }

    /* ── Unchanged summary ── */
    int unchanged = result->entry_count - result->changed_count;
    if (unchanged > 0) {
        pos += snprintf(out + pos, out_sz - (size_t)pos,
            "\n  ── Unchanged (%d registers) ──\n  ", unchanged);

        int col = 0;
        for (int i = 0; i < result->entry_count; i++) {
            if (!result->entries[i].changed) {
                pos += snprintf(out + pos, out_sz - (size_t)pos,
                               "%s%s", col > 0 ? "  " : "",
                               result->entries[i].name);
                col++;
                if (col >= 4) {
                    pos += snprintf(out + pos, out_sz - (size_t)pos, "\n  ");
                    col = 0;
                }
            }
        }
    }

    pos += snprintf(out + pos, out_sz - (size_t)pos,
        "\n\n  [F7]Step  [F5]Continue  [Esc]Close");

    return out;
}

/*
 * reg_diff_render() — PanelData 渲染器
 *
 * 该函数依赖 elf-tui 的 elf_parser.h (PanelData, fields_add)。
 * 实现放在这里会引入 elf_parser.h 依赖, 破坏纯计算引擎的独立性。
 *
 * 集成时在 btn_regdiff_action() 中调用 reg_diff_get_result()
 * 获取数据, 然后自行用 fields_add() 格式化。或者直接用
 * reg_diff_format() 获得弹窗文本。
 *
 * 参考实现见本文件末尾注释。
 */
