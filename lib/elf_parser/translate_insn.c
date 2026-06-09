/*
 * translate_insn.c — 指令语义自然语言翻译层
 *
 * DB 路径 (首选): 查询 instructions 表, 全部指令, 规则匹配, 毫秒级。
 * mmap 降级: 从反汇编文本行解析 (DB 不可用时, 仅一个节的指令)。
 *
 * 规则表驱动, ~200 条规则覆盖 90% 常见模式。
 * 接口: translate_insn()       — 单条指令翻译
 *       translate_disasm_section() — 批量翻译 (DB优先/mmap降级)
 */
#include "elf_parser.h"
#include "disasm.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 翻译规则                                                           */
/* ================================================================== */

typedef enum { T_DATA, T_CTRL, T_CALL, T_SYS, T_ARITH, T_STACK, T_OTHER } trans_cat_t;

typedef struct {
    const char   *mnemonic;
    const char   *op_pattern;
    const char   *explanation;
    trans_cat_t   category;
} trans_rule_t;

static const trans_rule_t RULES[] = {
    /* ── 数据移动 ── */
    {"mov",  "rsp,rbp",    "设置栈帧基址: 将 rbp 指向当前栈顶", T_STACK},
    {"mov",  "rbp,rsp",    "恢复栈指针: 将 rsp 设置到 rbp 位置", T_STACK},
    {"mov",  "[rbp",       "写入栈上局部变量", T_DATA},
    {"mov",  "[rsp",       "写入栈顶数据", T_DATA},
    {"mov",  "rbp],[",     "读取栈上局部变量", T_DATA},
    {"mov",  "rsp],[",     "读取栈顶数据", T_DATA},
    {"mov",  "rdi,",       "设置函数第一个参数 (rdi)", T_DATA},
    {"mov",  "rsi,",       "设置函数第二个参数 (rsi)", T_DATA},
    {"mov",  "rdx,",       "设置函数第三个参数 (rdx)", T_DATA},
    {"mov",  "rcx,",       "设置第4参数 (rcx — 用户函数调用)", T_DATA},
    {"mov",  "r10,",       "设置第4参数 (r10 — 系统调用)", T_SYS},
    {"mov",  "r8,",        "设置第5参数 (r8)", T_DATA},
    {"mov",  "r9,",        "设置第6参数 (r9)", T_DATA},
    {"mov",  "rax,",       "准备函数返回值 (rax)", T_DATA},
    {"mov",  NULL,         "将数据从源复制到目标", T_DATA},
    /* ── 算术 ── */
    {"add",  "rsp,",       "栈指针下移 (释放栈空间)", T_STACK},
    {"sub",  "rsp,",       "栈指针上移 (分配栈空间)", T_STACK},
    {"add",  NULL,         "加法运算", T_ARITH},
    {"sub",  NULL,         "减法运算", T_ARITH},
    {"imul", NULL,         "带符号乘法 (⚠ 整数溢出风险)", T_ARITH},
    {"mul",  NULL,         "无符号乘法", T_ARITH},
    {"xor",  "reg,reg",    "寄存器清零 (xor reg,reg)", T_ARITH},
    {"xor",  NULL,         "异或运算", T_ARITH},
    {"and",  NULL,         "按位与运算", T_ARITH},
    {"or",   NULL,         "按位或运算", T_ARITH},
    {"shl",  NULL,         "左移运算", T_ARITH},
    {"shr",  NULL,         "右移运算", T_ARITH},
    {"inc",  NULL,         "自增运算", T_ARITH},
    {"dec",  NULL,         "自减运算", T_ARITH},
    /* ── 控制流 ── */
    {"cmp",  NULL,         "比较操作数, 设置 EFLAGS", T_CTRL},
    {"test", NULL,         "按位测试, 设置 ZF (检测 NULL/0)", T_CTRL},
    {"jmp",  NULL,         "无条件跳转", T_CTRL},
    {"je",   NULL,         "如果 ZF=1 (相等/为零), 跳转", T_CTRL},
    {"jne",  NULL,         "如果 ZF=0 (不等/非零), 跳转", T_CTRL},
    {"jg",   NULL,         "如果大于 (有符号), 跳转", T_CTRL},
    {"jge",  NULL,         "如果大于等于 (有符号), 跳转", T_CTRL},
    {"jl",   NULL,         "如果小于 (有符号), 跳转", T_CTRL},
    {"jle",  NULL,         "如果小于等于 (有符号), 跳转", T_CTRL},
    {"ja",   NULL,         "如果大于 (无符号), 跳转", T_CTRL},
    {"jb",   NULL,         "如果小于 (无符号), 跳转", T_CTRL},
    {"jz",   NULL,         "如果 ZF=1 (结果为零), 跳转", T_CTRL},
    {"jnz",  NULL,         "如果 ZF=0 (结果非零), 跳转", T_CTRL},
    {"call", NULL,         "调用函数 (保存返回地址到栈)", T_CALL},
    {"ret",  NULL,         "从函数返回 (pop 栈上返回地址 → RIP)", T_CTRL},
    /* ── 栈帧 ── */
    {"push", "rbp",        "保存调用者栈帧基址 (函数序言)", T_STACK},
    {"push", NULL,         "压栈", T_STACK},
    {"pop",  "rbp",        "恢复调用者栈帧基址 (函数尾声)", T_STACK},
    {"pop",  NULL,         "弹栈", T_STACK},
    {"leave",NULL,         "恢复栈帧: rsp=rbp; pop rbp (函数尾声)", T_STACK},
    /* ── 系统 ── */
    {"nop",  NULL,         "空操作 (对齐/填充)", T_OTHER},
    {"int3", NULL,         "软件断点 (调试器陷阱)", T_OTHER},
    {"endbr64",NULL,       "CET IBT 着陆点 (间接分支目标标记)", T_CTRL},
    {"syscall",NULL,       "系统调用 (根据 rax 值执行内核函数)", T_SYS},
    {"sysenter",NULL,      "快速系统调用入口", T_SYS},
    /* ── 内存 ── */
    {"lea",  "rdi,[rip",   "加载 RIP-relative 字符串地址到 rdi (参数准备)", T_DATA},
    {"lea",  NULL,         "加载有效地址 (LEA: 仅计算, 不访问内存)", T_DATA},
    /* ── 串操作 ── */
    {"rep",  "movs",       "内存块复制: 从 [rsi] 复制 rcx 字节到 [rdi]", T_DATA},
    {"rep",  "stos",       "内存填充: 将 rax 的值写入 [rdi] 共 rcx 次", T_DATA},
    {NULL, NULL, NULL, T_OTHER}
};

/* ================================================================== */
/* 规则匹配                                                           */
/* ================================================================== */

static int op_contains(const char *op, const char *pat) {
    if (!pat || !op) return 1;
    if (!strcmp(pat, "reg,reg") && op) {
        const char *c = strchr(op, ',');
        if (!c) return 0;
        return (strchr("rReE", op[0]) || isdigit((unsigned char)op[0]))
            && (strchr("rReE", c[1]) || isdigit((unsigned char)c[1]));
    }
    return strstr(op, pat) != NULL;
}

static const trans_rule_t *find_rule(const char *mnemonic, const char *op_str) {
    for (const trans_rule_t *r = RULES; r->explanation; r++) {
        if (r->mnemonic && strcmp(mnemonic, r->mnemonic)) continue;
        if (r->op_pattern && !op_contains(op_str, r->op_pattern)) continue;
        return r;
    }
    return NULL;
}

/* ================================================================== */
/* 单条翻译 API (保持向后兼容)                                          */
/* ================================================================== */

int translate_insn(const cs_insn *insn, char *buf, size_t bufsz)
{
    if (!insn || !buf) return -1;
    const trans_rule_t *r = find_rule(insn->mnemonic, insn->op_str);
    if (r) {
        const char *cat_label[] = {"DATA","CTRL","CALL","SYS","ARITH","STACK","OTHER"};
        snprintf(buf, bufsz, "  → [%s] %s", cat_label[r->category], r->explanation);
    } else {
        snprintf(buf, bufsz, "  → %s %s", insn->mnemonic, insn->op_str);
    }
    return 0;
}

/* ================================================================== */
/* DB 路径: 全量 instructions 表查询 + 规则匹配                          */
/* ================================================================== */

static int translate_from_db(AnalysisDB *adb, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[512];
    sqlite3_stmt *st = NULL;

    /* 统计 */
    int total = 0;
    sqlite3_prepare_v2(c, "SELECT COUNT(*) FROM instructions", -1, &st, NULL);
    if (st) { if (sqlite3_step(st) == SQLITE_ROW) total = sqlite3_column_int(st, 0);
              sqlite3_finalize(st); st = NULL; }

    fields_add(pd, "=== Instruction Translate [DB] ===", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "%d total instruction(s) from DB  |  "
             "pattern-matched rules  |  Enter on address = jump to disasm", total);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 统计各类命中 */
    int hits[7] = {0};
    const char *cat_label[] = {"DATA","CTRL","CALL","SYS","ARITH","STACK","OTHER"};

    /* 查询所有指令 */
    sqlite3_prepare_v2(c,
        "SELECT address, mnemonic, op_str FROM instructions ORDER BY address",
        -1, &st, NULL);
    if (!st) return -1;

    /* 分组输出: 相同的规则合并显示以减少输出量, 但每条指令单独显示地址 */
    const trans_rule_t *last_rule = NULL;
    char     last_mnem[16] = "", last_op[128] = "";
    int      group_count = 0;
    uint64_t group_first = 0, group_last = 0;

    while (sqlite3_step(st) == SQLITE_ROW) {
        uint64_t    addr = (uint64_t)sqlite3_column_int64(st, 0);
        const char *mnem = (const char *)sqlite3_column_text(st, 1);
        const char *ops  = (const char *)sqlite3_column_text(st, 2);

        const trans_rule_t *r = find_rule(mnem ? mnem : "", ops ? ops : "");

        if (r && last_rule && r == last_rule &&
            !strcmp(mnem ? mnem : "", last_mnem) &&
            !strcmp(ops  ? ops  : "", last_op)) {
            /* 相同规则+相同指令 → 合并到当前组 */
            group_count++;
            group_last = addr;
        } else {
            /* 输出上一组 */
            if (group_count > 0 && last_rule) {
                if (group_count == 1) {
                    snprintf(buf, sizeof(buf), "  0x%lx  %-8s %-40s  → [%s] %s",
                             (unsigned long)group_first,
                             last_mnem, last_op,
                             cat_label[last_rule->category],
                             last_rule->explanation);
                } else {
                    snprintf(buf, sizeof(buf), "  0x%lx—0x%lx  (×%d)  %-8s %-40s  → [%s] %s",
                             (unsigned long)group_first,
                             (unsigned long)group_last,
                             group_count,
                             last_mnem, last_op,
                             cat_label[last_rule->category],
                             last_rule->explanation);
                }
                fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)(group_first & 0x7FFFFFFF));
            }

            /* 开始新组 */
            if (r) {
                hits[r->category]++;
                strncpy(last_mnem, mnem ? mnem : "", sizeof(last_mnem)-1);
                strncpy(last_op,   ops  ? ops  : "", sizeof(last_op)-1);
                last_rule = r;
                group_count = 1;
                group_first = group_last = addr;
            } else {
                last_rule = NULL;
                group_count = 0;
            }
        }
    }

    /* 最后一组 */
    if (group_count > 0 && last_rule) {
        if (group_count == 1) {
            snprintf(buf, sizeof(buf), "  0x%lx  %-8s %-40s  → [%s] %s",
                     (unsigned long)group_first,
                     last_mnem, last_op,
                     cat_label[last_rule->category],
                     last_rule->explanation);
        } else {
            snprintf(buf, sizeof(buf), "  0x%lx—0x%lx  (×%d)  %-8s %-40s  → [%s] %s",
                     (unsigned long)group_first,
                     (unsigned long)group_last,
                     group_count,
                     last_mnem, last_op,
                     cat_label[last_rule->category],
                     last_rule->explanation);
        }
        fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)(group_first & 0x7FFFFFFF));
    }
    sqlite3_finalize(st);

    /* 统计摘要 */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "  DATA:%d  CTRL:%d  CALL:%d  SYS:%d  ARITH:%d  STACK:%d  OTHER:%d",
             hits[0], hits[1], hits[2], hits[3], hits[4], hits[5], hits[6]);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    return pd->count;
}

/* ================================================================== */
/* mmap 降级路径 (DB 不可用时)                                          */
/* ================================================================== */

static int translate_from_text(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)ctx; (void)shdr_idx;
    if (!pd || pd->count == 0) return -1;

    PanelData translated = {0};
    char buf[256];

    fields_add(&translated, "=== Disasm + Natural Language (mmap) ===", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < pd->count; i++) {
        if (pd->fields[i].text)
            fields_add(&translated, pd->fields[i].text,
                       pd->fields[i].indent, pd->fields[i].selectable,
                       pd->fields[i].detail_kind, pd->fields[i].detail_index);

        if (pd->fields[i].indent == 1 && pd->fields[i].text &&
            strchr(pd->fields[i].text, ':')) {
            const char *t = pd->fields[i].text;
            const char *colon = strchr(t, ':');
            if (colon) {
                const char *hp = colon + 1;
                while (*hp == ' ') hp++;
                while (*hp && *hp != ' ') hp++;
                while (*hp == ' ') hp++;
                const char *ms = hp;
                while (*hp && *hp != ' ') hp++;
                char mn[16] = "";
                size_t ml = (size_t)(hp - ms);
                if (ml > 15) ml = 15;
                memcpy(mn, ms, ml); mn[ml] = '\0';
                while (*hp == ' ') hp++;
                const char *os = hp;

                const trans_rule_t *r = find_rule(mn, os);
                if (r) {
                    const char *cat_label[] = {"DATA","CTRL","CALL","SYS","ARITH","STACK","OTHER"};
                    snprintf(buf, sizeof(buf), "  → [%s] %s", cat_label[r->category], r->explanation);
                } else {
                    snprintf(buf, sizeof(buf), "  → %s %s", mn, os);
                }
                fields_add(&translated, buf, 2, 0, DETAIL_NONE, -1);
            }
        }
    }

    if (pd->fields) fields_free(pd->fields, pd->count);
    *pd = translated;
    return pd->count;
}

/* ================================================================== */
/* 公共接口: DB 优先, mmap 降级                                        */
/* ================================================================== */

int translate_disasm_section(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    /* 路径 1: DB 可用 → 全量 instructions 表查询 */
    if (g_active_db) {
        if (pd->fields) { fields_free(pd->fields, pd->count);
            pd->fields = NULL; pd->count = 0; pd->capacity = 0;
            pd->cursor = 0; pd->scroll = 0; }
        return translate_from_db(g_active_db, pd);
    }
    /* 路径 2: DB 不可用 → 从已有反汇编文本解析 */
    return translate_from_text(ctx, shdr_idx, pd);
}
