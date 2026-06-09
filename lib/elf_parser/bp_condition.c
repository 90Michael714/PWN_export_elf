/*
 * bp_condition.c — 条件断点引擎 (依赖 expr_eval.c, 零其他依赖)
 *
 * 用法:
 *   1. 解析条件表达式
 *   2. 断点命中时, 用当前寄存器值求值条件
 *   3. 条件为真 → 停止; 条件为假 → 自动继续
 *
 * 条件语法:
 *   "$rdi == 0x7f..."       寄存器值等于某个地址
 *   "($rsp+0x8) > 0x1000"   栈上值大于阈值
 *   "($rax & 0xff) == 0"    低字节为零
 *   "$rcx < 0x100 && $rdi > 0"  复合条件 (&& 支持)
 *
 * API:
 *   int  bp_condition_parse(const char *cond_str, bp_cond_t *cond);
 *   int  bp_condition_eval(const bp_cond_t *cond, const uint64_t regs[]);
 *   void bp_condition_free(bp_cond_t *cond);
 *   int  bp_condition_hit(bp_cond_t *bp, const uint64_t regs[], bp_hit_t *hit);
 *
 * 数据结构:
 *   bp_cond_t  — 解析后的条件 (支持最多 4 个子条件, AND 逻辑)
 *   bp_hit_t   — 命中记录 (计数, 上次值等)
 *
 * 依赖: expr_eval.c (表达式求值引擎)
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/* ================================================================== */
/* 外部依赖: expr_eval.c 的声明                                       */
/* ================================================================== */

/* (这些声明应与 expr_eval.c 保持一致, 编译时一起链接) */
extern int64_t expr_eval(const char *expr, const uint64_t regs[], int *err);
extern int     expr_eval_condition(const char *cond, const uint64_t regs[], int *err);
extern int     expr_validate(const char *expr);
extern const char *expr_error_str(int err);

/* 寄存器索引 — 来自 expr_eval.c */
enum {
    R_RAX=0, R_RBX, R_RCX, R_RDX, R_RSI, R_RDI, R_RBP, R_RSP,
    R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_RIP, R_EFLAGS, R_CS, R_DS, R_ES, R_FS, R_GS, R_SS, R_COUNT
};

/* ================================================================== */
/* 条件断点数据结构                                                     */
/* ================================================================== */

#define BP_MAX_SUB_CONDITIONS 4

typedef struct {
    char    *expr_text;       /* 原始表达式文本 */
    int      is_active;       /* 是否启用 */
    uint64_t hit_count;       /* 命中次数 */
    uint64_t last_values[BP_MAX_SUB_CONDITIONS]; /* 上次命中时的值 */
} bp_subcond_t;

typedef struct {
    bp_subcond_t subs[BP_MAX_SUB_CONDITIONS];
    int          sub_count;   /* 子条件数量 (AND 连接) */
    int          total_hits;  /* 所有命中次数 */
    char        *raw_text;    /* 原始条件字符串 */
} bp_cond_t;

typedef struct {
    uint64_t hit_count;       /* 累计命中 */
    uint64_t last_hit_addr;   /* 上次命中地址 */
    uint64_t last_hit_time;   /* (占位) */
} bp_hit_t;

/* ================================================================== */
/* 解析: "A && B && C" → sub_count 个子条件                           */
/* ================================================================== */

/**
 * 解析条件字符串为 bp_cond_t。
 * 支持 && 连接多个子条件。
 * 返回: 0=成功, -1=语法错误
 */
int bp_condition_parse(const char *cond_str, bp_cond_t *cond)
{
    if (!cond_str || !cond) return -1;
    memset(cond, 0, sizeof(*cond));

    /* 手动复制 (避免 strdup 需要 _GNU_SOURCE) */
    size_t clen = strlen(cond_str);
    cond->raw_text = malloc(clen + 1);
    if (!cond->raw_text) return -1;
    memcpy(cond->raw_text, cond_str, clen + 1);

    /* 按 "&&" 分割 */
    char *copy = malloc(clen + 1);
    if (!copy) { free(cond->raw_text); cond->raw_text = NULL; return -1; }
    memcpy(copy, cond_str, clen + 1);

    char *save = copy;
    while (save && *save && cond->sub_count < BP_MAX_SUB_CONDITIONS) {
        /* 找到下一个 && */
        char *and_pos = strstr(save, "&&");
        if (and_pos) *and_pos = '\0';

        /* 去除首尾空格 */
        while (*save == ' ') save++;
        char *end = save + strlen(save) - 1;
        while (end > save && *end == ' ') *end-- = '\0';

        if (*save) {
            /* 校验语法 */
            int err;
            uint64_t dummy[R_COUNT];
            memset(dummy, 0, sizeof(dummy));
            expr_eval_condition(save, dummy, &err);
            if (err != 0) {
                /* 语法错误 — 清理并返回 */
                for (int i = 0; i < cond->sub_count; i++)
                    free(cond->subs[i].expr_text);
                free(copy);
                free(cond->raw_text);
                cond->raw_text = NULL;
                return -1;
            }

            bp_subcond_t *sc = &cond->subs[cond->sub_count];
            size_t slen = strlen(save);
            sc->expr_text = malloc(slen + 1);
            if (sc->expr_text) memcpy(sc->expr_text, save, slen + 1);
            sc->is_active = 1;
            sc->hit_count = 0;
            memset(sc->last_values, 0, sizeof(sc->last_values));
            cond->sub_count++;
        }

        save = and_pos ? and_pos + 2 : NULL;
    }

    free(copy);
    return 0;
}

/** 求值所有子条件, 返回 true 当且仅当所有条件都满足。 */
int bp_condition_eval(const bp_cond_t *cond, const uint64_t regs[])
{
    if (!cond || cond->sub_count == 0 || !regs) return 1; /* 无条件 = 总是命中 */

    for (int i = 0; i < cond->sub_count; i++) {
        if (!cond->subs[i].is_active) continue;

        int err = 0;
        int result = expr_eval_condition(cond->subs[i].expr_text, regs, &err);
        if (err != 0) return 0; /* 求值失败 = 不命中 */

        if (!result) return 0; /* 任一条件不满 → 不命中 */
    }
    return 1; /* 所有条件满足 */
}

/** 记录一次命中 (更新统计) */
int bp_condition_hit(bp_cond_t *cond, const uint64_t regs[], bp_hit_t *hit)
{
    if (!cond || !regs) return 0;

    int should_stop = bp_condition_eval(cond, regs);
    cond->total_hits++;

    if (!should_stop) return 0;

    /* 更新统计 */
    for (int i = 0; i < cond->sub_count; i++) {
        cond->subs[i].hit_count++;
        if (cond->subs[i].expr_text) {
            int err;
            cond->subs[i].last_values[i] =
                (uint64_t)expr_eval(cond->subs[i].expr_text, regs, &err);
        }
    }

    if (hit) {
        hit->hit_count++;
        hit->last_hit_addr = regs[R_RIP];
    }

    return 1; /* 命中, 应停止 */
}

/** 释放条件断点 */
void bp_condition_free(bp_cond_t *cond)
{
    if (!cond) return;
    for (int i = 0; i < cond->sub_count; i++)
        free(cond->subs[i].expr_text);
    free(cond->raw_text);
    memset(cond, 0, sizeof(*cond));
}

/** 格式化条件描述 */
int bp_condition_format(const bp_cond_t *cond, char *buf, size_t bufsz)
{
    if (!cond || !buf) return -1;
    int pos = 0;
    for (int i = 0; i < cond->sub_count; i++) {
        if (i > 0) pos += snprintf(buf + pos, bufsz - (size_t)pos, " && ");
        pos += snprintf(buf + pos, bufsz - (size_t)pos, "%s",
                        cond->subs[i].expr_text ? cond->subs[i].expr_text : "?");
    }
    pos += snprintf(buf + pos, bufsz - (size_t)pos,
                    "  (hits: %lu)", (unsigned long)cond->total_hits);
    return pos;
}
