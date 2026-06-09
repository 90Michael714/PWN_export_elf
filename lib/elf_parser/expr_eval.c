/*
 * expr_eval.c — 表达式求值引擎 (C 实现, 零依赖)
 *
 * 语法:
 *   expr   = or_expr
 *   or_expr  = xor_expr ('|' xor_expr)*
 *   xor_expr = and_expr ('^' and_expr)*
 *   and_expr = shift_expr ('&' shift_expr)*
 *   shift_expr = add_expr (('<<'|'>>') add_expr)*
 *   add_expr = mul_expr (('+'|'-') mul_expr)*
 *   mul_expr = unary (('*'|'/'|'%') unary)*
 *   unary   = ('+'|'-'|'~'|'!')? primary
 *   primary = NUMBER | '$' REGISTER | '(' expr ')' | '*' '(' expr ')' | REGISTER '[' expr ']'
 *
 * 寄存器: $rax $eax $ax $al ... $r15 $r15d $r15w $r15b
 *          $rip $rsp $rbp $rflags $cs $ds $es $fs $gs $ss
 * 解引用: $rax[8] → *(uint64_t*)(rax+8)
 *         *($rsp+0x20) → *(uint64_t*)(rsp+0x20)
 *
 * API:
 *   int64_t expr_eval(const char *expr, const uint64_t regs[], int *err);
 *   int     expr_validate(const char *expr);   // 只校验, 不求值
 *
 * 依赖: 无 (纯 C99, 不依赖 elf-tui 的任何头文件)
 */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>

/* ================================================================== */
/* 寄存器定义                                                         */
/* ================================================================== */

/* 寄存器索引 (与 x86-64 struct user_regs_struct 对齐) */
enum {
    R_RAX=0, R_RBX, R_RCX, R_RDX, R_RSI, R_RDI, R_RBP, R_RSP,
    R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_RIP, R_EFLAGS,
    R_CS, R_DS, R_ES, R_FS, R_GS, R_SS,
    R_COUNT
};

typedef struct {
    const char *name64;   /* "rax" */
    const char *name32;   /* "eax" */
    const char *name16;   /* "ax"  */
    const char *name8;    /* "al"  */
    const char *name8h;   /* "ah"  (仅 rax..rbx,rcx,rdx) */
} reg_info_t;

static const reg_info_t REG_TABLE[] = {
    {"rax","eax","ax","al","ah"},   /* R_RAX */
    {"rbx","ebx","bx","bl","bh"},   /* R_RBX */
    {"rcx","ecx","cx","cl","ch"},   /* R_RCX */
    {"rdx","edx","dx","dl","dh"},   /* R_RDX */
    {"rsi","esi","si","sil",NULL},  /* R_RSI */
    {"rdi","edi","di","dil",NULL},  /* R_RDI */
    {"rbp","ebp","bp","bpl",NULL},  /* R_RBP */
    {"rsp","esp","sp","spl",NULL},  /* R_RSP */
    {"r8", "r8d","r8w","r8b",NULL}, /* R_R8 */
    {"r9", "r9d","r9w","r9b",NULL},
    {"r10","r10d","r10w","r10b",NULL},
    {"r11","r11d","r11w","r11b",NULL},
    {"r12","r12d","r12w","r12b",NULL},
    {"r13","r13d","r13w","r13b",NULL},
    {"r14","r14d","r14w","r14b",NULL},
    {"r15","r15d","r15w","r15b",NULL},
    {"rip","eip",NULL,NULL,NULL},
    {"eflags","flags",NULL,NULL,NULL},
    {"cs",NULL,NULL,NULL,NULL},
    {"ds",NULL,NULL,NULL,NULL},
    {"es",NULL,NULL,NULL,NULL},
    {"fs",NULL,NULL,NULL,NULL},
    {"gs",NULL,NULL,NULL,NULL},
    {"ss",NULL,NULL,NULL,NULL},
};

/**
 * 按寄存器名查找索引。
 * @param name  寄存器名 (如 "rax", "eax", "r15d")
 * @param sz    输出: 大小 (1/2/4/8)
 * @param mask  输出: 位掩码 (用于截断)
 * @return      寄存器索引, -1 找不到
 */
static int find_register(const char *name, int *sz, uint64_t *mask)
{
    if (!name || name[0] == '\0') return -1;

    for (int i = 0; i < R_COUNT; i++) {
        const reg_info_t *r = &REG_TABLE[i];
        if (r->name64 && !strcmp(name, r->name64)) { *sz=8; *mask=UINT64_MAX; return i; }
        if (r->name32 && !strcmp(name, r->name32)) { *sz=4; *mask=0xFFFFFFFFULL; return i; }
        if (r->name16 && !strcmp(name, r->name16)) { *sz=2; *mask=0xFFFFULL; return i; }
        if (r->name8  && !strcmp(name, r->name8))  { *sz=1; *mask=0xFFULL; return i; }
        if (r->name8h && !strcmp(name, r->name8h)) { *sz=1; *mask=0xFF00ULL; return i; }
    }
    return -1;
}

/* ================================================================== */
/* 解析器状态                                                         */
/* ================================================================== */

typedef struct {
    const char *p;          /* 当前位置 */
    const uint64_t *regs;   /* 寄存器数组 [R_COUNT] */
    int          err;        /* 0=OK, 1=语法错误, 2=除零, 3=溢出 */
} parser_t;

#define ERR_NONE    0
#define ERR_SYNTAX  1
#define ERR_DIVZERO 2
#define ERR_OVERFLOW 3

static void skip_space(parser_t *ps) {
    while (*ps->p == ' ' || *ps->p == '\t') ps->p++;
}

/* 前向声明 */
static int64_t parse_expr(parser_t *ps);

/* ── 数字 ── */
static int64_t parse_number(parser_t *ps)
{
    int base = 10;
    if (*ps->p == '0' && (ps->p[1] == 'x' || ps->p[1] == 'X')) {
        base = 16; ps->p += 2;
    } else if (*ps->p == '0' && isdigit((unsigned char)ps->p[1])) {
        base = 8; ps->p++;
    }
    const char *start = ps->p;
    while (isxdigit((unsigned char)*ps->p) ||
           (base != 16 && *ps->p >= '0' && *ps->p <= (base == 10 ? '9' : '7')))
        ps->p++;

    if (ps->p == start) { ps->err = ERR_SYNTAX; return 0; }
    return (int64_t)strtoll(start, NULL, base);
}

/* ── 寄存器 ── */
static int64_t parse_register(parser_t *ps)
{
    if (*ps->p != '$') { ps->err = ERR_SYNTAX; return 0; }
    ps->p++; /* 跳过 $ */

    const char *start = ps->p;
    while (isalnum((unsigned char)*ps->p)) ps->p++;
    size_t len = (size_t)(ps->p - start);

    char name[16];
    if (len >= sizeof(name)) { ps->err = ERR_SYNTAX; return 0; }
    memcpy(name, start, len);
    name[len] = '\0';

    int sz; uint64_t mask;
    int idx = find_register(name, &sz, &mask);
    if (idx < 0) { ps->err = ERR_SYNTAX; return 0; }

    if (!ps->regs) { ps->err = ERR_SYNTAX; return 0; } /* 没有寄存器上下文 */

    uint64_t val = ps->regs[idx];
    if (sz == 1 && mask == 0xFF00ULL) val = (val >> 8) & 0xFF; /* ah/bh/ch/dh */
    else val &= mask;

    /* 解引用: $rax[offset] → *(uint64_t*)(rax+offset) */
    skip_space(ps);
    if (*ps->p == '[') {
        ps->p++;
        skip_space(ps);
        int64_t off = parse_expr(ps); /* 偏移量 */
        skip_space(ps);
        if (*ps->p != ']') { ps->err = ERR_SYNTAX; return 0; }
        ps->p++;

        uint64_t addr = (uint64_t)((int64_t)val + off);
        /* 注意: 实际解引用需要 debug_readmem, 这里只返回地址 */
        /* 调用者通过检测 *ps->p 后续是否有 '[' 来判断是否需要解引用 */
        /* 简化: 返回地址值 (调用者用指针追踪) */
        return (int64_t)addr;
    }

    return (int64_t)val;
}

/* ── 内存解引用 ── */
static int64_t parse_deref(parser_t *ps)
{
    ps->p++; /* 跳过 * */
    skip_space(ps);
    if (*ps->p != '(') { ps->err = ERR_SYNTAX; return 0; }
    ps->p++;
    skip_space(ps);
    int64_t addr = parse_expr(ps);
    skip_space(ps);
    if (*ps->p != ')') { ps->err = ERR_SYNTAX; return 0; }
    ps->p++;

    /* 实际解引用: 读取 *(uint64_t*)addr */
    /* 这里只能返回地址, 真正的内存读取需要 debug_readmem */
    return addr;
}

/* ── primary ── */
static int64_t parse_primary(parser_t *ps)
{
    skip_space(ps);

    if (*ps->p == '(') {
        ps->p++;
        int64_t v = parse_expr(ps);
        skip_space(ps);
        if (*ps->p != ')') { ps->err = ERR_SYNTAX; return 0; }
        ps->p++;
        return v;
    }

    if (*ps->p == '*') {
        return parse_deref(ps);
    }

    if (*ps->p == '$') {
        return parse_register(ps);
    }

    if (isdigit((unsigned char)*ps->p) ||
        (*ps->p == '0' && (ps->p[1] == 'x' || ps->p[1] == 'X'))) {
        return parse_number(ps);
    }

    ps->err = ERR_SYNTAX;
    return 0;
}

/* ── unary ── */
static int64_t parse_unary(parser_t *ps)
{
    skip_space(ps);
    if (*ps->p == '+') { ps->p++; return parse_unary(ps); }
    if (*ps->p == '-') { ps->p++; return -parse_unary(ps); }
    if (*ps->p == '~') { ps->p++; return ~parse_unary(ps); }
    if (*ps->p == '!') { ps->p++; return !parse_unary(ps) ? 1 : 0; }
    return parse_primary(ps);
}

/* ── 各优先级层 ── */
static int64_t parse_mul(parser_t *ps) {
    int64_t v = parse_unary(ps);
    while (!ps->err) {
        skip_space(ps);
        if      (*ps->p == '*') { ps->p++; v *= parse_unary(ps); }
        else if (*ps->p == '/') {
            ps->p++; int64_t d = parse_unary(ps);
            if (d == 0) { ps->err = ERR_DIVZERO; return 0; }
            v /= d;
        }
        else if (*ps->p == '%') {
            ps->p++; int64_t d = parse_unary(ps);
            if (d == 0) { ps->err = ERR_DIVZERO; return 0; }
            v %= d;
        }
        else break;
    }
    return v;
}

static int64_t parse_add(parser_t *ps) {
    int64_t v = parse_mul(ps);
    while (!ps->err) {
        skip_space(ps);
        if      (*ps->p == '+') { ps->p++; v += parse_mul(ps); }
        else if (*ps->p == '-') { ps->p++; v -= parse_mul(ps); }
        else break;
    }
    return v;
}

static int64_t parse_shift(parser_t *ps) {
    int64_t v = parse_add(ps);
    while (!ps->err) {
        skip_space(ps);
        if      (ps->p[0]=='<' && ps->p[1]=='<') { ps->p+=2; v <<= parse_add(ps); }
        else if (ps->p[0]=='>' && ps->p[1]=='>') { ps->p+=2; v >>= parse_add(ps); }
        else break;
    }
    return v;
}

static int64_t parse_and(parser_t *ps) {
    int64_t v = parse_shift(ps);
    while (!ps->err && *ps->p == '&' && ps->p[1] != '&') {
        ps->p++; v &= parse_shift(ps);
    }
    return v;
}

static int64_t parse_xor(parser_t *ps) {
    int64_t v = parse_and(ps);
    while (!ps->err && *ps->p == '^') { ps->p++; v ^= parse_and(ps); }
    return v;
}

static int64_t parse_or(parser_t *ps) {
    int64_t v = parse_xor(ps);
    while (!ps->err && *ps->p == '|' && ps->p[1] != '|') {
        ps->p++; v |= parse_xor(ps);
    }
    return v;
}

static int64_t parse_expr(parser_t *ps) {
    return parse_or(ps);
}

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/**
 * 求值表达式。
 * @param expr  表达式字符串 (如 "$rax + $rbx*8 + 0x20")
 * @param regs  寄存器值数组 (R_COUNT 个 uint64_t), NULL = 只能用常量
 * @param err   输出: 0=OK, 1=语法错误, 2=除零
 * @return      表达式的值
 */
int64_t expr_eval(const char *expr, const uint64_t regs[], int *err)
{
    parser_t ps = { .p = expr, .regs = regs, .err = 0 };
    int64_t result = parse_expr(&ps);
    skip_space(&ps);
    if (ps.err == 0 && *ps.p != '\0') ps.err = ERR_SYNTAX; /* 尾部垃圾 */
    if (err) *err = ps.err;
    return result;
}

/**
 * 校验表达式语法 (不求值)。
 * @return 0=合法, 非零=错误
 */
int expr_validate(const char *expr)
{
    int err;
    /* 用 dummy registers 做解析 */
    uint64_t dummy[R_COUNT];
    memset(dummy, 0, sizeof(dummy));
    expr_eval(expr, dummy, &err);
    return err;
}

/* ================================================================== */
/* 便捷函数: 条件求值                                                 */
/* ================================================================== */

/**
 * 求值条件表达式 (返回 true/false)。
 * 支持: ==, !=, <, >, <=, >=
 * 例: "$rax == 0x7f...", "($rsp+8) > 0x1000"
 */
int expr_eval_condition(const char *cond_expr, const uint64_t regs[], int *err)
{
    /* 找到比较运算符 */
    const char *op = NULL;
    int op_type = 0; /* 0:== 1:!= 2:< 3:> 4:<= 5:>= */
    char left[128];

    /* 扫描找到比较运算符 (在括号和寄存器名之外) */
    const char *scan = cond_expr;
    int paren = 0;
    while (*scan) {
        if (*scan == '(') paren++;
        else if (*scan == ')') paren--;
        else if (paren == 0) {
            if (scan[0] == '=' && scan[1] == '=') { op = scan; op_type = 0; break; }
            if (scan[0] == '!' && scan[1] == '=') { op = scan; op_type = 1; break; }
            if (scan[0] == '<' && scan[1] == '=') { op = scan; op_type = 4; break; }
            if (scan[0] == '>' && scan[1] == '=') { op = scan; op_type = 5; break; }
            if (scan[0] == '<') { op = scan; op_type = 2; break; }
            if (scan[0] == '>') { op = scan; op_type = 3; break; }
        }
        scan++;
    }

    if (!op) {
        /* 无比较运算符 → 求值后检查是否非零 */
        int64_t v = expr_eval(cond_expr, regs, err);
        if (err && *err) return 0;
        return (v != 0);
    }

    size_t llen = (size_t)(op - cond_expr);
    if (llen >= sizeof(left)) { if (err) *err = ERR_SYNTAX; return 0; }
    memcpy(left, cond_expr, llen);
    left[llen] = '\0';

    int64_t lv = expr_eval(left, regs, err);
    if (err && *err) return 0;
    int64_t rv = expr_eval(op + (op_type <= 1 ? 2 : 1), regs, err);
    if (err && *err) return 0;

    switch (op_type) {
    case 0: return lv == rv;
    case 1: return lv != rv;
    case 2: return lv <  rv;
    case 3: return lv >  rv;
    case 4: return lv <= rv;
    case 5: return lv >= rv;
    default: return 0;
    }
}

/**
 * 返回错误描述。
 */
const char *expr_error_str(int err)
{
    switch (err) {
    case ERR_NONE:     return "OK";
    case ERR_SYNTAX:   return "syntax error";
    case ERR_DIVZERO:  return "division by zero";
    case ERR_OVERFLOW: return "overflow";
    default:           return "unknown error";
    }
}
