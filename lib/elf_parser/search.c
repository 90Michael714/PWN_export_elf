/*
 * search.c — 反汇编搜索/跳转模块 v2 (Prompt 14)
 *
 * 五种搜索模式:
 *   search_disasm      — 反汇编文本搜索 (助记符/操作数/地址)
 *   search_bytes       — 原始字节模式搜索 (支持 ?? 通配符)
 *   search_symbol      — 符号表模糊搜索 (保留)
 *   search_address     — 地址定位 (保留)
 *   search_string      — 字符串表搜索 (保留)
 *
 * 符合 COORDINATION.md:
 *   接口:
 *     int search_disasm(Elf64_Ctx*, const char *query, PanelData*);
 *     int search_bytes(Elf64_Ctx*, const char *pattern, PanelData*);
 *     int search_symbol(Elf64_Ctx*, const char *query, PanelData*);
 *     int search_address(Elf64_Ctx*, Elf64_Addr addr, PanelData*);
 *     int search_string(Elf64_Ctx*, const char *pattern, PanelData*);
 *
 * 依赖:
 *   search_disasm → disasm.h (Capstone)
 *   search_bytes  → 无
 *   search_symbol/search_address/search_string → 无
 */
#include "elf_parser.h"
#include "disasm.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* ================================================================== */
/* 辅助: 大小写不敏感子串匹配                                         */
/* ================================================================== */

static int str_icase(const char *h, const char *n)
{
    if (!h || !n) return 0;
    size_t hl = strlen(h), nl = strlen(n);
    if (nl > hl) return 0;
    for (size_t i = 0; i + nl <= hl; i++) {
        int m = 1;
        for (size_t j = 0; j < nl; j++)
            if (tolower((unsigned char)h[i+j]) != tolower((unsigned char)n[j]))
            { m = 0; break; }
        if (m) return 1;
    }
    return 0;
}

/**
 * 检查 single 是否在 words 数组中 (逗号分隔的多关键字)。
 * 例如: query="call,jmp,ret" 匹配 "call" "jmp" "ret"
 */
static int match_multi(const char *haystack, const char *query)
{
    /* 如果 query 包含逗号，拆分为多关键字 */
    /* 手动复制 (避免 strdup 需要 _GNU_SOURCE) */
    size_t qlen = strlen(query);
    char *qcopy = malloc(qlen + 1);
    if (!qcopy) return str_icase(haystack, query);
    memcpy(qcopy, query, qlen + 1);

    char *token = qcopy;
    while (token) {
        /* 找到下一个逗号 */
        char *comma = strchr(token, ',');
        if (comma) *comma = '\0';

        /* 去除首尾空格 */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (*token && str_icase(haystack, token)) {
            free(qcopy);
            return 1;
        }
        token = comma ? comma + 1 : NULL;
    }
    free(qcopy);
    return 0;
}

/* ================================================================== */
/* 指令类型过滤 (快捷搜索)                                            */
/* ================================================================== */

/** 指令组过滤器 */
typedef enum {
    FLT_ALL = 0,
    FLT_CALL,          /* 所有 call 指令 */
    FLT_JMP,           /* 所有跳转 (jmp/je/jne/jg/...) */
    FLT_RET,           /* ret / iret */
    FLT_COND_JMP,      /* 条件跳转 */
    FLT_SYSCALL,       /* syscall / sysenter / int 0x80 */
    FLT_STACK,         /* push/pop */
    FLT_ARITH,         /* 算术 (add/sub/mul/div/xor/...) */
    FLT_MEM,           /* 内存访问 (mov/lea/...) */
    FLT_PRIV,          /* 特权指令 */
} insn_filter_t;

/**
 * 判断指令是否匹配过滤器。
 * 用于快速定位感兴趣的类型 (如 "所有 call" / "所有 syscall")
 */
static int insn_match_filter(const cs_insn *insn, insn_filter_t f)
{
    if (f == FLT_ALL) return 1;
    if (!insn->detail) return 0;  /* 无法判断 → 不匹配 */

    uint8_t gc = insn->detail->groups_count;
    for (uint8_t g = 0; g < gc; g++) {
        unsigned int gid = insn->detail->groups[g];
        switch (f) {
        case FLT_CALL:     if (gid == X86_GRP_CALL) return 1; break;
        case FLT_JMP:      if (gid == X86_GRP_JUMP) return 1; break;
        case FLT_RET:      if (gid == X86_GRP_RET || gid == X86_GRP_IRET) return 1; break;
        case FLT_SYSCALL:  if (gid == X86_GRP_INT) return 1; break;
        case FLT_PRIV:     if (gid == X86_GRP_PRIVILEGE) return 1; break;
        default: break;
        }
    }

    /* 条件跳转: 不在 JUMP 组但 ID 是条件跳转 */
    if (f == FLT_COND_JMP) {
        switch (insn->id) {
        case X86_INS_JE: case X86_INS_JNE: case X86_INS_JG:
        case X86_INS_JGE: case X86_INS_JL: case X86_INS_JLE:
        case X86_INS_JA: case X86_INS_JAE: case X86_INS_JB:
        case X86_INS_JBE: case X86_INS_JO: case X86_INS_JNO:
        case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP:
        case X86_INS_JNP: case X86_INS_LOOP: case X86_INS_LOOPE:
        case X86_INS_LOOPNE: case X86_INS_JECXZ: case X86_INS_JRCXZ:
            return 1;
        default: break;
        }
    }
    if (f == FLT_SYSCALL && insn->id == X86_INS_SYSCALL) return 1;
    if (f == FLT_STACK && (insn->id == X86_INS_PUSH || insn->id == X86_INS_POP)) return 1;

    /* 算术: 检查助记符 */
    if (f == FLT_ARITH) {
        const char *arith[] = {"add","sub","mul","div","xor","and","or",
                               "shl","shr","sar","rol","ror","inc","dec",NULL};
        for (const char **a = arith; *a; a++)
            if (!strcmp(insn->mnemonic, *a)) return 1;
    }
    if (f == FLT_MEM) {
        const char *mem[] = {"mov","lea","xchg","cmpxchg","lds","les",NULL};
        for (const char **m = mem; *m; m++)
            if (!strcmp(insn->mnemonic, *m)) return 1;
        /* 也匹配任何含 '[' 的操作数 (内存引用) */
        if (strchr(insn->op_str, '[')) return 1;
    }

    return 0;
}

/** 解析过滤器名称 → 枚举 */
static insn_filter_t parse_filter(const char *name)
{
    if (!name) return FLT_ALL;
    if (str_icase(name, "call"))       return FLT_CALL;
    if (str_icase(name, "jmp"))        return FLT_JMP;
    if (str_icase(name, "ret"))        return FLT_RET;
    if (str_icase(name, "cond"))       return FLT_COND_JMP;
    if (str_icase(name, "syscall"))    return FLT_SYSCALL;
    if (str_icase(name, "stack"))      return FLT_STACK;
    if (str_icase(name, "arith"))      return FLT_ARITH;
    if (str_icase(name, "mem"))        return FLT_MEM;
    if (str_icase(name, "priv"))       return FLT_PRIV;
    return FLT_ALL;
}

/* ================================================================== */
/* 搜索状态机: 反汇编扫描 + 模式匹配                                   */
/* ================================================================== */

typedef struct {
    const char  *pattern;       /* 搜索字符串 (NULL = 仅过滤) */
    insn_filter_t filter;       /* 指令类型过滤器 */
    int          max_results;   /* 最多返回结果数 */
    int          found;         /* 已找到 */
    int          scanned;       /* 已扫描指令总数 */
    /* 结果缓存 */
    struct { uint64_t addr; char text[256]; } *results;
    int          cap;
    int          cnt;
    Elf64_Ctx   *ctx;
} search_state_t;

static bool on_insn_search(const cs_insn *insn, void *user)
{
    search_state_t *st = (search_state_t *)user;
    st->scanned++;

    /* 过滤器检查 */
    if (!insn_match_filter(insn, st->filter))
        return true; /* 继续, 不匹配这一条 */

    /* 模式匹配 */
    if (st->pattern) {
        /* 在助记符+操作数的完整文本中搜索 */
        char full[192];
        snprintf(full, sizeof(full), "%s %s", insn->mnemonic, insn->op_str);
        if (!match_multi(full, st->pattern))
            return true; /* 不匹配 */
    }

    st->found++;

    /* 存储结果 */
    if (st->cnt < st->cap) {
        st->results[st->cnt].addr = insn->address;
        snprintf(st->results[st->cnt].text,
                 sizeof(st->results[0].text),
                 "%s %s", insn->mnemonic, insn->op_str);
        st->cnt++;
    }

    /* 达到上限? */
    if (st->cnt >= st->max_results)
        return false; /* 停止扫描 */

    return true;
}

/** 扫描所有代码段，运行搜索 */
static int scan_code(Elf64_Ctx *ctx, search_state_t *st)
{
    disasm_ctx *d = disasm_open();
    if (!d) return -1;

    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_type != SHT_PROGBITS) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;

        disasm_run(d, ctx->map + sh->sh_offset, sh->sh_size,
                   sh->sh_addr, on_insn_search, st);

        if (st->cnt >= st->max_results) break;
    }

    disasm_close(d);
    return 0;
}

/* ================================================================== */
/* search_disasm — 反汇编文本搜索                                     */
/* ================================================================== */

int search_disasm(Elf64_Ctx *ctx, const char *query, PanelData *pd)
{
    /* 解析查询: "call,ret" → 多关键字; "call system" → 单关键字 */
    /* 第一个词如果是过滤器关键字，使用过滤器加速 */

    /* 提取第一个词作为可能的过滤器 */
    char first[32] = "";
    const char *rest = query;
    {
        const char *sp = strchr(query, ' ');
        const char *cm = strchr(query, ',');
        const char *sep = NULL;
        if (sp && cm) sep = (sp < cm) ? sp : cm;
        else          sep = sp ? sp : cm;
        if (sep) {
            size_t len = (size_t)(sep - query);
            if (len < sizeof(first)) { memcpy(first, query, len); first[len] = '\0'; }
            rest = sep + 1;
            while (*rest == ' ' || *rest == ',') rest++;
        } else {
            strncpy(first, query, sizeof(first)-1);
            rest = "";
        }
    }

    search_state_t st = {0};
    st.ctx         = ctx;
    st.filter      = parse_filter(first);
    st.pattern     = (*rest) ? rest : query; /* 如果只有一个词, 整体作为模式 */
    st.max_results = 200;
    st.cap         = 256;
    st.results     = calloc((size_t)st.cap, sizeof(st.results[0]));
    if (!st.results) return pd->count;

    scan_code(ctx, &st);

    /* 输出 */
    char buf[384];
    if (st.filter != FLT_ALL) {
        snprintf(buf, sizeof(buf),
                 "=== Disasm Search: \"%s\" (filter=%s, %d hits / %d insns) ===",
                 query, first, st.found, st.scanned);
    } else {
        snprintf(buf, sizeof(buf),
                 "=== Disasm Search: \"%s\" (%d hits / %d insns) ===",
                 query, st.found, st.scanned);
    }
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (st.found == 0) {
        fields_add(pd, "(no matches)", 1, 0, DETAIL_NONE, -1);
        free(st.results);
        return pd->count;
    }

    /* 按地址分组: 每遇到一个新节就在结果前加节名 */
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    for (int i = 0; i < st.cnt && i < st.max_results; i++) {
        /* 查找该地址所在的节 */
        const char *sec = "";
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (sh && st.results[i].addr >= sh->sh_addr &&
                st.results[i].addr < sh->sh_addr + sh->sh_size) {
                sec = elf_section_name(ctx, si);
                break;
            }
        }

        snprintf(buf, sizeof(buf),
                 "  0x%lx  %-48s  [%s]",
                 (unsigned long)st.results[i].addr,
                 st.results[i].text, sec ? sec : "?");
        fields_add(pd, buf, 1, 1, DETAIL_NONE,
                   (int)(st.results[i].addr & 0xFFFF));
    }

    if (st.found > st.max_results) {
        snprintf(buf, sizeof(buf),
                 "... (%d more results — narrow your search)", st.found - st.max_results);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    /* 统计 */
    snprintf(buf, sizeof(buf),
             "Scanned %d instructions across code sections, %d matched",
             st.scanned, st.found);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    free(st.results);
    return pd->count;
}

/* ================================================================== */
/* search_bytes — 原始字节模式搜索                                    */
/* ================================================================== */

/** 解析 hex 字符串 "48 8B ?? 24" → 字节数组 + wildcard mask */
static int parse_byte_pattern(const char *pattern,
                              uint8_t *bytes, uint8_t *mask, int max)
{
    int len = 0;
    const char *p = pattern;
    while (*p && len < max) {
        /* 跳过空格 */
        while (*p == ' ') p++;
        if (!*p) break;

        if (p[0] == '?' && p[1] == '?') {
            bytes[len] = 0;
            mask[len]  = 1;  /* wildcard */
            len++;
            p += 2;
        } else if (isxdigit((unsigned char)p[0]) &&
                   (p[1] == ' ' || p[1] == '\0' || isxdigit((unsigned char)p[1]))) {
            /* 单 hex 数字时左补 0: "A" → 0x0A, 不变成 "A0"=0xA0 */
            char hex[3];
            if (p[1] && isxdigit((unsigned char)p[1])) {
                hex[0] = p[0]; hex[1] = p[1]; hex[2] = '\0';
                p += 2;
            } else {
                hex[0] = '0'; hex[1] = p[0]; hex[2] = '\0';
                p += 1;
            }
            bytes[len] = (uint8_t)strtoul(hex, NULL, 16);
            mask[len]  = 0;
            len++;
        } else {
            p++; /* skip unknown char */
        }
    }
    return len;
}

int search_bytes(Elf64_Ctx *ctx, const char *pattern, PanelData *pd)
{
    uint8_t bytes[64], mask[64];
    int pat_len = parse_byte_pattern(pattern, bytes, mask, 64);

    char buf[320];
    if (pat_len <= 0) {
        fields_add(pd, "(invalid byte pattern — use hex: \"48 8B ?? 24\")",
                   0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    snprintf(buf, sizeof(buf),
             "=== Byte Search: \"%s\" (%d bytes, %d wildcards) ===",
             pattern, pat_len,
             (int)(memchr(mask, 1, (size_t)pat_len) != NULL ? 1 : 0));
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    int total = 0;
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    #define MAX_RESULTS 100

    for (int si = 0; si < shnum && total < MAX_RESULTS; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size < (Elf64_Xword)pat_len) continue;

        const uint8_t *data = ctx->map + sh->sh_offset;
        size_t size = sh->sh_size;

        for (size_t off = 0; off + (size_t)pat_len <= size && total < MAX_RESULTS; off++) {
            int match = 1;
            for (int b = 0; b < pat_len; b++) {
                if (!mask[b] && data[off + b] != bytes[b]) { match = 0; break; }
            }
            if (!match) continue;

            if (total == 0) {
                const char *sn = elf_section_name(ctx, si);
                snprintf(buf, sizeof(buf), "  [%s]", sn ? sn : "?");
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            }

            /* 显示匹配位置 + 上下文 */
            char hex[64];
            int hpos = 0;
            for (int b = 0; b < pat_len && hpos < 55; b++)
                hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                                "%02x ", data[off + b]);

            uint64_t addr = sh->sh_addr + off;
            snprintf(buf, sizeof(buf), "  0x%lx:  %s", (unsigned long)addr, hex);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)(addr & 0xFFFF));
            total++;
        }
    }

    if (total >= MAX_RESULTS) {
        snprintf(buf, sizeof(buf), "... (stopped at %d results)", MAX_RESULTS);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    } else if (total == 0) {
        fields_add(pd, "(no matches)", 1, 0, DETAIL_NONE, -1);
    } else {
        snprintf(buf, sizeof(buf), "Found %d match(es)", total);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}

/* ================================================================== */
/* search_symbol — 符号表模糊搜索 (保留)                              */
/* ================================================================== */

int search_symbol(Elf64_Ctx *ctx, const char *query, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    char buf[320];

    snprintf(buf, sizeof(buf), "=== Search: \"%s\" in symbols ===", query);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    int found = 0;
    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        const char *table = (pass == 0) ? ".symtab" : ".dynsym";
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_type != want) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;

            Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym && found < 100; j++) {
                const char *n = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
                if (!n || !n[0] || !str_icase(n, query)) continue;
                snprintf(buf, sizeof(buf),
                         "[%02d] %-40s 0x%lx  %s  (%s)",
                         found, n, (unsigned long)syms[j].st_value,
                         elf_st_type_str(syms[j].st_info), table);
                fields_add(pd, buf, 1, 1, DETAIL_SYM, j);
                found++;
            }
        }
    }
    snprintf(buf, sizeof(buf), "Found %d matching symbols", found);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    return pd->count;
}

/* ================================================================== */
/* search_address — 地址定位 (保留)                                   */
/* ================================================================== */

int search_address(Elf64_Ctx *ctx, Elf64_Addr addr, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    char buf[320];

    snprintf(buf, sizeof(buf), "=== Search: address 0x%lx ===", (unsigned long)addr);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 查找所属节 */
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (addr >= sh->sh_addr && addr < sh->sh_addr + sh->sh_size) {
            const char *sn = elf_section_name(ctx, i);
            snprintf(buf, sizeof(buf), "0x%lx is in section [%d] %s (offset +0x%lx)",
                     (unsigned long)addr, i, sn ? sn : "?",
                     (unsigned long)(addr - sh->sh_addr));
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    }

    /* 最近符号 */
    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_type != want) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;
            Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            uint64_t best = 0;
            const char *bn = NULL;
            for (int j = 0; j < nsym; j++) {
                if (syms[j].st_value > 0 && syms[j].st_value <= addr &&
                    syms[j].st_value > best) {
                    best = syms[j].st_value;
                    bn = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
                }
            }
            if (bn && bn[0]) {
                snprintf(buf, sizeof(buf), "Nearest symbol: %s+0x%lx",
                         bn, (unsigned long)(addr - best));
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            }
        }
    }
    return pd->count;
}

/* ================================================================== */
/* search_string — 字符串表搜索 (保留)                                */
/* ================================================================== */

int search_string(Elf64_Ctx *ctx, const char *pattern, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    char buf[320];

    snprintf(buf, sizeof(buf), "=== Search: \"%s\" in strings ===", pattern);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    int found = 0;
    size_t plen = strlen(pattern);

    for (int si = 0; si < shnum && found < 50; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_flags & SHF_EXECINSTR) continue;

        const char *sn = elf_section_name(ctx, si);
        const uint8_t *data = ctx->map + sh->sh_offset;
        size_t size = sh->sh_size;

        for (size_t off = 0; off + plen <= size; off++) {
            int match = 1;
            for (size_t c = 0; c < plen; c++)
                if (tolower(data[off + c]) != tolower((unsigned char)pattern[c]))
                { match = 0; break; }
            if (!match) continue;

            /* 提取上下文 */
            size_t ctx_start = (off > 30) ? off - 30 : 0;
            size_t ctx_end = (off + plen + 30 < size) ? off + plen + 30 : size;
            char preview[72]; int pp = 0;
            for (size_t c = ctx_start; c < ctx_end && pp < 68; c++) {
                unsigned char ch = data[c];
                preview[pp++] = isprint(ch) ? (char)ch : '.';
            }
            preview[pp] = '\0';

            snprintf(buf, sizeof(buf), "\"%s\" @ %s+0x%zx", preview, sn, off);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            found++;
            off += plen;
        }
    }

    snprintf(buf, sizeof(buf), "Found %d match(es)", found);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    return pd->count;
}
