/*
 * gadget.c — ROP Gadget 搜索模块 (v2 — DB 优先)
 *
 * 双路径:
 *   DB 路径: 从 instructions 表查询特定助记符序列 (零反汇编, 零扫描)
 *   mmap 路径: 纯字节扫描 ret(0xC3) 并回溯 (原有逻辑, DB 不可用时降级)
 *
 * 接口: int parse_gadget(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 */
#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* Gadget 分类                                                        */
/* ================================================================== */

typedef struct {
    const char *label;
    const uint8_t *sig;        /* 字节序列 */
    int           sig_len;
    int           max_show;
} gadget_class_t;

static const uint8_t POP_RDI[]  = {0x5f, 0xc3};          /* pop rdi; ret */
static const uint8_t POP_RSI[]  = {0x5e, 0xc3};          /* pop rsi; ret */
static const uint8_t POP_RDX[]  = {0x5a, 0xc3};          /* pop rdx; ret */
static const uint8_t POP_RCX[]  = {0x59, 0xc3};          /* pop rcx; ret */
static const uint8_t POP_RAX[]  = {0x58, 0xc3};          /* pop rax; ret */
static const uint8_t SYSCALL[]  = {0x0f, 0x05, 0xc3};    /* syscall; ret */
static const uint8_t XOR_RAX[]  = {0x48, 0x31, 0xc0, 0xc3}; /* xor rax,rax; ret */
static const uint8_t XOR_EAX[]  = {0x31, 0xc0, 0xc3};    /* xor eax,eax; ret */
static const uint8_t LEAVE_RET[]= {0xc9, 0xc3};          /* leave; ret */

static const gadget_class_t CLASSES[] = {
    {"pop rdi; ret",      POP_RDI,   sizeof(POP_RDI),   20},
    {"pop rsi; ret",      POP_RSI,   sizeof(POP_RSI),   15},
    {"pop rdx; ret",      POP_RDX,   sizeof(POP_RDX),   15},
    {"pop rcx; ret",      POP_RCX,   sizeof(POP_RCX),   10},
    {"pop rax; ret",      POP_RAX,   sizeof(POP_RAX),   10},
    {"syscall; ret",      SYSCALL,   sizeof(SYSCALL),   10},
    {"xor rax,rax; ret",  XOR_RAX,   sizeof(XOR_RAX),   10},
    {"xor eax,eax; ret",  XOR_EAX,   sizeof(XOR_EAX),   10},
    {"leave; ret",        LEAVE_RET, sizeof(LEAVE_RET), 10},
};
#define NCLASS (int)(sizeof(CLASSES) / sizeof(CLASSES[0]))

/* 与已知 pattern 比较 */
static int match_sig(const uint8_t *data, size_t size,
                     const uint8_t *sig, int sig_len)
{
    if ((int)size < sig_len) return 0;
    return memcmp(data, sig, (size_t)sig_len) == 0;
}

/* ================================================================== */
/* DB 路径: 从 instructions 表查询 gadget                               */
/* ================================================================== */

/* gadget 查询定义: (助记符, 操作数, 后继助记符) */
typedef struct {
    const char *label;
    const char *mnem;       /* 主要助记符 (pop/syscall/xor) */
    const char *op_str;     /* 操作数字符串 (NULL = 任意) */
    const char *next_mnem;  /* 必须是 'ret' 结尾 */
    int         max_show;
} gadget_query_t;

static const gadget_query_t GADGET_QUERIES[] = {
    {"pop rdi; ret",       "pop",  "rdi",     "ret",  20},
    {"pop rsi; ret",       "pop",  "rsi",     "ret",  15},
    {"pop rdx; ret",       "pop",  "rdx",     "ret",  15},
    {"pop rcx; ret",       "pop",  "rcx",     "ret",  10},
    {"pop rax; ret",       "pop",  "rax",     "ret",  10},
    {"pop r8; ret",        "pop",  "r8",      "ret",   5},
    {"pop r9; ret",        "pop",  "r9",      "ret",   5},
    {"syscall; ret",       "syscall", NULL,   "ret",  10},
    {"xor rax,rax; ret",   "xor",  "rax, rax","ret",  10},
    {"xor eax,eax; ret",   "xor",  "eax, eax","ret",  10},
    {"leave; ret",         "leave", NULL,     "ret",  10},
    {"ret",                "ret",   NULL,     NULL,    10},
};

#define NGQ (int)(sizeof(GADGET_QUERIES) / sizeof(GADGET_QUERIES[0]))

static int parse_gadget_db(AnalysisDB *adb, Elf64_Ctx *ctx, PanelData *pd)
{
    (void)ctx;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[256];
    int total_found = 0;
    int class_found[NGQ];

    fields_add(pd, "=== ROP Gadget Search [DB] ===", 0, 0, DETAIL_NONE, -1);

    for (int qi = 0; qi < NGQ; qi++) {
        char sql[512];
        /* 查询当前指令匹配, 下一条指令匹配 next_mnem */
        if (GADGET_QUERIES[qi].next_mnem) {
            if (GADGET_QUERIES[qi].op_str) {
                snprintf(sql, sizeof(sql),
                    "SELECT i1.address, i1.mnemonic, i1.op_str, i2.address "
                    "FROM instructions i1 "
                    "JOIN instructions i2 ON i2.address = i1.address + i1.size "
                    "WHERE i1.mnemonic='%s' AND i1.op_str='%s' "
                    "AND i2.mnemonic='%s' "
                    "ORDER BY i1.address LIMIT %d",
                    GADGET_QUERIES[qi].mnem,
                    GADGET_QUERIES[qi].op_str,
                    GADGET_QUERIES[qi].next_mnem,
                    GADGET_QUERIES[qi].max_show);
            } else {
                snprintf(sql, sizeof(sql),
                    "SELECT i1.address, i1.mnemonic, i1.op_str, i2.address "
                    "FROM instructions i1 "
                    "JOIN instructions i2 ON i2.address = i1.address + i1.size "
                    "WHERE i1.mnemonic='%s' "
                    "AND i2.mnemonic='%s' "
                    "ORDER BY i1.address LIMIT %d",
                    GADGET_QUERIES[qi].mnem,
                    GADGET_QUERIES[qi].next_mnem,
                    GADGET_QUERIES[qi].max_show);
            }
        } else {
            /* 单条指令 (如 ret) */
            snprintf(sql, sizeof(sql),
                "SELECT address, mnemonic, op_str, 0 FROM instructions "
                "WHERE mnemonic='%s' ORDER BY address LIMIT %d",
                GADGET_QUERIES[qi].mnem,
                GADGET_QUERIES[qi].max_show);
        }

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c, sql, -1, &st, NULL) != SQLITE_OK) continue;

        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *mnem = (const char *)sqlite3_column_text(st, 1);
            const char *op   = (const char *)sqlite3_column_text(st, 2);
            uint64_t addr2   = (uint64_t)sqlite3_column_int64(st, 3);

            if (found == 0) {
                snprintf(buf, sizeof(buf), "--- %s ---",
                         GADGET_QUERIES[qi].label);
                fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
            }

            if (addr2) {
                snprintf(buf, sizeof(buf), "0x%lx: %-8s %-16s → ret @ 0x%lx",
                         (unsigned long)addr, mnem ? mnem : "?",
                         op ? op : "", (unsigned long)addr2);
            } else {
                snprintf(buf, sizeof(buf), "0x%lx: %-8s %-16s",
                         (unsigned long)addr, mnem ? mnem : "?",
                         op ? op : "");
            }
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)addr);
            found++;
            total_found++;
        }
        class_found[qi] = found;
        sqlite3_finalize(st);
    }

    /* 总结 */
    snprintf(buf, sizeof(buf), "────────────────────");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    for (int qi = 0; qi < NGQ; qi++) {
        if (class_found[qi] > 0) {
            snprintf(buf, sizeof(buf), "%d %s", class_found[qi], GADGET_QUERIES[qi].label);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    }
    snprintf(buf, sizeof(buf), "Total: %d gadgets", total_found);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始字节扫描 (DB 不可用时降级)                           */
/* ================================================================== */

static int parse_gadget_mmap(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;

    /* 收集所有代码段数据 */
    typedef struct { const uint8_t *data; size_t size; uint64_t base; } code_seg_t;
    code_seg_t code_segs[32];
    int ncode = 0;

    if (shdr_idx >= 0) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
        if (sh && sh->sh_size > 0 && (sh->sh_flags & SHF_EXECINSTR)) {
            code_segs[ncode].data = ctx->map + sh->sh_offset;
            code_segs[ncode].size = sh->sh_size;
            code_segs[ncode].base = sh->sh_addr;
            ncode++;
        }
    } else {
        for (int i = 0; i < shnum && ncode < 32; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (!sh || sh->sh_size == 0) continue;
            if (!(sh->sh_flags & SHF_EXECINSTR)) continue;
            code_segs[ncode].data = ctx->map + sh->sh_offset;
            code_segs[ncode].size = sh->sh_size;
            code_segs[ncode].base = sh->sh_addr;
            ncode++;
        }
    }

    /* 标题 */
    char buf[256];
    int total_found = 0;
    int class_found[NCLASS];
    memset(class_found, 0, sizeof(class_found));
    int other_found = 0;

    /* 第一趟: 统计各类型数量 */
    for (int ci = 0; ci < ncode; ci++) {
        const uint8_t *data = code_segs[ci].data;
        size_t size = code_segs[ci].size;

        for (size_t off = 0; off < size; off++) {
            if (data[off] != 0xc3) continue; /* 只关心 ret */

            /* 回溯最多 20 字节 */
            size_t back = (off >= 20) ? 20 : off;
            const uint8_t *gadget = data + off - back;
            size_t glen = back + 1;

            /* 匹配已知类型 */
            int matched = 0;
            for (int cl = 0; cl < NCLASS; cl++) {
                if (glen >= (size_t)CLASSES[cl].sig_len) {
                    const uint8_t *tail = data + off + 1 - CLASSES[cl].sig_len;
                    if (memcmp(tail, CLASSES[cl].sig,
                               (size_t)CLASSES[cl].sig_len) == 0) {
                        class_found[cl]++;
                        matched = 1;
                        break;
                    }
                }
            }
            if (!matched) other_found++;
            total_found++;
        }
    }

    snprintf(buf, sizeof(buf), "=== ROP Gadget Search (%d found) ===", total_found);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 第二趟: 输出每类 (最多 N 个) */
    for (int cl = 0; cl < NCLASS; cl++) {
        if (class_found[cl] == 0) continue;

        snprintf(buf, sizeof(buf), "--- %s (%d found) ---",
                 CLASSES[cl].label, class_found[cl]);
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

        int shown = 0;
        for (int ci = 0; ci < ncode && shown < CLASSES[cl].max_show; ci++) {
            const uint8_t *data = code_segs[ci].data;
            size_t size = code_segs[ci].size;
            uint64_t base = code_segs[ci].base;

            for (size_t off = (size_t)CLASSES[cl].sig_len - 1;
                 off < size && shown < CLASSES[cl].max_show; off++) {
                if (data[off] != 0xc3) continue;
                const uint8_t *tail = data + off + 1 - CLASSES[cl].sig_len;
                if (memcmp(tail, CLASSES[cl].sig,
                           (size_t)CLASSES[cl].sig_len) != 0) continue;

                uint64_t addr = base + off + 1 - CLASSES[cl].sig_len;
                char hex[48] = "";
                for (int b = 0; b < CLASSES[cl].sig_len; b++)
                    snprintf(hex + b*3, sizeof(hex) - (size_t)(b*3),
                             "%02x ", tail[b]);

                snprintf(buf, sizeof(buf), "0x%lx: %-24s %s",
                         (unsigned long)addr, hex, CLASSES[cl].label);
                fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)addr);
                shown++;
            }
        }
    }

    /* Other */
    if (other_found > 0) {
        snprintf(buf, sizeof(buf), "--- other (%d found) ---", other_found);
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 总结 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);
    int sum = other_found;
    for (int cl = 0; cl < NCLASS; cl++) sum += class_found[cl];
    char summary[256] = "";
    int slen = 0;
    for (int cl = 0; cl < NCLASS; cl++) {
        if (class_found[cl] > 0) {
            slen += snprintf(summary + slen, sizeof(summary) - (size_t)slen,
                             "%d %s, ", class_found[cl], CLASSES[cl].label);
        }
    }
    slen += snprintf(summary + slen, sizeof(summary) - (size_t)slen,
                     "%d other", other_found);
    snprintf(buf, sizeof(buf), "Summary: %s", summary);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    return pd->count;
}

/* ── 公共接口 ────────────────────────────────────────────────────── */

int parse_gadget(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    if (g_active_db) {
        return parse_gadget_db(g_active_db, ctx, pd);
    }
    return parse_gadget_mmap(ctx, shdr_idx, pd);
}
