/*
 * xref.c — 交叉引用查看器 (Code/Data XRef)
 *
 * 双路径架构:
 *   DB 路径:  直接从 xrefs/instructions/symbols 表查询 (零反汇编)
 *   mmap 路径: 扫描所有指令操作数构建引用索引 (原有逻辑, DB 不可用时降级)
 *
 * 符合 COORDINATION.md:
 *   接口: int parse_xref(Elf64_Ctx *ctx, PanelData *pd);
 *
 * 依赖: disasm.h (Capstone, 仅 mmap 路径)
 */
#include "elf_parser.h"
#include "disasm.h"
#include "core/db.h"
#include <sqlite3.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* 外部 DB 句柄 */
extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 数据结构                                                           */
/* ================================================================== */

#define XREF_MAX 16384

typedef enum { XREF_CODE = 0, XREF_DATA, XREF_STRING } xref_type_t;

typedef struct {
    xref_type_t type;
    uint64_t    from;       /* 引用来源地址 */
    uint64_t    to;         /* 被引用地址 */
    char        insn[64];   /* 引用指令文本 */
} xref_t;

typedef struct {
    xref_t *entries;
    int     count;
    int     capacity;
} xref_index_t;

/* ================================================================== */
/* 辅助: 地址段检测                                                   */
/* ================================================================== */

/** addr 是否在代码段范围内 */
static int in_exec_section(Elf64_Ctx *ctx, uint64_t addr)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;
        if (addr >= sh->sh_addr && addr < sh->sh_addr + sh->sh_size)
            return 1;
    }
    return 0;
}

/** addr 是否在可读数据段范围内 */
static int in_data_section(Elf64_Ctx *ctx, uint64_t addr)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_flags & SHF_EXECINSTR) continue;
        if (!(sh->sh_flags & SHF_ALLOC)) continue;
        if (addr >= sh->sh_addr && addr < sh->sh_addr + sh->sh_size)
            return 1;
    }
    return 0;
}

/* ================================================================== */
/* 反汇编回调                                                        */
/* ================================================================== */

typedef struct {
    xref_index_t *idx;
    Elf64_Ctx    *ctx;
} xref_collect_t;

static bool xref_on_insn(const cs_insn *insn, void *user)
{
    xref_collect_t *coll = (xref_collect_t *)user;

    if (!insn->detail) return true;

    cs_x86 *x86 = &insn->detail->x86;
    char insn_text[64];
    snprintf(insn_text, sizeof(insn_text), "%.32s %.24s", insn->mnemonic, insn->op_str);

    for (uint8_t oi = 0; oi < x86->op_count; oi++) {
        cs_x86_op *op = &x86->operands[oi];
        uint64_t target = 0;
        xref_type_t xtype = XREF_CODE;

        if (op->type == X86_OP_IMM) {
            target = (uint64_t)op->imm;
            if (target == 0) continue;

            if (in_exec_section(coll->ctx, target))
                xtype = XREF_CODE;
            else if (in_data_section(coll->ctx, target))
                xtype = XREF_DATA;
            else
                continue;
        } else if (op->type == X86_OP_MEM) {
            int64_t disp = op->mem.disp;
            if (disp == 0) continue;

            if (op->mem.base == X86_REG_RIP || op->mem.base == X86_REG_EIP) {
                target = (uint64_t)((int64_t)insn->address +
                                    (int64_t)insn->size + disp);
            } else {
                target = (uint64_t)disp;
            }

            if (in_data_section(coll->ctx, target))
                xtype = XREF_DATA;
            else if (in_exec_section(coll->ctx, target))
                xtype = XREF_CODE;
            else
                continue;
        } else {
            continue;
        }

        /* 扩容 */
        if (coll->idx->count >= coll->idx->capacity) {
            coll->idx->capacity = coll->idx->capacity ? coll->idx->capacity * 2 : 2048;
            xref_t *ne = realloc(coll->idx->entries,
                (size_t)coll->idx->capacity * sizeof(xref_t));
            if (!ne) return false;
            coll->idx->entries = ne;
        }

        xref_t *xr = &coll->idx->entries[coll->idx->count++];
        xr->type = xtype;
        xr->from = insn->address;
        xr->to   = target;
        strncpy(xr->insn, insn_text, sizeof(xr->insn) - 1);
        xr->insn[sizeof(xr->insn) - 1] = '\0';
    }

    return true;
}

/* ================================================================== */
/* 排序与分组                                                        */
/* ================================================================== */

static int xref_by_to(const void *a, const void *b)
{
    const xref_t *xa = (const xref_t *)a;
    const xref_t *xb = (const xref_t *)b;
    if (xa->to < xb->to) return -1;
    if (xa->to > xb->to) return 1;
    return 0;
}

/* ================================================================== */
/* DB 路径: 从 xrefs 表直接查询                                        */
/* ================================================================== */

static int parse_xref_db(AnalysisDB *adb, Elf64_Ctx *ctx, PanelData *pd)
{
    (void)ctx;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[256];
    int total_xrefs = 0;

    /* 统计 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM xrefs", -1, &st, NULL);
    if (st) {
        if (sqlite3_step(st) == SQLITE_ROW)
            total_xrefs = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    snprintf(buf, sizeof(buf),
             "=== Cross-Reference Index (%d refs) [DB] ===", total_xrefs);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (total_xrefs == 0) {
        fields_add(pd, "(no xrefs in DB — import ELF first)", 1, 0, DETAIL_NONE, -1);
        return 0;
    }

    /* Code vs Data 统计 */
    int code_refs = 0, data_refs = 0;
    sqlite3_prepare_v2(c,
        "SELECT ref_type,COUNT(*) FROM xrefs GROUP BY ref_type",
        -1, &st, NULL);
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *rt = (const char *)sqlite3_column_text(st, 0);
            int cnt = sqlite3_column_int(st, 1);
            if (rt && strstr(rt, "JMP") || rt && strstr(rt, "CALL"))
                code_refs += cnt;
            else
                data_refs += cnt;
        }
        sqlite3_finalize(st);
    }
    snprintf(buf, sizeof(buf), "Code refs: %d  Data refs: %d", code_refs, data_refs);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 按目标地址分组: 最多显示 200 条 */
    fields_add(pd, "── References by target ──", 0, 0, DETAIL_NONE, -1);

    sqlite3_prepare_v2(c,
        "SELECT x.to_addr,"
        "  (SELECT ref_type FROM xrefs x2 WHERE x2.to_addr=x.to_addr LIMIT 1), "
        "  x.from_addr, i.mnemonic, i.op_str, "
        "  (SELECT name FROM sections WHERE addr = ("
        "    SELECT MAX(s2.addr) FROM sections s2 WHERE s2.addr<=x.to_addr)) "
        "FROM xrefs x "
        "JOIN instructions i ON x.from_addr=i.address "
        "ORDER BY x.to_addr, x.from_addr LIMIT 300",
        -1, &st, NULL);
    if (st) {
        uint64_t last_to = 0;
        int per_target = 0;
        int shown = 0;

        while (sqlite3_step(st) == SQLITE_ROW && shown < 300) {
            uint64_t to_addr   = (uint64_t)sqlite3_column_int64(st, 0);
            const char *ref_type = (const char *)sqlite3_column_text(st, 1);
            uint64_t from_addr = (uint64_t)sqlite3_column_int64(st, 2);
            const char *mnem   = (const char *)sqlite3_column_text(st, 3);
            const char *op_str = (const char *)sqlite3_column_text(st, 4);
            const char *sec    = (const char *)sqlite3_column_text(st, 5);

            if (to_addr != last_to) {
                per_target = 0;
                const char *type_str = (ref_type && strstr(ref_type, "JMP") || ref_type && strstr(ref_type, "CALL"))
                    ? "[CODE]" : "[DATA]";
                snprintf(buf, sizeof(buf),
                         "XRefs to 0x%lx %s (%s):",
                         (unsigned long)to_addr, type_str,
                         sec ? sec : "?");
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                last_to = to_addr;
            }

            if (per_target < 5) {
                snprintf(buf, sizeof(buf),
                         "  ← 0x%lx  %s %s",
                         (unsigned long)from_addr,
                         mnem ? mnem : "?", op_str ? op_str : "");
                fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                per_target++;
                shown++;
            } else if (per_target == 5) {
                fields_add(pd, "  ... (more refs)", 2, 0, DETAIL_NONE, -1);
                per_target++;
            }
        }
        sqlite3_finalize(st);
    }

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始实现 (DB 不可用时降级)                               */
/* ================================================================== */

static int parse_xref_mmap(Elf64_Ctx *ctx, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    disasm_ctx *d = disasm_open();
    if (!d) {
        fields_add(pd, "(disasm engine unavailable)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    /* 初始化索引 */
    xref_index_t idx = {NULL, 0, 0};
    xref_collect_t coll = {&idx, ctx};

    /* 扫描所有代码段 */
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_type != SHT_PROGBITS) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;

        disasm_run(d, ctx->map + sh->sh_offset, sh->sh_size,
                   sh->sh_addr, xref_on_insn, &coll);
    }

    disasm_close(d);

    /* 输出 */
    char buf[256];
    snprintf(buf, sizeof(buf),
             "=== Cross-Reference Index (%d refs) ===", idx.count);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (idx.count == 0) {
        fields_add(pd, "(no cross-references found)", 1, 0, DETAIL_NONE, -1);
        free(idx.entries);
        return pd->count;
    }

    /* 按被引用地址排序, 分组显示 */
    qsort(idx.entries, (size_t)idx.count, sizeof(xref_t), xref_by_to);

    /* 统计 */
    int code_refs = 0, data_refs = 0;
    for (int i = 0; i < idx.count; i++) {
        if (idx.entries[i].type == XREF_CODE) code_refs++;
        else data_refs++;
    }

    snprintf(buf, sizeof(buf), "Code refs: %d  Data refs: %d",
             code_refs, data_refs);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 分组: 每个被引用地址最多显示 5 条引用 */
    fields_add(pd, "─ ─ ─ References by target ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    uint64_t last_to = 0;
    int per_target = 0;
    int shown = 0;
    int max_show = 150;

    for (int i = 0; i < idx.count && shown < max_show; i++) {
        xref_t *xr = &idx.entries[i];

        if (xr->to != last_to) {
            per_target = 0;

            /* 解析目标名称 */
            const char *target_sec = "";
            for (int si = 0; si < shnum; si++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, si);
                if (sh && xr->to >= sh->sh_addr &&
                    xr->to < sh->sh_addr + sh->sh_size) {
                    target_sec = elf_section_name(ctx, si);
                    break;
                }
            }

            const char *type_str = xr->type == XREF_CODE ? "[CODE]" : "[DATA]";
            snprintf(buf, sizeof(buf),
                     "XRefs to 0x%lx %s (%s):",
                     (unsigned long)xr->to, type_str,
                     target_sec ? target_sec : "?");
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            last_to = xr->to;
        }

        if (per_target < 5) {
            snprintf(buf, sizeof(buf),
                     "  ← 0x%lx  %s",
                     (unsigned long)xr->from, xr->insn);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            per_target++;
            shown++;
        } else if (per_target == 5) {
            fields_add(pd, "  ... (more refs, use detail view)", 2, 0, DETAIL_NONE, -1);
            per_target++;
        }
    }

    if (idx.count > max_show) {
        snprintf(buf, sizeof(buf), "... (%d more refs not shown)",
                 idx.count - max_show);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    free(idx.entries);
    return pd->count;
}

/* ================================================================== */
/* 公共接口: parse_xref (DB 优先, mmap 降级)                          */
/* ================================================================== */

int parse_xref(Elf64_Ctx *ctx, PanelData *pd)
{
    if (g_active_db) {
        return parse_xref_db(g_active_db, ctx, pd);
    }
    return parse_xref_mmap(ctx, pd);
}
