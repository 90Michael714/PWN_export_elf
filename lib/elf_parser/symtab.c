/*
 * symtab.c — 符号表解析 (.symtab / .dynsym)
 *
 * 双路径:
 *   DB 路径: 从 symbols 表直接查询 (支持按名称/地址/类型排序和过滤)
 *   mmap 路径: 解析节中的符号条目 (原有逻辑, DB 不可用时降级)
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern AnalysisDB *g_active_db;

/* ── DB 路径 ─────────────────────────────────────────────────────── */

static int parse_symtab_db(AnalysisDB *adb, const char *table_name, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[512];
    sqlite3_stmt *st = NULL;

    /* 统计 */
    int total = 0;
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM symbols WHERE table_name=?1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_text(st, 1, table_name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) total = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    snprintf(buf, sizeof(buf), "=== %s (%d symbols) [DB] ===", table_name, total);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 查询: 按地址排序 */
    sqlite3_prepare_v2(c,
        "SELECT address, name, size, type, bind FROM symbols "
        "WHERE table_name=?1 ORDER BY address LIMIT 50000",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_text(st, 1, table_name, -1, SQLITE_STATIC);
        int i = 0;
        while (sqlite3_step(st) == SQLITE_ROW && i < 50000) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *name = (const char *)sqlite3_column_text(st, 1);
            int sz           = sqlite3_column_int(st, 2);
            const char *type = (const char *)sqlite3_column_text(st, 3);
            const char *bind = (const char *)sqlite3_column_text(st, 4);

            snprintf(buf, sizeof(buf),
                     "[%5d] %-6s/%-7s 0x%lX %6d %-32s",
                     i, bind ? bind : "?", type ? type : "?",
                     (unsigned long)addr, sz,
                     name ? name : "(null)");
            fields_add(pd, buf, 0, 1, DETAIL_SYM, i);
            i++;
        }
        sqlite3_finalize(st);
    }

    if (total > 50000)
        fields_add(pd, "... (truncated, showing first 50000)", 0, 0, DETAIL_NONE, -1);

    return 0;
}

/* ── mmap 路径: 原始实现 ─────────────────────────────────────────── */

static int parse_symtab_mmap(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *sec_name = elf_section_name(ctx, shdr_idx);

    if (sh->sh_entsize == 0) {
        fields_add(pd, "(Empty symbol table — sh_entsize=0)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    int sym_count = sh->sh_size / sizeof(Elf64_Sym);
    Elf64_Off stroff = 0; /* 关联字符串表偏移 */

    /* .symtab 使用 .strtab, .dynsym 使用 .dynstr */
    Elf64_Shdr *str_shdr = elf_get_shdr(ctx, sh->sh_link);
    if (str_shdr) stroff = str_shdr->sh_offset;

    char buf[320];
    snprintf(buf, sizeof(buf), "=== %s (%d symbols) ===", sec_name, sym_count);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    Elf64_Sym *syms = (Elf64_Sym*)(ctx->map + sh->sh_offset);

    for (int i = 0; i < sym_count && i < 50000; i++) {
        Elf64_Sym *sym = &syms[i];
        const char *name = (sym->st_name && stroff)
            ? elf_strtab_get(ctx, stroff, sym->st_name) : "";

        char bind_type[32];
        snprintf(bind_type, sizeof(bind_type), "%s/%s",
                 elf_st_bind_str(sym->st_info),
                 elf_st_type_str(sym->st_info));

        /* 可见性 */
        const char *vis = "DEFAULT";
        if (sym->st_other == 2) vis = "HIDDEN";
        else if (sym->st_other == 3) vis = "PROTECTED";

        snprintf(buf, sizeof(buf),
                 "[%5d] %-12s %4s 0x%lX %6lu %-32s  shndx=%d",
                 i, bind_type, vis,
                 (unsigned long)sym->st_value,
                 (unsigned long)sym->st_size,
                 name[0] ? name : "(null)",
                 sym->st_shndx);
        fields_add(pd, buf, 0, 1, DETAIL_SYM, i);
    }

    if (sym_count > 50000) {
        fields_add(pd, "... (truncated, showing first 50000 symbols)",
                   0, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}

/* ── 公共接口 ────────────────────────────────────────────────────── */

int parse_symtab(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    if (g_active_db) {
        /* 根据 shdr_idx 确定是 .dynsym 还是 .symtab */
        Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
        const char *table_name = ".symtab";
        if (sh && sh->sh_type == SHT_DYNSYM) table_name = ".dynsym";
        return parse_symtab_db(g_active_db, table_name, pd);
    }
    return parse_symtab_mmap(ctx, shdr_idx, pd);
}

int parse_sym_detail(Elf64_Ctx *ctx, int shdr_idx,
                     int sym_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    Elf64_Off stroff = 0;
    Elf64_Shdr *str_shdr = elf_get_shdr(ctx, sh->sh_link);
    if (str_shdr) stroff = str_shdr->sh_offset;

    Elf64_Sym *syms = (Elf64_Sym*)(ctx->map + sh->sh_offset);
    Elf64_Sym *sym = &syms[sym_idx];
    const char *name = (sym->st_name && stroff)
        ? elf_strtab_get(ctx, stroff, sym->st_name) : "";
    char buf[256];

    snprintf(buf, sizeof(buf), "=== Symbol [%d]: %s ===",
             sym_idx, name[0] ? name : "(null)");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "st_name:  0x%08X -> \"%s\"",
             sym->st_name, name[0] ? name : "(null)");
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    unsigned char bind = ELF64_ST_BIND(sym->st_info);
    unsigned char type = ELF64_ST_TYPE(sym->st_info);
    snprintf(buf, sizeof(buf), "st_info:  0x%02X -> bind=%s(%d) type=%s(%d)",
             sym->st_info,
             elf_st_bind_str(sym->st_info), bind,
             elf_st_type_str(sym->st_info), type);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    const char *vis_str = "STV_DEFAULT";
    if (sym->st_other == 2) vis_str = "STV_HIDDEN";
    else if (sym->st_other == 3) vis_str = "STV_PROTECTED";
    snprintf(buf, sizeof(buf), "st_other: 0x%02X -> %s", sym->st_other, vis_str);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 特殊节索引 */
    const char *shndx_str = "";
    if (sym->st_shndx == SHN_UNDEF)  shndx_str = " (SHN_UNDEF)";
    else if (sym->st_shndx == SHN_ABS)    shndx_str = " (SHN_ABS)";
    else if (sym->st_shndx == SHN_COMMON) shndx_str = " (SHN_COMMON)";
    snprintf(buf, sizeof(buf), "st_shndx: 0x%04X%s", sym->st_shndx, shndx_str);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "st_value: 0x%lX",
             (unsigned long)sym->st_value);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "st_size:  %lu bytes",
             (unsigned long)sym->st_size);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    fields_add(pd, "--- Symbol Meaning ---", 1, 0, DETAIL_NONE, -1);
    switch (type) {
        case STT_FUNC:
            fields_add(pd, "This is a FUNCTION symbol (code entry point)", 2, 0, DETAIL_NONE, -1);
            break;
        case STT_OBJECT:
            fields_add(pd, "This is an OBJECT symbol (data storage)", 2, 0, DETAIL_NONE, -1);
            break;
        case STT_SECTION:
            fields_add(pd, "This is a SECTION symbol (section association)", 2, 0, DETAIL_NONE, -1);
            break;
        case STT_FILE:
            fields_add(pd, "This is a FILE symbol (source file name)", 2, 0, DETAIL_NONE, -1);
            break;
        case STT_TLS:
            fields_add(pd, "This is a TLS symbol (thread-local storage)", 2, 0, DETAIL_NONE, -1);
            break;
        default:
            break;
    }

    return pd->count;
}
