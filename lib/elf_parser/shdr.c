/*
 * shdr.c — Section Headers 解析
 *
 * parse_shdr_list:  左侧面板节列表
 * parse_shdr_detail: 中间面板 — 节概览 (ELF字段 + DB内容统计)
 *
 * 中间面板选中可选项 → 右侧面板显示 DB 查询详情
 * (通过 tui_input.c 中已有的 Enter 处理器)
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern AnalysisDB *g_active_db;

int parse_shdr_list(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int shnum = ehdr->e_shnum;
    char flags_buf[32];

    fields_add(pd, "=== Section Headers ===", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        const char *name = elf_section_name(ctx, i);
        char buf[256];

        snprintf(buf, sizeof(buf), "[%02d] %-24s  %s  %s  size=0x%lX",
                 i, name,
                 elf_sh_type_str(sh->sh_type),
                 elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf)),
                 (unsigned long)sh->sh_size);
        fields_add(pd, buf, 0, 1, DETAIL_SHDR, i);
    }

    return pd->count;
}

int parse_shdr_detail(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *name = elf_section_name(ctx, shdr_idx);
    char flags_buf[32];
    char buf[512];

    /* ── 标题 ── */
    snprintf(buf, sizeof(buf), "=== Section [%02d]: %s ===", shdr_idx, name);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* ── ELF 节头字段 ── */
    fields_add(pd, "── ELF Section Header ──", 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_name:      0x%08X (\"%s\")", sh->sh_name, name);
    fields_add(pd, buf, 1, 1, DETAIL_SHDR, shdr_idx);

    snprintf(buf, sizeof(buf), "sh_type:      0x%08X — %s",
             sh->sh_type, elf_sh_type_str(sh->sh_type));
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf));
    snprintf(buf, sizeof(buf), "sh_flags:     0x%lX (%s)",
             (unsigned long)sh->sh_flags, flags_buf);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addr:      0x%lX  (virtual address in memory)",
             (unsigned long)sh->sh_addr);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_offset:    0x%lX  (%lu bytes into file)",
             (unsigned long)sh->sh_offset, (unsigned long)sh->sh_offset);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_size:      0x%lX  (%lu bytes)",
             (unsigned long)sh->sh_size, (unsigned long)sh->sh_size);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addralign: 0x%lX", (unsigned long)sh->sh_addralign);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (sh->sh_entsize > 0) {
        int entries = (int)(sh->sh_size / sh->sh_entsize);
        snprintf(buf, sizeof(buf), "sh_entsize:   %lu  →  %d entries",
                 (unsigned long)sh->sh_entsize, entries);
    } else {
        snprintf(buf, sizeof(buf), "sh_entsize:   %lu  (no fixed-size entries)",
                 (unsigned long)sh->sh_entsize);
    }
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_link:      %d  sh_info: %d", sh->sh_link, sh->sh_info);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* ── sh_link/sh_info 解读 ── */
    switch (sh->sh_type) {
        case SHT_SYMTAB: case SHT_DYNSYM:
            snprintf(buf, sizeof(buf), "→ link=[%d]=strtab, info=[%d]=1st non-local",
                     sh->sh_link, sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_RELA: case SHT_REL:
            snprintf(buf, sizeof(buf), "→ link=[%d]=symtab, info=[%d]=target section",
                     sh->sh_link, sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_DYNAMIC:
            snprintf(buf, sizeof(buf), "→ link=[%d]=dynstr", sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_HASH: case SHT_GNU_HASH:
            snprintf(buf, sizeof(buf), "→ link=[%d]=dynsym", sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
    }

    /* ═════════════════════════════════════════════════════════════
     * DB 内容统计 (如果有 DB)
     * ═════════════════════════════════════════════════════════════ */
    if (g_active_db && sh->sh_addr > 0 && sh->sh_size > 0) {
        sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
        if (c) {
            uint64_t low = sh->sh_addr, high = sh->sh_addr + sh->sh_size;

            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            fields_add(pd, "── Section Contents (from analysis DB) ──", 0, 0, DETAIL_NONE, -1);

            /* 指令数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM instructions WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int ic = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Instructions:  %d", ic);
                        fields_add(pd, buf, 1, ic > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 函数数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM functions WHERE start_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int fc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Functions:     %d", fc);
                        fields_add(pd, buf, 1, fc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 符号数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM symbols WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int sc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Symbols:       %d", sc);
                        fields_add(pd, buf, 1, sc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 字符串数 (.rodata 等) */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM strings WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int strc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Strings:       %d", strc);
                        fields_add(pd, buf, 1, strc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 基本块数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM basic_blocks WHERE start_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int bbc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Basic Blocks:  %d", bbc);
                        fields_add(pd, buf, 1, bbc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 交叉引用数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM xrefs WHERE from_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int xrc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  XRefs (out):   %d", xrc);
                        fields_add(pd, buf, 1, xrc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 字节范围 */
            snprintf(buf, sizeof(buf), "  Address range: 0x%lx — 0x%lx  (%lu bytes)",
                     (unsigned long)low, (unsigned long)high, (unsigned long)sh->sh_size);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    } else if (sh->sh_addr > 0 && sh->sh_size > 0) {
        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        snprintf(buf, sizeof(buf), "(DB not available — import ELF first for content stats)");
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    /* ── 底部: 常用操作提示 ── */
    if (sh->sh_type == SHT_PROGBITS && (sh->sh_flags & 4 /* SHF_EXECINSTR */)) {
        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        fields_add(pd, "→ Use Code Analysis → Disasm for full disassembly", 1, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}
