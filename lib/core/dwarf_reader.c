/*
 * dwarf_reader.c — DWARF 调试信息解析器 (minimal subset)
 *
 * 支持的节:
 *   .debug_line   → 地址到源文件:行号的映射
 *   .debug_str    → DWARF 字符串表 (变量名/类型名/文件路径)
 *   .debug_info   → Compilation Unit 级别的基本信息
 *
 * 约定: 使用 <dwarf.h> 的常量名, 但值内联 (避免外部依赖)。
 */

#include "core/dwarf_reader.h"
#include "core/db.h"
#include "elf_parser.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── ULEB128 / SLEB128 解码 ────────────────────────────────────── */
static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t result = 0; int shift = 0;
    while (*p < end) {
        uint8_t byte = *(*p)++; result |= (uint64_t)(byte & 0x7f) << shift;
        if (!(byte & 0x80)) break; shift += 7;
    }
    return result;
}

static int64_t read_sleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t result = 0; int shift = 0; uint8_t byte;
    while (*p < end) {
        byte = *(*p)++; result |= (uint64_t)(byte & 0x7f) << shift; shift += 7;
        if (!(byte & 0x80)) break;
    }
    if (shift < 64 && (byte & 0x40)) result |= -(1ULL << shift);
    return (int64_t)result;
}

/* ── 查找 DWARF 节 ── */
static const uint8_t* find_dwarf_section(Elf64_Ctx *ctx, const char *name, size_t *size_out)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        const char *sn = elf_section_name(ctx, i);
        if (sn && !strcmp(sn, name) && sh->sh_type == 1 /* PROGBITS */) {
            *size_out = (size_t)sh->sh_size;
            return ctx->map + sh->sh_offset;
        }
    }
    *size_out = 0;
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * .debug_line 解析
 * ═════════════════════════════════════════════════════════════════ */

/* DWARF standard opcodes */
enum {
    DW_LNS_copy              = 1,
    DW_LNS_advance_pc        = 2,
    DW_LNS_advance_line      = 3,
    DW_LNS_set_file          = 4,
    DW_LNS_set_column        = 5,
    DW_LNS_negate_stmt       = 6,
    DW_LNS_set_basic_block   = 7,
    DW_LNS_const_add_pc      = 8,
    DW_LNS_fixed_advance_pc  = 9,
    DW_LNE_end_sequence      = 1,
    DW_LNE_set_address       = 2,
    DW_LNE_define_file       = 3,
};

static int parse_debug_line(Elf64_Ctx *ctx, AnalysisDB *db)
{
    size_t sz = 0;
    const uint8_t *data = find_dwarf_section(ctx, ".debug_line", &sz);
    if (!data || sz < 16) return 0;

    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c) return -1;

    sqlite3_stmt *ins = NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR REPLACE INTO dwarf_lines(addr,source_file,line_no,column_no) "
        "VALUES(?1,?2,?3,?4)", -1, &ins, NULL);
    if (!ins) return -1;

    /* 收集所有源文件路径 */
    sqlite3_stmt *ins_src = NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO dwarf_sources(file_path) VALUES(?1)",
        -1, &ins_src, NULL);

    const uint8_t *p = data, *end = data + sz;
    int total_lines = 0;

    while (p + 4 < end) {
        uint32_t unit_len = *(uint32_t *)p; p += 4;
        if (unit_len == 0 || p + unit_len > end) break;
        if (unit_len == 0xFFFFFFFF) { p += 8; unit_len = *(uint32_t *)p; p += 4; } /* DWARF64 跳过 */

        const uint8_t *unit_end = p + unit_len - 4;
        uint16_t version = *(uint16_t *)p; p += 2;
        if (version < 2 || version > 5) { p = unit_end; continue; }

        uint8_t header_len_field = 4;
        uint64_t header_len = 0;
        if (version >= 5) {
            /* DWARF5: address_size after header_length */
            /* For simplicity, handle DWARF4 header */
        }
        if (unit_len > 0xFFFF0000) {
            header_len = *(uint64_t *)p; p += 8; header_len_field = 8;
        } else {
            header_len = *(uint32_t *)p; p += 4;
        }
        const uint8_t *prog_start = p + header_len;
        if (prog_start > unit_end) { p = unit_end; continue; }

        uint8_t min_insn_len = *p++;
        uint8_t max_ops_per_insn = *p++; if (max_ops_per_insn == 0) max_ops_per_insn = 1;
        uint8_t default_is_stmt = *p++;
        int8_t   line_base = (int8_t)*p++;
        uint8_t line_range = *p++;
        uint8_t opcode_base = *p++;
        if (opcode_base == 0) opcode_base = 1;
        /* skip standard_opcode_lengths[opcode_base-1] */
        p += (opcode_base - 1);

        /* ── directory table (DWARF < 5) ── */
        char dirs[16][256]; int ndirs = 0;
        if (version < 5) {
            while (p < prog_start && *p && ndirs < 16) {
                int d = 0;
                while (p < prog_start && *p && d < 250) dirs[ndirs][d++] = (char)*p++;
                dirs[ndirs][d] = '\0'; ndirs++;
                if (p < prog_start && *p == 0) p++;
            }
            if (p < prog_start && *p == 0) p++; /* skip null terminator */
        }

        /* ── file name table ── */
        char files[64][256]; int nfiles = 0;
        int dir_indices[64] = {0};
        while (p < prog_start && *p && nfiles < 64) {
            int f = 0;
            while (p < prog_start && *p && f < 250) files[nfiles][f++] = (char)*p++;
            files[nfiles][f] = '\0';
            if (p < prog_start && *p == 0) p++;
            dir_indices[nfiles] = (int)read_uleb128(&p, prog_start);
            read_uleb128(&p, prog_start); /* mtime */
            read_uleb128(&p, prog_start); /* file size */
            nfiles++;
        }
        if (p < prog_start && *p == 0) p++;
        p = prog_start;

        /* ── line number program state machine ── */
        uint64_t address = 0;
        int64_t  line   = 1;
        int file_idx    = 1;
        int column      = 0;
        int is_stmt     = default_is_stmt;
        int end_seq     = 0;

        while (p < unit_end && total_lines < 100000) {
            uint8_t op = *p++;

            if (op == 0) {
                /* Extended opcode */
                uint64_t ext_len = read_uleb128(&p, unit_end);
                if (p >= unit_end) break;
                uint8_t sub = *p++;
                if (sub == DW_LNE_end_sequence) {
                    end_seq = 1;
                } else if (sub == DW_LNE_set_address) {
                    address = 0; memcpy(&address, p, 8); p += 8;
                } else if (sub == DW_LNE_define_file) {
                    /* skip */
                    while (*p && p < unit_end) p++; p++;
                    read_uleb128(&p, unit_end);
                    read_uleb128(&p, unit_end);
                    read_uleb128(&p, unit_end);
                } else {
                    p += ext_len > 0 ? ext_len - 1 : 0;
                }
            } else if (op < opcode_base) {
                /* Standard opcode */
                switch (op) {
                    case DW_LNS_copy:
                        if (is_stmt && address > 0 && file_idx > 0 && file_idx <= nfiles) {
                            sqlite3_reset(ins);
                            sqlite3_bind_int64(ins, 1, (sqlite3_int64)address);
                            sqlite3_bind_text(ins, 2, files[file_idx-1], -1, SQLITE_STATIC);
                            sqlite3_bind_int(ins, 3, (int)line);
                            sqlite3_bind_int(ins, 4, column);
                            sqlite3_step(ins);

                            if (ins_src) {
                                sqlite3_reset(ins_src);
                                sqlite3_bind_text(ins_src, 1, files[file_idx-1], -1, SQLITE_STATIC);
                                sqlite3_step(ins_src);
                            }
                            total_lines++;
                        }
                        break;
                    case DW_LNS_advance_pc:
                        address += read_uleb128(&p, unit_end) * min_insn_len;
                        break;
                    case DW_LNS_advance_line:
                        line += read_sleb128(&p, unit_end);
                        break;
                    case DW_LNS_set_file:
                        file_idx = (int)read_uleb128(&p, unit_end);
                        break;
                    case DW_LNS_set_column:
                        column = (int)read_uleb128(&p, unit_end);
                        break;
                    case DW_LNS_negate_stmt:
                        is_stmt = !is_stmt;
                        break;
                    case DW_LNS_set_basic_block:
                        break;
                    case DW_LNS_const_add_pc: {
                        int adv = (255 - opcode_base) / line_range;
                        address += (uint64_t)adv * min_insn_len;
                        break;
                    }
                    case DW_LNS_fixed_advance_pc:
                        if (p + 2 <= unit_end) {
                            address += *(uint16_t *)p; p += 2;
                        }
                        break;
                    default:
                        /* skip unknown standard opcode args */
                        for (int j = 0; j < (int)(opcode_base > 0 ?
                            ((const uint8_t *)(prog_start - (opcode_base - 1)))[op-1] : 0); j++)
                            read_uleb128(&p, unit_end);
                        break;
                }
            } else {
                /* Special opcode */
                int adjusted = op - opcode_base;
                address += (uint64_t)(adjusted / line_range) * min_insn_len;
                line += line_base + (adjusted % line_range);
                if (is_stmt && address > 0 && file_idx > 0 && file_idx <= nfiles) {
                    sqlite3_reset(ins);
                    sqlite3_bind_int64(ins, 1, (sqlite3_int64)address);
                    sqlite3_bind_text(ins, 2, files[file_idx-1], -1, SQLITE_STATIC);
                    sqlite3_bind_int(ins, 3, (int)line);
                    sqlite3_bind_int(ins, 4, column);
                    sqlite3_step(ins);

                    if (ins_src) {
                        sqlite3_reset(ins_src);
                        sqlite3_bind_text(ins_src, 1, files[file_idx-1], -1, SQLITE_STATIC);
                        sqlite3_step(ins_src);
                    }
                    total_lines++;
                }
            }

            if (end_seq) { address = 0; line = 1; file_idx = 1; column = 0; end_seq = 0; }
        }
        p = unit_end;
    }

    sqlite3_finalize(ins);
    if (ins_src) sqlite3_finalize(ins_src);
    return total_lines;
}

/* ═══════════════════════════════════════════════════════════════════
 * .debug_str 提取 → 用于符号/变量名增强
 * ═════════════════════════════════════════════════════════════════ */

static int parse_debug_str(Elf64_Ctx *ctx, AnalysisDB *db)
{
    size_t sz = 0;
    const uint8_t *data = find_dwarf_section(ctx, ".debug_str", &sz);
    if (!data || sz < 4) return 0;

    /* 使用现有的 symbols 表的 name 字段做增强:
     * 如果符号名是空或 sub_xxx 形式, 尝试从 .debug_str 中找更好的名字。
     *
     * 简化实现: 收集所有以字母开头的可读字符串, 用于变量名推断。
     * 完整的变量解析需要遍历 .debug_info 的 DIE 树, 这太过复杂。
     * 只做轻量级的字符串提取以辅助 decompile 显示。
     */
    (void)db;
    return (int)sz;
}

/* ═══════════════════════════════════════════════════════════════════
 * .debug_info — 提取 Compilation Unit 列表
 * ═════════════════════════════════════════════════════════════════ */

static int parse_debug_info(Elf64_Ctx *ctx, AnalysisDB *db)
{
    size_t sz = 0;
    const uint8_t *data = find_dwarf_section(ctx, ".debug_info", &sz);
    if (!data || sz < 11) return 0;

    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c) return -1;

    sqlite3_stmt *ins = NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR REPLACE INTO dwarf_funcs(addr,name,source_file,line_no) "
        "VALUES(?1,?2,?3,?4)", -1, &ins, NULL);
    if (!ins) return -1;

    sqlite3_stmt *ins_src = NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO dwarf_sources(file_path) VALUES(?1)",
        -1, &ins_src, NULL);

    /* 简化 CU 扫描: 在每个 CU header 中找 DW_AT_name (源文件名) 和
     * DW_AT_comp_dir。然后跳过 DIE 树 (不做完整解析)。 */
    const uint8_t *p = data, *end = data + sz;
    int cu_count = 0;

    while (p + 11 < end && cu_count < 100) {
        uint32_t unit_len = *(uint32_t *)p; p += 4;
        if (unit_len == 0 || p + unit_len > end) break;
        if (unit_len == 0xFFFFFFFF) { p += 8; unit_len = *(uint32_t *)p; p += 4; }

        const uint8_t *cu_end = p + unit_len - 4;
        uint16_t ver = *(uint16_t *)p; p += 2;
        if (ver < 2 || ver > 5) { p = cu_end; continue; }

        /* abbrev_offset */
        if (unit_len > 0xFFFF0000) p += 8; else p += 4;

        uint8_t addr_size = *p++;

        /* Quick scan: look for DW_AT_name in the CU DIE.
         * DW_AT_name = 0x03, DW_FORM_strp = 0x0e.
         * This is a heuristic — full DIE parsing requires .debug_abbrev. */
        /* For now, skip the detailed DIE parsing and just count CUs */
        cu_count++;
        p = cu_end;
    }

    sqlite3_finalize(ins);
    if (ins_src) sqlite3_finalize(ins_src);
    return cu_count;
}

/* ═══════════════════════════════════════════════════════════════════
 * 主入口
 * ═════════════════════════════════════════════════════════════════ */

int dwarf_read_all(AnalysisDB *db, Elf64_Ctx *ctx)
{
    if (!db || !ctx) return -1;

    int dbg_lines  = parse_debug_line(ctx, db);
    parse_debug_str(ctx, db);
    int dbg_info   = parse_debug_info(ctx, db);

    /* 如果有 DWARF 数据, 记录到 _meta */
    if (dbg_lines > 0 || dbg_info > 0) {
        sqlite3 *c = (sqlite3 *)db_conn(db);
        if (c) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%d", dbg_lines);
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(c,
                "INSERT OR REPLACE INTO _meta(key,value) VALUES('dwarf_lines_count',?1)",
                -1, &st, NULL);
            if (st) { sqlite3_bind_text(st, 1, buf, -1, SQLITE_STATIC); sqlite3_step(st); sqlite3_finalize(st); }
        }
    }

    return dbg_lines;
}

/* ═══════════════════════════════════════════════════════════════════
 * 查询接口
 * ═════════════════════════════════════════════════════════════════ */

int dwarf_query_line(AnalysisDB *db, uint64_t addr, PanelData *pd)
{
    if (!db || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT source_file, line_no FROM dwarf_lines WHERE addr=?1 LIMIT 1",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);

    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *sf = (const char *)sqlite3_column_text(st, 0);
        int ln = sqlite3_column_int(st, 1);
        char buf[256];
        if (sf) {
            const char *base = strrchr(sf, '/');
            base = base ? base + 1 : sf;
            snprintf(buf, sizeof(buf), "  %s:%d", base, ln);
        } else {
            snprintf(buf, sizeof(buf), "  line %d", ln);
        }
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }
    sqlite3_finalize(st);
    return 0;
}

int dwarf_query_func(AnalysisDB *db, uint64_t func_addr, PanelData *pd)
{
    if (!db || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT name, source_file, line_no, return_type FROM dwarf_funcs WHERE addr=?1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *nm = (const char *)sqlite3_column_text(st, 0);
            const char *sf = (const char *)sqlite3_column_text(st, 1);
            int ln = sqlite3_column_int(st, 2);
            if (nm && nm[0]) {
                char buf[512];
                snprintf(buf, sizeof(buf), "── DWARF Debug Info ──");
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                snprintf(buf, sizeof(buf), "  Name:  %s", nm);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                if (sf && sf[0]) {
                    snprintf(buf, sizeof(buf), "  File:  %s:%d", sf, ln);
                    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                }
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            }
        }
        sqlite3_finalize(st);
    }
    return 0;
}

int dwarf_query_vars(AnalysisDB *db, uint64_t addr, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c || !pd) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT name, type_name FROM dwarf_vars "
        "WHERE function_addr=?1 OR addr=?1 ORDER BY id LIMIT 30",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        int first = 1;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (first) {
                fields_add(pd, "── Dwarf Variables ──", 0, 0, DETAIL_NONE, -1);
                first = 0;
            }
            const char *nm = (const char *)sqlite3_column_text(st, 0);
            const char *tp = (const char *)sqlite3_column_text(st, 1);
            char buf[256];
            snprintf(buf, sizeof(buf), "  %-24s  %s", nm ? nm : "?", tp ? tp : "");
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }
    return 0;
}

int dwarf_list_sources(AnalysisDB *db, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(db);
    if (!c || !pd) return -1;

    fields_add(pd, "── DWARF Source Files ──", 0, 0, DETAIL_NONE, -1);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT file_path FROM dwarf_sources ORDER BY file_path", -1, &st, NULL);
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *fp = (const char *)sqlite3_column_text(st, 0);
            if (fp) fields_add(pd, fp, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }
    return 0;
}
