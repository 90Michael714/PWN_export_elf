/*
 * decompile.c — 运行时地址反编译引擎 v7
 *
 * 核心理念:
 *   1. 必须 attach 到进程才能工作 (需要 /proc/PID/maps 计算 load_base)
 *   2. 真实地址 = load_base + 静态偏移
 *   3. 中间面板: 列出所有符号 (FUNC/OBJECT/字符串/PLT), 显示真实地址
 *   4. 右侧面板: 对选定地址展示完整详情 —
 *      节归属 + 符号信息 + 反汇编(真实地址+符号标注) + 交叉引用
 *
 * 全局变量: decompile_load_base (由 btn_decompile_action 设置)
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern AnalysisDB *g_active_db;
uint64_t decompile_load_base = 0;

/* ── 地址转换 ── */
static uint64_t real_a(uint64_t static_a) {
    return decompile_load_base + static_a;
}

/* ═══════════════════════════════════════════════════════════════════
 * Phase 1: 中间面板 — 全部符号/地址统一列表 (以真实地址排序)
 * ═════════════════════════════════════════════════════════════════ */

int parse_decompile(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)ctx; (void)shdr_idx;
    if (!g_active_db) {
        fields_add(pd, "(DB not available)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) { fields_add(pd, "(DB connection failed)", 0, 0, DETAIL_NONE, -1); return 0; }

    char buf[512];
    int total = 0;

    /* ── 标题 — 必须包含 "Decompile" 让 Enter 处理器匹配 ── */
    snprintf(buf, sizeof(buf),
        "=== Decompile — runtime addrs (base +0x%lx) ===",
        (unsigned long)decompile_load_base);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (decompile_load_base == 0)
        fields_add(pd, "(base=0 → non-PIE or attach first)", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[F]=func [V]=var [S]=str [P]=PLT  [Enter]=detail → right",
               0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /*
     * ── 1. 全部有名称的符号 (from symbols 表, 按真实地址排序) ──
     *
     * 包括: FUNC(函数), OBJECT(变量), NOTYPE(标记), 以及 PLT 中的函数。
     * 这是最全面的符号列表, 可能数千条。
     */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT s.address, s.name, s.type, s.bind, s.size, "
            "  (SELECT COUNT(*) FROM instructions i WHERE i.address=s.address) as is_code "
            "FROM symbols s "
            "ORDER BY s.address",
            -1, &st, NULL);
        if (st) {
            int n = 0;
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t sa     = (uint64_t)sqlite3_column_int64(st, 0);
                const char *nm  = (const char *)sqlite3_column_text(st, 1);
                const char *tp  = (const char *)sqlite3_column_text(st, 2);
                const char *bd  = (const char *)sqlite3_column_text(st, 3);
                int sz          = sqlite3_column_int(st, 4);
                int is_code     = sqlite3_column_int(st, 5);
                uint64_t ra     = real_a(sa);

                if (!nm || !nm[0]) continue;
                if (sa < 0x100) continue;

                /* 分类标记 */
                char tag[4] = " V ";
                if (tp) {
                    if (!strcmp(tp, "FUNC"))   snprintf(tag, sizeof(tag), "[F]");
                    else if (!strcmp(tp, "OBJECT")) snprintf(tag, sizeof(tag), "[V]");
                    else if (!strcmp(tp, "NOTYPE")) snprintf(tag, sizeof(tag), "[N]");
                    else if (!strcmp(tp, "FILE") || !strcmp(tp, "SECTION"))
                        continue;  /* 跳过文件和节标记 */
                }
                if (is_code && (!tp || strcmp(tp, "FUNC")))
                    snprintf(tag, sizeof(tag), "[C]");  /* 代码但非 FUNC */

                n++;
                snprintf(buf, sizeof(buf),
                    "%s 0x%016lx  %-36s  sz=%-6d  %s",
                    tag, (unsigned long)ra, nm, sz,
                    bd ? bd : "");
                /* 存静态地址到 detail_index (int 足够容纳 ELF 静态地址) */
                fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)sa);
                total++;
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 2. 字符串常量 (不在符号表中的 .rodata 数据) ── */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT s2.address, s2.value, s2.length "
            "FROM strings s2 "
            "WHERE s2.address NOT IN (SELECT address FROM symbols) "
            "  AND s2.address > 0x100 "
            "ORDER BY s2.address",
            -1, &st, NULL);
        if (st) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t sa     = (uint64_t)sqlite3_column_int64(st, 0);
                const char *val = (const char *)sqlite3_column_text(st, 1);
                int len         = sqlite3_column_int(st, 2);
                uint64_t ra     = real_a(sa);

                char preview[44] = "";
                if (val) {
                    int p = 0;
                    for (const char *s = val; *s && p < 40; s++) {
                        if      (*s == '\n') { preview[p++]='\\'; preview[p++]='n'; }
                        else if (*s == '\r') { preview[p++]='\\'; preview[p++]='r'; }
                        else if ((unsigned char)*s >= 32 && (unsigned char)*s < 127)
                            preview[p++] = *s;
                    }
                    preview[p] = '\0';
                }
                snprintf(buf, sizeof(buf),
                    "[S] 0x%016lx  \"%s\"%s  (%dB)",
                    (unsigned long)ra, preview,
                    (val && (int)strlen(val) > 40) ? "..." : "", len);
                fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)sa);
                total++;
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 3. PLT 存根 (符号表中 type=FUNC 且在 .plt 节中) ── */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT s.address, s.name FROM symbols s "
            "JOIN sections sec ON s.address >= sec.addr "
            "  AND s.address < sec.addr + sec.size "
            "WHERE sec.name LIKE '%%plt%%' AND s.type = 'FUNC' "
            "ORDER BY s.address",
            -1, &st, NULL);
        if (st) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t sa    = (uint64_t)sqlite3_column_int64(st, 0);
                const char *nm = (const char *)sqlite3_column_text(st, 1);
                uint64_t ra    = real_a(sa);
                if (!nm || !nm[0]) continue;
                snprintf(buf, sizeof(buf),
                    "[P] 0x%016lx  %-36s  PLT stub", (unsigned long)ra, nm);
                fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)sa);
                total++;
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 底部 ── */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf),
        "── %d total entries (all symbols + strings + PLT) ──", total);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[Enter]=detail  [j/k]=nav  [g]=top  [G]=bottom  [h]=back",
               0, 0, DETAIL_NONE, -1);

    return pd->count;
}

/* ═══════════════════════════════════════════════════════════════════
 * Phase 2: 右面板 — 地址全景详情
 *
 *  1. 节上下文 (哪个节, 类型, 权限)
 *  2. 符号信息 (名称, 类型, 绑定, 大小)
 *  3. 函数详情 (范围, BB, 指令数)
 *  4. 反汇编 (真实地址, 20 条, 含符号标注 call/jmp 目标)
 *  5. 入向交叉引用 (谁引用了我)
 *  6. 出向调用/引用 (我调用了/引用了谁)
 *  7. 字符串内容 (如果这是字符串地址)
 * ═════════════════════════════════════════════════════════════════ */

int decompile_addr_detail(sqlite3 *c, uint64_t static_input_addr, PanelData *pd)
{
    if (!c || !pd) return -1;
    uint64_t sa = static_input_addr;
    uint64_t ra = real_a(sa);
    char buf[512];
    int is_func = 0, is_data = 0;

    /* 清空 */
    if (pd->fields) {
        extern void fields_free(Elf64_Field*, int);
        fields_free(pd->fields, pd->count);
        pd->fields = NULL; pd->count = 0; pd->capacity = 0;
        pd->cursor = 0; pd->scroll = 0; pd->scroll_x = 0;
    }

    /* ── 标题 ── */
    if (decompile_load_base > 0)
        snprintf(buf, sizeof(buf), "▸ 0x%016lx  (static 0x%lx + base 0x%lx)",
                 (unsigned long)ra, (unsigned long)sa,
                 (unsigned long)decompile_load_base);
    else
        snprintf(buf, sizeof(buf), "▸ 0x%016lx  (no ASLR)", (unsigned long)ra);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* ── 没有 DB 数据 ── */
    if (sa < 0x100) {
        fields_add(pd, "(no data for this address range)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    /* ═════════════════════════════════════════════════════════════
     * 1. 节上下文
     * ═════════════════════════════════════════════════════════════ */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT name, type, flags FROM sections "
            "WHERE addr <= ?1 AND (?1 - addr) < size "
            "ORDER BY addr DESC LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *sn = (const char *)sqlite3_column_text(st, 0);
                int stype = sqlite3_column_int(st, 1);
                int sflags = sqlite3_column_int(st, 2);
                char p[8] = "";
                if (sflags & 4) strcat(p, "X");
                if (sflags & 2) strcat(p, "A");
                if (sflags & 1) strcat(p, "W");
                const char *tn = "?";
                switch (stype) {
                    case 1: tn="PROGBITS"; break; case 2: tn="SYMTAB"; break;
                    case 3: tn="STRTAB"; break;   case 4: tn="RELA"; break;
                    case 6: tn="DYNAMIC"; break;  case 7: tn="NOTE"; break;
                    case 8: tn="NOBITS"; break;   case 11: tn="DYNSYM"; break;
                }
                snprintf(buf, sizeof(buf), "── Section ──  %s  %s  %s",
                         sn ? sn : "?", tn, p[0] ? p : "-");
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                snprintf(buf, sizeof(buf), "  static 0x%lx → runtime 0x%lx  offset +0x%lx",
                         (unsigned long)sa, (unsigned long)ra,
                         (unsigned long)(sa - (uint64_t)sqlite3_column_int64(st, 0) /* addr field index */));
                /* 简化: 直接显示偏移 */
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(st);
        }
    }

    /* ═════════════════════════════════════════════════════════════
     * 2. 符号信息
     * ═════════════════════════════════════════════════════════════ */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT name, type, bind, size FROM symbols WHERE address=?1 LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *nm = (const char *)sqlite3_column_text(st, 0);
                const char *tp = (const char *)sqlite3_column_text(st, 1);
                const char *bd = (const char *)sqlite3_column_text(st, 2);
                int sz = sqlite3_column_int(st, 3);
                if (tp && !strcmp(tp, "FUNC")) is_func = 1;
                if (tp && !strcmp(tp, "OBJECT")) is_data = 1;

                snprintf(buf, sizeof(buf), "── Symbol ──");
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                snprintf(buf, sizeof(buf), "  Name: %-36s  Type: %-8s  Bind: %-8s  Size: %d",
                         nm ? nm : "(unnamed)", tp ? tp : "?", bd ? bd : "?", sz);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            } else {
                fields_add(pd, "── Symbol ── (no symbol at this address)", 0, 0, DETAIL_NONE, -1);
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(st);
        }
    }

    /* ═════════════════════════════════════════════════════════════
     * 3. 函数详情 (仅 FUNC)
     * ═════════════════════════════════════════════════════════════ */
    uint64_t func_end = sa;  /* 用于后续范围查询 */
    if (is_func) {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT end_addr, bb_count FROM functions WHERE start_addr=?1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            if (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t se = (uint64_t)sqlite3_column_int64(st, 0);
                int bbc = sqlite3_column_int(st, 1);
                func_end = se;
                uint64_t re = real_a(se);

                int ic = 0;
                sqlite3_stmt *icst = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM instructions WHERE address BETWEEN ?1 AND ?2",
                    -1, &icst, NULL);
                if (icst) {
                    sqlite3_bind_int64(icst, 1, (sqlite3_int64)sa);
                    sqlite3_bind_int64(icst, 2, (sqlite3_int64)se);
                    if (sqlite3_step(icst) == SQLITE_ROW) ic = sqlite3_column_int(icst, 0);
                    sqlite3_finalize(icst);
                }
                snprintf(buf, sizeof(buf), "── Function ──  BBs:%d  Insns:%d  Size:0x%lx",
                         bbc, ic, (unsigned long)(se - sa));
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                snprintf(buf, sizeof(buf), "  static: 0x%lx — 0x%lx", (unsigned long)sa, (unsigned long)se);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                snprintf(buf, sizeof(buf), "  real:   0x%lx — 0x%lx", (unsigned long)ra, (unsigned long)re);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(st);
        }
    }

    /* ═════════════════════════════════════════════════════════════
     * 4. 反汇编 (代码地址时, 显示前 25 条指令, 符号标注调用/跳转目标)
     * ═════════════════════════════════════════════════════════════ */
    {
        sqlite3_stmt *st = NULL;
        int has_disasm = 0;
        sqlite3_prepare_v2(c,
            "SELECT address, mnemonic, op_str, bytes, size FROM instructions "
            "WHERE address >= ?1 ORDER BY address LIMIT 25",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            int n = 0;
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!has_disasm) {
                    snprintf(buf, sizeof(buf), "── Disassembly (real addrs, 25 insns) ──");
                    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                    has_disasm = 1;
                }
                uint64_t ia = (uint64_t)sqlite3_column_int64(st, 0);
                const char *mn = (const char *)sqlite3_column_text(st, 1);
                const char *op = (const char *)sqlite3_column_text(st, 2);
                const uint8_t *by = (const uint8_t *)sqlite3_column_blob(st, 3);
                int bsz = sqlite3_column_bytes(st, 3);
                uint64_t ria = real_a(ia);

                /* 字节 hex */
                char hx[32] = ""; int hp = 0;
                if (by) for (int i = 0; i < bsz && i < 8 && hp < 28; i++)
                    hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, "%02x ", by[i]);

                /* 符号标注: call 0x... / jmp 0x... → 查符号名 */
                char symtag[64] = "";
                if ((!strcmp(mn, "call") || !strncmp(mn, "j", 1)) && op) {
                    uint64_t tgt = (uint64_t)strtoull(op, NULL, 16);
                    if (tgt > 0x100) {
                        sqlite3_stmt *sy = NULL;
                        sqlite3_prepare_v2(c,
                            "SELECT name FROM symbols WHERE address=?1 LIMIT 1",
                            -1, &sy, NULL);
                        if (sy) {
                            sqlite3_bind_int64(sy, 1, (sqlite3_int64)tgt);
                            if (sqlite3_step(sy) == SQLITE_ROW) {
                                const char *sn = (const char *)sqlite3_column_text(sy, 0);
                                if (sn) {
                                    uint64_t rtgt = real_a(tgt);
                                    snprintf(symtag, sizeof(symtag), "  → 0x%lx <%s>",
                                             (unsigned long)rtgt, sn);
                                }
                            }
                            sqlite3_finalize(sy);
                        }
                    }
                }

                /* 如果是数据引用 (lea/mov 含立即数), 查符号 */
                if ((!strcmp(mn, "lea") || !strcmp(mn, "mov")) && op) {
                    const char *comma = strchr(op, ',');
                    const char *src = comma ? comma + 1 : op;
                    while (*src == ' ') src++;
                    if (src[0] == '0' && src[1] == 'x') {
                        uint64_t tgt = (uint64_t)strtoull(src, NULL, 16);
                        if (tgt > 0x100) {
                            sqlite3_stmt *sy = NULL;
                            sqlite3_prepare_v2(c,
                                "SELECT name FROM symbols WHERE address=?1 LIMIT 1",
                                -1, &sy, NULL);
                            if (sy) {
                                sqlite3_bind_int64(sy, 1, (sqlite3_int64)tgt);
                                if (sqlite3_step(sy) == SQLITE_ROW) {
                                    const char *sn = (const char *)sqlite3_column_text(sy, 0);
                                    if (sn && !symtag[0]) {
                                        uint64_t rtgt = real_a(tgt);
                                        snprintf(symtag, sizeof(symtag), "  ; &0x%lx <%s>",
                                                 (unsigned long)rtgt, sn);
                                    }
                                }
                                sqlite3_finalize(sy);
                            }
                            /* 也检查字符串 */
                            if (!symtag[0]) {
                                sqlite3_stmt *ss = NULL;
                                sqlite3_prepare_v2(c,
                                    "SELECT value FROM strings WHERE address=?1 LIMIT 1",
                                    -1, &ss, NULL);
                                if (ss) {
                                    sqlite3_bind_int64(ss, 1, (sqlite3_int64)tgt);
                                    if (sqlite3_step(ss) == SQLITE_ROW) {
                                        const char *sv = (const char *)sqlite3_column_text(ss, 0);
                                        if (sv) {
                                            char pv[48]; int pp = 0;
                                            for (const char *sp = sv; *sp && pp < 44; sp++) {
                                                if (*sp == '\n') { pv[pp++]='\\'; pv[pp++]='n'; }
                                                else if ((unsigned char)*sp >= 32) pv[pp++] = *sp;
                                            }
                                            pv[pp] = '\0';
                                            snprintf(symtag, sizeof(symtag), "  ; \"%s\"", pv);
                                        }
                                    }
                                    sqlite3_finalize(ss);
                                }
                            }
                        }
                    }
                }

                char marker = (ia == sa) ? '>' : ' ';
                snprintf(buf, sizeof(buf), "  %c 0x%lx: %-20s %-8s %-20s%s",
                         marker, (unsigned long)ria, hx,
                         mn ? mn : "?", op ? op : "", symtag);
                fields_add(pd, buf, 1, (ia == sa) ? 1 : 0, DETAIL_NONE, -1);
                n++;
            }
            if (has_disasm) fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            sqlite3_finalize(st);
        }
        if (!has_disasm && !is_func && !is_data) {
            fields_add(pd, "── Disassembly ── (not a known code address)", 0, 0, DETAIL_NONE, -1);
            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        }
    }

    /* ═════════════════════════════════════════════════════════════
     * 5. 入向交叉引用 (谁引用了这个地址)
     * ═════════════════════════════════════════════════════════════ */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT x.from_addr, x.ref_type, COALESCE(s.name, '') "
            "FROM xrefs x "
            "LEFT JOIN symbols s ON s.address = x.from_addr "
            "WHERE x.to_addr = ?1 ORDER BY x.from_addr LIMIT 32",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            int first = 1, n = 0;
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (first) {
                    snprintf(buf, sizeof(buf), "── Incoming XRefs (who references this) ──");
                    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                    first = 0;
                }
                uint64_t fr = (uint64_t)sqlite3_column_int64(st, 0);
                const char *rt = (const char *)sqlite3_column_text(st, 1);
                const char *sn = (const char *)sqlite3_column_text(st, 2);
                uint64_t rfr = real_a(fr);
                if (sn && sn[0])
                    snprintf(buf, sizeof(buf), "  ← 0x%lx  %-10s <%s>",
                             (unsigned long)rfr, rt ? rt : "", sn);
                else
                    snprintf(buf, sizeof(buf), "  ← 0x%lx  %-10s",
                             (unsigned long)rfr, rt ? rt : "");
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                n++;
            }
            if (first)
                fields_add(pd, "── Incoming XRefs ── (none)", 0, 0, DETAIL_NONE, -1);
            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            sqlite3_finalize(st);
        }
    }

    /* ═════════════════════════════════════════════════════════════
     * 6. 出向引用 (函数调用 + 数据/字符串引用)
     * ═════════════════════════════════════════════════════════════ */
    {
        uint64_t fe = sa + 0x10000;
        if (is_func) {
            sqlite3_stmt *fs = NULL;
            sqlite3_prepare_v2(c,
                "SELECT end_addr FROM functions WHERE start_addr=?1", -1, &fs, NULL);
            if (fs) {
                sqlite3_bind_int64(fs, 1, (sqlite3_int64)sa);
                if (sqlite3_step(fs) == SQLITE_ROW) fe = (uint64_t)sqlite3_column_int64(fs, 0);
                sqlite3_finalize(fs);
            }
        }
        int shown = 0;

        /* 6a. call 目标 */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT e.to_addr, COALESCE(s.name, '') "
            "FROM cfg_edges e "
            "LEFT JOIN symbols s ON s.address = e.to_addr "
            "WHERE e.from_addr BETWEEN ?1 AND ?2 AND e.edge_type = 'call' "
            "ORDER BY e.from_addr LIMIT 64",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)fe);
            while (sqlite3_step(st) == SQLITE_ROW) {
                if (!shown) {
                    snprintf(buf, sizeof(buf), "── Outgoing (calls / refs from here) ──");
                    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                    shown = 1;
                }
                uint64_t to = (uint64_t)sqlite3_column_int64(st, 0);
                const char *sn = (const char *)sqlite3_column_text(st, 1);
                uint64_t rto = real_a(to);
                if (sn && sn[0])
                    snprintf(buf, sizeof(buf), "  → 0x%lx  CALL  %s", (unsigned long)rto, sn);
                else
                    snprintf(buf, sizeof(buf), "  → 0x%lx  CALL  sub_%lx", (unsigned long)rto, (unsigned long)to);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(st);
        }

        /* 6b. 数据引用 */
        sqlite3_stmt *xr = NULL;
        sqlite3_prepare_v2(c,
            "SELECT x.to_addr, x.ref_type, "
            "  COALESCE((SELECT name FROM symbols WHERE address=x.to_addr), "
            "           (SELECT value FROM strings WHERE address=x.to_addr), '') "
            "FROM xrefs x "
            "WHERE x.from_addr BETWEEN ?1 AND ?2 AND x.ref_type != 'call' "
            "ORDER BY x.from_addr LIMIT 64",
            -1, &xr, NULL);
        if (xr) {
            sqlite3_bind_int64(xr, 1, (sqlite3_int64)sa);
            sqlite3_bind_int64(xr, 2, (sqlite3_int64)fe);
            while (sqlite3_step(xr) == SQLITE_ROW) {
                if (!shown) {
                    snprintf(buf, sizeof(buf), "── Outgoing (calls / refs from here) ──");
                    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                    shown = 1;
                }
                uint64_t to = (uint64_t)sqlite3_column_int64(xr, 0);
                const char *rt = (const char *)sqlite3_column_text(xr, 1);
                const char *tg = (const char *)sqlite3_column_text(xr, 2);
                uint64_t rto = real_a(to);
                if (tg && tg[0]) {
                    char pv[48]; int pp = 0;
                    for (const char *sp = tg; *sp && pp < 40; sp++) {
                        if (*sp == '\n') { pv[pp++]='\\'; pv[pp++]='n'; }
                        else if ((unsigned char)*sp >= 32) pv[pp++] = *sp;
                    }
                    pv[pp] = '\0';
                    snprintf(buf, sizeof(buf), "  → 0x%lx  %-6s  \"%s\"",
                             (unsigned long)rto, rt ? rt : "data", pv);
                } else {
                    snprintf(buf, sizeof(buf), "  → 0x%lx  %-6s",
                             (unsigned long)rto, rt ? rt : "data");
                }
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(xr);
        }
        if (shown) fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    }

    /* ═════════════════════════════════════════════════════════════
     * 7. 字符串内容 (如果这是字符串地址)
     * ═════════════════════════════════════════════════════════════ */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT value, length FROM strings WHERE address=?1", -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)sa);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *val = (const char *)sqlite3_column_text(st, 0);
                int len = sqlite3_column_int(st, 1);
                snprintf(buf, sizeof(buf), "── String @ 0x%lx (%dB) ──", (unsigned long)ra, len);
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                if (val && val[0]) {
                    char escaped[300]; int ep = 0;
                    for (const char *s = val; *s && ep < 290; s++) {
                        if (*s == '\n')      { escaped[ep++]='\\'; escaped[ep++]='n'; }
                        else if (*s == '\r') { escaped[ep++]='\\'; escaped[ep++]='r'; }
                        else if (*s == '\t') { escaped[ep++]='\\'; escaped[ep++]='t'; }
                        else if (*s == '\\') { escaped[ep++]='\\'; escaped[ep++]='\\'; }
                        else if (*s == '"')  { escaped[ep++]='\\'; escaped[ep++]='"'; }
                        else if ((unsigned char)*s >= 32) escaped[ep++] = *s;
                    }
                    escaped[ep] = '\0';
                    snprintf(buf, sizeof(buf), "  \"%s\"", escaped);
                    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                }
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 底部 ── */
    fields_add(pd, "── [h]=back  [g]=top  [G]=bottom ──", 0, 0, DETAIL_NONE, -1);
    return pd->count;
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int decompile_function_at(uint64_t func_addr, PanelData *pd)
{
    if (!g_active_db) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) return -1;
    return decompile_addr_detail(c, func_addr, pd);
}
