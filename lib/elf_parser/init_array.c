/*
 * init_array.c — .init_array/.fini_array/.preinit_array 展开 (v2 — DB优先)
 *
 * 解析构造函数/析构函数指针数组。
 *
 * 双路径:
 *   DB 路径: symbols 表 O(log n) 符号解析 + xrefs 危险调用检测
 *   mmap 路径: 遍历 .symtab/.dynsym 做符号解析 (原有逻辑, DB 不可用时降级)
 *
 * 接口: int parse_init_array(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* DB 符号解析: O(log n) 查询                                         */
/* ================================================================== */

static const char *db_lookup_sym(AnalysisDB *adb, Elf64_Addr addr,
                                  char *buf, size_t bufsz)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) goto fallback;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT name, type, bind FROM symbols WHERE address=? LIMIT 1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *nm   = (const char *)sqlite3_column_text(st, 0);
            const char *type = (const char *)sqlite3_column_text(st, 1);
            const char *bind = (const char *)sqlite3_column_text(st, 2);
            /* 标注导入函数 vs 本地函数 */
            if (bind && !strcmp(bind, "GLOBAL") && type && !strcmp(type, "FUNC"))
                snprintf(buf, bufsz, "%s", nm ? nm : "?");
            else if (bind && !strcmp(bind, "WEAK"))
                snprintf(buf, bufsz, "%s [WEAK]", nm ? nm : "?");
            else
                snprintf(buf, bufsz, "%s", nm ? nm : "?");
            sqlite3_finalize(st);
            return buf;
        }
        sqlite3_finalize(st);
    }

    /* 检查是否是 PLT 条目 (导入函数) */
    sqlite3_prepare_v2(c,
        "SELECT s.name FROM instructions i "
        "JOIN xrefs x ON i.address=x.from_addr "
        "JOIN symbols s ON x.to_addr=s.address "
        "WHERE i.address=? AND i.mnemonic='jmp' LIMIT 1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *nm = (const char *)sqlite3_column_text(st, 0);
            snprintf(buf, bufsz, "%s [IMPORT]", nm ? nm : "?");
            sqlite3_finalize(st);
            return buf;
        }
        sqlite3_finalize(st);
    }

    /* 检查 dangerous API */
    static const char *danger_list[] = {
        "ptrace","prctl","syscall","int80","mprotect","dlopen","dlsym",
        "capset","setuid","setgid","personality","clone","fork",
        "signal","sigaction","sigprocmask", NULL
    };
    for (const char **dp = danger_list; *dp; dp++) {
        sqlite3_prepare_v2(c,
            "SELECT 1 FROM symbols s "
            "JOIN xrefs x ON x.to_addr=s.address "
            "WHERE s.name=?1 AND x.from_addr=?2 LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_text(st,  1, *dp, -1, SQLITE_STATIC);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)addr);
            int found = (sqlite3_step(st) == SQLITE_ROW);
            sqlite3_finalize(st);
            if (found) {
                snprintf(buf, bufsz, "%s [DANGER:%s]", *dp, *dp);
                return buf;
            }
        }
    }

fallback:
    snprintf(buf, bufsz, "0x%lx", (unsigned long)addr);
    return buf;
}

/* ================================================================== */
/* DB 路径: 危险调用检测                                               */
/* ================================================================== */

static int db_check_danger(AnalysisDB *adb, uint64_t func_addr,
                            char *tags, size_t tagsz)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return 0;

    tags[0] = '\0';

    static const struct {
        const char *fn; const char *label;
    } checks[] = {
        {"ptrace",   "ANTI-DEBUG"},
        {"prctl",    "PRCTL"},
        {"syscall",  "SYSCALL"},
        {"mprotect", "MPROTECT"},
        {"dlopen",   "DYNLOAD"},
        {"dlsym",    "DYNLOAD"},
        {"capset",   "PRIVESC"},
        {"setuid",   "PRIVESC"},
        {"clone",    "PROCESS"},
        {"fork",     "PROCESS"},
        {"signal",   "SIGNAL"},
        {"sigaction","SIGNAL"},
        {NULL, NULL}
    };

    sqlite3_stmt *st = NULL;
    for (int ci = 0; checks[ci].fn; ci++) {
        sqlite3_prepare_v2(c,
            "SELECT 1 FROM xrefs x "
            "JOIN symbols s ON x.to_addr=s.address "
            "JOIN instructions i ON x.from_addr=i.address "
            "WHERE s.name=?1 AND i.address>=?2 AND i.address<("
            "  SELECT COALESCE(end_addr,?2+4096) FROM functions WHERE start_addr<=?2 LIMIT 1"
            ") LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_text(st,  1, checks[ci].fn, -1, SQLITE_STATIC);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)func_addr);
            if (sqlite3_step(st) == SQLITE_ROW) {
                size_t tl = strlen(tags);
                snprintf(tags + tl, tagsz - tl, "%s%s",
                         tags[0] ? " " : "", checks[ci].label);
            }
            sqlite3_finalize(st);
        }
    }
    return tags[0] ? 1 : 0;
}

/* ================================================================== */
/* mmap 符号解析: 原始实现                                             */
/* ================================================================== */

static const char *mmap_lookup_sym(Elf64_Ctx *ctx, Elf64_Addr addr,
                                    char *buf, size_t bufsz)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (int i = 0; i < shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (!sh || sh->sh_type != want) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;
            Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym; j++) {
                if (syms[j].st_value == addr && syms[j].st_value != 0) {
                    const char *n = elf_strtab_get(ctx, strsh->sh_offset,
                                                   syms[j].st_name);
                    if (n && n[0]) { snprintf(buf, bufsz, "%s", n); return buf; }
                }
            }
        }
    }
    snprintf(buf, bufsz, "0x%lx", (unsigned long)addr);
    return buf;
}

/* ================================================================== */
/* 数组展开 (DB 路径或 mmap 路径)                                       */
/* ================================================================== */

static void dump_array(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd,
                       const char *label, const char *phase_desc,
                       AnalysisDB *adb)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_size == 0 || sh->sh_entsize == 0) return;

    int count = (int)(sh->sh_size / sizeof(Elf64_Addr));
    Elf64_Addr *entries = (Elf64_Addr *)(ctx->map + sh->sh_offset);

    char buf[400];
    snprintf(buf, sizeof(buf), "=== %s (%d entries) — %s ===",
             label, count, phase_desc);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < count; i++) {
        char sym_buf[128];
        const char *name;
        char danger_tags[128] = "";

        if (entries[i] == 0) {
            snprintf(buf, sizeof(buf), "[%d] (NULL terminator)", i);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            break;  /* NULL 之后的不再显示 */
        }

        if (adb) {
            name = db_lookup_sym(adb, entries[i], sym_buf, sizeof(sym_buf));
            db_check_danger(adb, entries[i], danger_tags, sizeof(danger_tags));
        } else {
            name = mmap_lookup_sym(ctx, entries[i], sym_buf, sizeof(sym_buf));
        }

        snprintf(buf, sizeof(buf), "[%d] 0x%lx", i, (unsigned long)entries[i]);
        fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)entries[i]);

        snprintf(buf, sizeof(buf), "    → %s%s%s",
                 name,
                 danger_tags[0] ? "  [" : "",
                 danger_tags);
        if (danger_tags[0]) strcat(buf, "]");
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int parse_init_array(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    AnalysisDB *adb = g_active_db;

    /* 指定具体节: 直接展开 */
    if (shdr_idx >= 0) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
        if (!sh || sh->sh_size == 0) return pd->count;

        const char *name = elf_section_name(ctx, shdr_idx);
        const char *desc = "";
        if (sh->sh_type == SHT_PREINIT_ARRAY)  desc = "called BEFORE init_array";
        else if (sh->sh_type == SHT_INIT_ARRAY) desc = "called at program startup";
        else if (sh->sh_type == SHT_FINI_ARRAY) desc = "called at program exit (reverse order)";

        dump_array(ctx, shdr_idx, pd, name ? name : "?", desc, adb);
        return pd->count;
    }

    /* 全部扫描: 单趟遍历, 按 preinit → init → fini 顺序 */
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    int found = 0;

    /* 顺序 1: .preinit_array */
    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (sh && sh->sh_type == SHT_PREINIT_ARRAY) {
            dump_array(ctx, si, pd,
                       elf_section_name(ctx, si), "called BEFORE init_array", adb);
            found++;
        }
    }
    /* 顺序 2: .init_array */
    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (sh && sh->sh_type == SHT_INIT_ARRAY) {
            dump_array(ctx, si, pd,
                       elf_section_name(ctx, si), "called at program startup", adb);
            found++;
        }
    }
    /* 顺序 3: .fini_array */
    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (sh && sh->sh_type == SHT_FINI_ARRAY) {
            dump_array(ctx, si, pd,
                       elf_section_name(ctx, si), "called at program exit (reverse order)", adb);
            found++;
        }
    }

    if (found == 0) {
        fields_add(pd, "(no .init_array/.fini_array/.preinit_array sections found)",
                   0, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}
