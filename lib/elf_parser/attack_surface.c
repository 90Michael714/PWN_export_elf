/*
 * attack_surface.c — 攻击面摘要模块 (v2 — DB 优先)
 *
 * 双路径:
 *   DB 路径: JOIN symbols + xrefs, 精确统计每个类的实际调用点数量
 *   mmap 路径: 纯 .dynsym 扫描 (原有逻辑, DB 不可用时降级)
 *
 * 接口: int parse_attack_surface(Elf64_Ctx *ctx, PanelData *pd);
 */
#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 攻击面分类数据库                                                    */
/* ================================================================== */

typedef struct {
    const char *category;
    const char *risk_icon;   /* 🔥⚡✅ */
    const char **funcs;
    int         func_count;
} as_category_t;

/* 各分类的函数列表 */
static const char *NET_IO[]    = {"socket","connect","accept","bind","listen",
                                  "send","recv","sendto","recvfrom","getaddrinfo",
                                  "setsockopt","getsockname","getpeername",
                                  "socketpair","shutdown", NULL};
static const char *FILE_IO[]   = {"open","read","write","close","fopen","fread",
                                  "fwrite","mmap","stat","access","lstat","fstat",
                                  "openat","readlink","unlink","rename","chmod",
                                  "chown","truncate","ftruncate", NULL};
static const char *PROCESS[]   = {"system","execve","execvp","fork","clone",
                                  "ptrace","prctl","capset","capget","setuid",
                                  "setgid","getuid","kill","waitpid", NULL};
static const char *MEMORY[]    = {"mmap","munmap","mprotect","brk","sbrk",
                                  "malloc","free","memcpy","memmove","calloc",
                                  "realloc","memset", NULL};
static const char *SIGNAL[]    = {"signal","sigaction","sigprocmask","kill",
                                  "sigaltstack","sigreturn", NULL};
static const char *DYNAMIC[]   = {"dlopen","dlsym","dlclose","dlerror", NULL};
static const char *USER_INPUT[]= {"scanf","gets","readline","getenv","fgets",
                                  "getchar","fscanf","getline", NULL};

static const as_category_t CATEGORIES[] = {
    {"Network I/O",     "🔥", NET_IO,    0},
    {"File I/O",        "🔥", FILE_IO,   0},
    {"Process Control", "🔥", PROCESS,   0},
    {"Memory Ops",      "⚡", MEMORY,    0},
    {"Signal",          "✅", SIGNAL,    0},
    {"Dynamic Load",    "⚡", DYNAMIC,   0},
    {"User Input",      "🔥", USER_INPUT,0},
};
#define NCAT (int)(sizeof(CATEGORIES) / sizeof(CATEGORIES[0]))

/* 计算 funcs 数组长度 (NULL 结尾) */
static int count_funcs(const char **funcs) {
    int n = 0; while (funcs[n]) n++; return n;
}

/* ================================================================== */
/* DB 路径: JOIN symbols + xrefs 精确统计                               */
/* ================================================================== */

static int parse_attack_surface_db(AnalysisDB *adb, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[512];
    int total_points = 0;

    fields_add(pd, "=== Attack Surface Analysis [DB] ===", 0, 0, DETAIL_NONE, -1);

    /* 特殊: 统计所有导入函数 (从 PLT 相关 symbols) */
    sqlite3_stmt *st0 = NULL;
    int total_imports = 0;
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM symbols WHERE table_name='.dynsym'"
        " AND type='FUNC'",
        -1, &st0, NULL);
    if (st0) {
        if (sqlite3_step(st0) == SQLITE_ROW)
            total_imports = sqlite3_column_int(st0, 0);
        sqlite3_finalize(st0);
    }

    snprintf(buf, sizeof(buf), "Imported functions: %d", total_imports);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    for (int cat = 0; cat < NCAT; cat++) {
        int func_count = count_funcs((const char **)CATEGORIES[cat].funcs);

        /* 构建 SQL IN 子句 */
        char in_list[4096] = "";
        int ilp = 0;
        for (int f = 0; f < func_count && ilp < (int)sizeof(in_list) - 64; f++) {
            const char *fn = CATEGORIES[cat].funcs[f];
            if (!fn) break;
            ilp += snprintf(in_list + ilp, sizeof(in_list) - (size_t)ilp,
                            "%s'%s'", f > 0 ? "," : "", fn);
        }

        /* 查询: 在 symbols 中匹配 + 统计实际的 xref 调用点 */
        char sql[5000];
        snprintf(sql, sizeof(sql),
            "SELECT s.name, COUNT(x.from_addr) as call_count "
            "FROM symbols s "
            "LEFT JOIN xrefs x ON x.to_addr=s.address AND x.ref_type='call' "
            "WHERE s.name IN (%s) "
            "GROUP BY s.name "
            "ORDER BY s.name",
            in_list);

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c, sql, -1, &st, NULL) != SQLITE_OK) continue;

        int found_count = 0;
        int total_calls = 0;
        char found_list[512] = "";
        int flen = 0;

        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *fn = (const char *)sqlite3_column_text(st, 0);
            int n_calls     = sqlite3_column_int(st, 1);

            if (fn) {
                found_count++;
                total_calls += n_calls;
                if (flen < (int)sizeof(found_list) - 40) {
                    flen += snprintf(found_list + flen,
                                     sizeof(found_list) - (size_t)flen,
                                     "%s%s(%d)",
                                     flen > 0 ? " " : "",
                                     fn, n_calls);
                }
            }
        }
        sqlite3_finalize(st);

        int risk = (found_count >= 5) ? 3 : (found_count >= 2) ? 2 : 1;
        total_points += found_count;

        if (found_count > 0) {
            snprintf(buf, sizeof(buf),
                     "%s %s: %s %d functions, %d call sites (%s)",
                     (risk >= 3) ? "🔥" : (risk >= 2) ? "⚡" : "✅",
                     CATEGORIES[cat].category,
                     (risk >= 3) ? "HIGH" : (risk >= 2) ? "MEDIUM" : "LOW",
                     found_count, total_calls,
                     found_list);
        } else {
            snprintf(buf, sizeof(buf),
                     "✅ %s: (none)", CATEGORIES[cat].category);
        }
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 总结 */
    fields_add(pd, "───────────────────────", 0, 0, DETAIL_NONE, -1);

    const char *overall;
    if (total_points >= 20)      overall = "🔥 HIGH — large attack surface, prioritize audit";
    else if (total_points >= 8)  overall = "⚡ MEDIUM — moderate risk, review hotspots";
    else                        overall = "✅ LOW — limited external interaction";

    snprintf(buf, sizeof(buf), "Attack surface points: %d (%d imports) — %s",
             total_points, total_imports, overall);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始实现 (DB 不可用时降级)                               */
/* ================================================================== */

static int parse_attack_surface_mmap(Elf64_Ctx *ctx, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;

    /* 收集所有导入符号名 */
    char imports[512][64];
    int nimports = 0;

    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_type != SHT_DYNSYM) continue;
        Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
        if (!strsh) continue;

        Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
        int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

        for (int j = 0; j < nsym && nimports < 512; j++) {
            const char *name = elf_strtab_get(ctx, strsh->sh_offset,
                                              syms[j].st_name);
            if (name && name[0]) {
                strncpy(imports[nimports], name, 63);
                imports[nimports][63] = '\0';
                nimports++;
            }
        }
    }

    /* 统计各分类 */
    fields_add(pd, "=== Attack Surface Analysis ===", 0, 0, DETAIL_NONE, -1);

    int total_points = 0;
    char buf[512];

    for (int c = 0; c < NCAT; c++) {
        int func_count = count_funcs((const char **)CATEGORIES[c].funcs);

        /* 查找哪些函数被导入 */
        char found_list[256] = "";
        int found_count = 0;
        int flen = 0;

        for (int f = 0; f < func_count; f++) {
            const char *fn = CATEGORIES[c].funcs[f];
            for (int im = 0; im < nimports; im++) {
                if (!strcmp(imports[im], fn)) {
                    if (found_count > 0 && flen < (int)sizeof(found_list) - 20) {
                        flen += snprintf(found_list + flen,
                                        sizeof(found_list) - (size_t)flen, "/");
                    }
                    if (flen < (int)sizeof(found_list) - 20) {
                        flen += snprintf(found_list + flen,
                                        sizeof(found_list) - (size_t)flen, "%s", fn);
                    }
                    found_count++;
                    break;
                }
            }
        }

        int risk = (found_count >= 5) ? 3 : (found_count >= 2) ? 2 : 1;
        total_points += found_count;

        if (found_count > 0) {
            snprintf(buf, sizeof(buf),
                     "%s %s: %s %d functions (%s)",
                     (risk >= 3) ? "🔥" : (risk >= 2) ? "⚡" : "✅",
                     CATEGORIES[c].category,
                     (found_count >= 5) ? "HIGH" : (found_count >= 2) ? "MEDIUM" : "LOW",
                     found_count,
                     found_list);
        } else {
            snprintf(buf, sizeof(buf),
                     "✅ %s: (none)", CATEGORIES[c].category);
        }
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 总结 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    const char *overall;
    if (total_points >= 20)      overall = "🔥 HIGH — large attack surface, prioritize audit";
    else if (total_points >= 8)  overall = "⚡ MEDIUM — moderate risk, review hotspots";
    else                        overall = "✅ LOW — limited external interaction";

    snprintf(buf, sizeof(buf), "Attack surface points: %d — %s",
             total_points, overall);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    return pd->count;
}

/* ── 公共接口 ────────────────────────────────────────────────────── */

int parse_attack_surface(Elf64_Ctx *ctx, PanelData *pd)
{
    if (g_active_db) {
        return parse_attack_surface_db(g_active_db, pd);
    }
    return parse_attack_surface_mmap(ctx, pd);
}
