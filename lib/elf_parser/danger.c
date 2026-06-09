/*
 * danger.c — 危险函数调用检测模块 (v3 — DB 优先)
 *
 * 三通道检测:
 *   Path DB: 从 symbols/xrefs/instructions 表直接查询 (零扫描, 零反汇编)
 *   Pass 1 (mmap): 扫描 .dynstr — 检测导入的危险 API
 *   Pass 2 (mmap): 反汇编代码段 — 找到实际 call 指令地址 + 上下文
 *
 * 符合 COORDINATION.md 规范:
 *   接口: int parse_danger(Elf64_Ctx *ctx, PanelData *pd);
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
/* 危险 API 数据库 (与 elf-disasm 共享)                               */
/* ================================================================== */

typedef enum {
    CAT_BOF, CAT_FMTSTR, CAT_UAF, CAT_INT_OVFL,
    CAT_RACE, CAT_CMD_INJ, CAT_INFO_LEAK, CAT_ARB_RW, CAT_OTHER
} vuln_cat_t;

static const char *cat_names[] = {
    "BOF", "FMTSTR", "UAF", "INT_OVFL",
    "RACE", "CMD_INJ", "INFO_LEAK", "ARB_RW", "OTHER"
};

typedef struct {
    const char *name;
    vuln_cat_t  category;
    int         severity;  /* 0=INFO 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL */
    const char *reason;
} danger_api_t;

static const char *sev_names[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};

static const danger_api_t DANGER_DB[] = {
    /* Buffer Overflow */
    {"gets",        CAT_BOF, 4, "unbounded input, no size check"},
    {"strcpy",      CAT_BOF, 3, "no destination size check"},
    {"strcat",      CAT_BOF, 3, "no destination size check"},
    {"sprintf",     CAT_BOF, 3, "no destination size check"},
    {"vsprintf",    CAT_BOF, 3, "no destination size check"},
    {"scanf",       CAT_BOF, 3, "unbounded format input"},
    {"memcpy",      CAT_BOF, 2, "check third argument (size)"},
    {"memmove",     CAT_BOF, 2, "check third argument (size)"},
    {"read",        CAT_BOF, 2, "check buffer vs input length"},
    {"recv",        CAT_BOF, 2, "check buffer vs input length"},
    {"recvfrom",    CAT_BOF, 2, "check buffer vs input length"},
    {"sscanf",      CAT_BOF, 2, "check format for '%s' limit"},
    {"memset",      CAT_BOF, 1, "check third argument (size)"},
    {"bcopy",       CAT_BOF, 2, "check third argument (size)"},
    {"strncpy",     CAT_BOF, 1, "may not null-terminate"},
    {"strncat",     CAT_BOF, 1, "check size parameter"},
    {"fgets",       CAT_BOF, 1, "bounded, check buffer size"},

    /* Format String */
    {"printf",      CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},
    {"fprintf",     CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},
    {"snprintf",    CAT_FMTSTR, 2, "check format argument"},
    {"syslog",      CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},
    {"dprintf",     CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},
    {"err",         CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},
    {"warn",        CAT_FMTSTR, 2, "fmtstr vuln if user-controlled"},

    /* Command Injection */
    {"system",      CAT_CMD_INJ, 4, "cmd injection if input-controlled"},
    {"popen",       CAT_CMD_INJ, 4, "cmd injection if input-controlled"},
    {"execve",      CAT_CMD_INJ, 3, "check argument array"},
    {"execvp",      CAT_CMD_INJ, 3, "check path from input"},
    {"execl",       CAT_CMD_INJ, 4, "check path from input"},
    {"execlp",      CAT_CMD_INJ, 4, "check path from input"},

    /* Integer Overflow */
    {"malloc",      CAT_INT_OVFL, 0, "check multiplication in size calc"},
    {"calloc",      CAT_INT_OVFL, 0, "check nmemb * size for overflow"},
    {"realloc",     CAT_INT_OVFL, 0, "check new size calculation"},
    {"alloca",      CAT_INT_OVFL, 3, "stack alloc with variable size"},

    /* Race Condition */
    {"access",      CAT_RACE, 2, "TOCTOU: check open after access"},
    {"stat",        CAT_RACE, 1, "TOCTOU: check open after stat"},
    {"lstat",       CAT_RACE, 1, "TOCTOU: check open after lstat"},
    {"chmod",       CAT_RACE, 1, "TOCTOU: symlink race"},
    {"chown",       CAT_RACE, 1, "TOCTOU: symlink race"},

    /* Information Leak */
    {"puts",        CAT_INFO_LEAK, 1, "may leak stack/heap data"},
    {"write",       CAT_INFO_LEAK, 1, "check buffer content"},
    {"send",        CAT_INFO_LEAK, 1, "check buffer content"},

    /* Arbitrary R/W */
    {"mmap",        CAT_ARB_RW, 0, "check user-controlled address"},
    {"mprotect",    CAT_ARB_RW, 2, "check if making code writable"},
};

#define DB_SIZE (int)(sizeof(DANGER_DB) / sizeof(DANGER_DB[0]))

/* ================================================================== */
/* Pass 1: 字符串搜索                                                 */
/* ================================================================== */

/**
 * 检查危险 API 名称是否作为完整字符串出现在 .dynstr 中。
 */
static int api_in_strtab(Elf64_Ctx *ctx, const char *api_name)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    size_t api_len = strlen(api_name);

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        const char *name = elf_section_name(ctx, i);
        if (!name) continue;

        if (strstr(name, "dynstr") || strstr(name, "strtab")) {
            const char *data = (const char *)(ctx->map + sh->sh_offset);
            size_t size = sh->sh_size;
            for (size_t off = 0; off + api_len <= size; off++) {
                if (memcmp(data + off, api_name, api_len) != 0) continue;
                if (off > 0 && data[off - 1] != '\0') continue;
                if (off + api_len < size && data[off + api_len] != '\0') continue;
                return 1;
            }
        }
    }
    return 0;
}

/* ================================================================== */
/* Pass 2: 反汇编扫描 (新 — 需要 Capstone)                           */
/* ================================================================== */

/**
 * 回调数据结构: 反汇编扫描中收集匹配到的危险调用。
 */
typedef struct {
    uint64_t    call_addr;
    const char *api_name;
    int         db_index;    /* DANGER_DB 索引 */
    char        context[64];  /* 调用指令文本 */
} found_call_t;

typedef struct {
    found_call_t *calls;
    int           count;
    int           capacity;
    Elf64_Ctx    *ctx;
} call_collector_t;

/**
 * 反汇编回调: 检查每条指令是否为危险 API 调用。
 */
static bool on_instruction(const cs_insn *insn, void *user)
{
    int shnum = (int)((Elf64_Ehdr*)((Elf64_Ctx*)((call_collector_t*)user)->ctx)->map)->e_shnum;
    call_collector_t *coll = (call_collector_t *)user;

    /* 必须启用 detail 才能判断指令组 */
    if (!insn->detail) return true;

    /* 检查是否为 call 指令 */
    int is_call = 0;
    for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
        if (insn->detail->groups[g] == X86_GRP_CALL) {
            is_call = 1;
            break;
        }
    }
    if (!is_call) return true;

    /* 提取 call 目标地址 */
    uint64_t target = 0;
    cs_x86 *x86 = &insn->detail->x86;
    for (uint8_t oi = 0; oi < x86->op_count; oi++) {
        if (x86->operands[oi].type == X86_OP_IMM) {
            target = (uint64_t)x86->operands[oi].imm;
            break;
        }
    }
    if (target == 0) return true;

    /* 尝试从符号表解析目标名称 */
    const char *target_name = NULL;
    /* 扫描 .dynsym 查找地址 = target 的符号 */
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(coll->ctx, i);
        if (!sh || sh->sh_type != SHT_DYNSYM) continue;

        Elf64_Shdr *str_shdr = elf_get_shdr(coll->ctx, sh->sh_link);
        if (!str_shdr) continue;
        Elf64_Off stroff = str_shdr->sh_offset;

        Elf64_Sym *syms = (Elf64_Sym *)(coll->ctx->map + sh->sh_offset);
        int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

        for (int j = 0; j < nsym; j++) {
            if (syms[j].st_value == target) {
                target_name = elf_strtab_get(coll->ctx, stroff, syms[j].st_name);
                if (target_name) break;
            }
        }
        if (target_name) break;
    }

    /* 如果没有符号名, 检查 .symtab */
    if (!target_name) {
        for (int i = 0; i < shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(coll->ctx, i);
            if (!sh || sh->sh_type != SHT_SYMTAB) continue;

            Elf64_Shdr *str_shdr = elf_get_shdr(coll->ctx, sh->sh_link);
            if (!str_shdr) continue;
            Elf64_Off stroff = str_shdr->sh_offset;

            Elf64_Sym *syms = (Elf64_Sym *)(coll->ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

            for (int j = 0; j < nsym; j++) {
                if (syms[j].st_value == target) {
                    target_name = elf_strtab_get(coll->ctx, stroff, syms[j].st_name);
                    if (target_name) break;
                }
            }
            if (target_name) break;
        }
    }

    /* 匹配危险 API 数据库 */
    for (int ai = 0; ai < DB_SIZE; ai++) {
        int matched = 0;
        if (target_name && !strcmp(target_name, DANGER_DB[ai].name)) {
            matched = 1;
        }
        /* 也检查 op_str (Capstone 有时输出 "call strcpy@plt") */
        if (!matched && strstr(insn->op_str, DANGER_DB[ai].name)) {
            matched = 1;
        }
        if (!matched) continue;

        /* 扩容 */
        if (coll->count >= coll->capacity) {
            coll->capacity = coll->capacity ? coll->capacity * 2 : 64;
            found_call_t *nc = realloc(coll->calls,
                (size_t)coll->capacity * sizeof(found_call_t));
            if (!nc) return false;
            coll->calls = nc;
        }

        found_call_t *fc = &coll->calls[coll->count++];
        fc->call_addr = insn->address;
        fc->api_name  = DANGER_DB[ai].name;
        fc->db_index  = ai;
        snprintf(fc->context, sizeof(fc->context),
                 "%.32s %.24s", insn->mnemonic, insn->op_str);
        break;
    }

    return true;  /* 继续扫描 */
}

/**
 * Pass 2 入口: 对所有代码段进行反汇编扫描。
 */
static int scan_code_sections(Elf64_Ctx *ctx, call_collector_t *coll)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    disasm_ctx *d = disasm_open();
    if (!d) return -1;

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_type != SHT_PROGBITS) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;

        disasm_run(d,
                   ctx->map + sh->sh_offset,
                   sh->sh_size,
                   sh->sh_addr,
                   on_instruction,
                   coll);
    }

    disasm_close(d);
    return 0;
}

/* ================================================================== */
/* DB 路径: 从 xrefs + symbols 表查询危险调用                          */
/* ================================================================== */

static int parse_danger_db(AnalysisDB *adb, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[320];
    snprintf(buf, sizeof(buf), "=== Dangerous API Detection [DB] ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 构建 SQL IN 子句: 所有危险 API 名称 */
    char in_list[4096] = "";
    int ilp = 0;
    for (int ai = 0; ai < DB_SIZE && ilp < (int)sizeof(in_list) - 64; ai++) {
        ilp += snprintf(in_list + ilp, sizeof(in_list) - (size_t)ilp,
                        "%s'%s'", ai > 0 ? "," : "", DANGER_DB[ai].name);
    }

    /* 查询: 找到所有 call 指令, 其目标指向危险 API */
    char sql[4608];
    snprintf(sql, sizeof(sql),
        "SELECT x.from_addr, s.name, i.mnemonic, i.op_str "
        "FROM xrefs x "
        "JOIN symbols s ON x.to_addr=s.address "
        "JOIN instructions i ON x.from_addr=i.address "
        "WHERE x.ref_type='call' "
        "AND s.name IN (%s) "
        "ORDER BY x.from_addr LIMIT 200",
        in_list);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c, sql, -1, &st, NULL);
    if (!st) {
        fields_add(pd, "(DB query failed — import ELF first)", 1, 0, DETAIL_NONE, -1);
        return 0;
    }

    /* 统计: 按类别和严重度 */
    int cat_counts[9] = {0};
    int sev_counts[5] = {0};
    int total = 0;

    fields_add(pd, "── Call Sites (by severity) ──", 0, 0, DETAIL_NONE, -1);

    while (sqlite3_step(st) == SQLITE_ROW && total < 150) {
        uint64_t call_addr = (uint64_t)sqlite3_column_int64(st, 0);
        const char *api_name = (const char *)sqlite3_column_text(st, 1);
        const char *mnem     = (const char *)sqlite3_column_text(st, 2);
        const char *op_str   = (const char *)sqlite3_column_text(st, 3);

        /* 匹配 DANGER_DB 获取分类 */
        int db_idx = -1;
        for (int ai = 0; ai < DB_SIZE; ai++) {
            if (!strcmp(DANGER_DB[ai].name, api_name)) { db_idx = ai; break; }
        }
        if (db_idx < 0) continue;

        danger_api_t *api = (danger_api_t *)&DANGER_DB[db_idx];

        /* 行 1: 序号 + 严重度 + 函数名 + 分类 */
        snprintf(buf, sizeof(buf),
                 "[%d] %-9s %-18s  %s",
                 total + 1,
                 sev_names[api->severity],
                 api->name,
                 cat_names[api->category]);
        fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)call_addr);

        /* 行 2: 地址 + 调用上下文 */
        snprintf(buf, sizeof(buf),
                 "    0x%lx    %s %s",
                 (unsigned long)call_addr,
                 mnem ? mnem : "?",
                 op_str ? op_str : "");
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        cat_counts[api->category]++;
        sev_counts[api->severity]++;
        total++;
    }
    sqlite3_finalize(st);

    /* 还查询: 在 symbols 表中有但 DB 中无调用点的危险 API (类似 mmap 的 orphan 检测) */
    snprintf(sql, sizeof(sql),
        "SELECT s.name FROM symbols s "
        "WHERE s.name IN (%s) "
        "AND s.address NOT IN (SELECT DISTINCT to_addr FROM xrefs WHERE ref_type='call') "
        "LIMIT 50",
        in_list);
    sqlite3_prepare_v2(c, sql, -1, &st, NULL);
    if (st) {
        int orphan = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 0);
            if (!name) continue;
            /* 匹配分类 */
            for (int ai = 0; ai < DB_SIZE; ai++) {
                if (!strcmp(DANGER_DB[ai].name, name)) {
                    if (orphan == 0) {
                        fields_add(pd, "── Imported but no call site found ──", 0, 0, DETAIL_NONE, -1);
                    }
                    danger_api_t *api = (danger_api_t *)&DANGER_DB[ai];
                    snprintf(buf, sizeof(buf),
                             "%-9s %-18s  %s",
                             sev_names[api->severity],
                             api->name,
                             cat_names[api->category]);
                    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
                    snprintf(buf, sizeof(buf),
                             "    (imported, no call site) — %s",
                             api->reason);
                    fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                    cat_counts[api->category]++;
                    sev_counts[api->severity]++;
                    orphan++;
                    break;
                }
            }
        }
        sqlite3_finalize(st);
    }

    /* 摘要 */
    fields_add(pd, "──────────────────────────────", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "By severity: CRIT=%d HIGH=%d MED=%d LOW=%d INFO=%d",
             sev_counts[4], sev_counts[3], sev_counts[2], sev_counts[1], sev_counts[0]);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    for (int ci = 0; ci < 9; ci++) {
        if (cat_counts[ci] > 0) {
            snprintf(buf, sizeof(buf), "  %s: %d", cat_names[ci], cat_counts[ci]);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
    }

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始双通道检测 (DB 不可用时降级)                         */
/* ================================================================== */

static int parse_danger_mmap(Elf64_Ctx *ctx, PanelData *pd)
{
    char buf[320];

    /* ---------- Pass 1: 快速字符串扫描 ---------- */
    typedef struct {
        const char *name;
        int         db_index;
    } str_found_t;

    str_found_t str_found[64];
    int nstr = 0;

    for (int ai = 0; ai < DB_SIZE && nstr < 64; ai++) {
        if (api_in_strtab(ctx, DANGER_DB[ai].name)) {
            int dup = 0;
            for (int fi = 0; fi < nstr; fi++) {
                if (!strcmp(str_found[fi].name, DANGER_DB[ai].name)) {
                    dup = 1; break;
                }
            }
            if (!dup) {
                str_found[nstr].name     = DANGER_DB[ai].name;
                str_found[nstr].db_index = ai;
                nstr++;
            }
        }
    }

    /* ---------- Pass 2: 反汇编扫描 ---------- */
    call_collector_t coll = {NULL, 0, 0, ctx};
    int scan_ok = (scan_code_sections(ctx, &coll) == 0);

    /* ---------- 输出 ---------- */
    snprintf(buf, sizeof(buf),
             "=== Dangerous API Detection ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (nstr == 0 && coll.count == 0) {
        fields_add(pd, "(no dangerous APIs detected)", 1, 0, DETAIL_NONE, -1);
        free(coll.calls);
        return pd->count;
    }

    /* 统计 */
    int cat_counts[9] = {0};
    int sev_counts[5] = {0};

    snprintf(buf, sizeof(buf),
             "Pass 1 (strings): %d APIs | Pass 2 (disasm): %d call sites found",
             nstr, coll.count);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    /* 按严重等级排列调用点 */
    if (scan_ok && coll.count > 0) {
        fields_add(pd, "─ ─ ─ ─ Call Sites (by severity) ─ ─ ─ ─",
                   0, 0, DETAIL_NONE, -1);

        /* 冒泡排序: 严重级别从高到低 */
        for (int i = 0; i < coll.count - 1; i++) {
            for (int j = i + 1; j < coll.count; j++) {
                int si = DANGER_DB[coll.calls[i].db_index].severity;
                int sj = DANGER_DB[coll.calls[j].db_index].severity;
                if (sj > si) {
                    found_call_t tmp = coll.calls[i];
                    coll.calls[i] = coll.calls[j];
                    coll.calls[j] = tmp;
                }
            }
        }

        int shown = 0;
        for (int i = 0; i < coll.count && shown < 100; i++) {
            found_call_t *fc = &coll.calls[i];
            danger_api_t *api = (danger_api_t *)&DANGER_DB[fc->db_index];

            snprintf(buf, sizeof(buf),
                     "[%d] %-9s %-18s  %s",
                     shown + 1,
                     sev_names[api->severity],
                     api->name,
                     cat_names[api->category]);
            fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)fc->call_addr);
            snprintf(buf, sizeof(buf),
                     "    0x%lx    %s",
                     (unsigned long)fc->call_addr,
                     fc->context);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

            cat_counts[api->category]++;
            sev_counts[api->severity]++;
            shown++;
        }

        if (coll.count > 100) {
            snprintf(buf, sizeof(buf), "... (%d more call sites)",
                     coll.count - 100);
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        }
    }

    /* Pass 1 中发现的 API 但 Pass 2 未找到调用点的 */
    if (nstr > 0) {
        int orphan = 0;
        for (int si = 0; si < nstr; si++) {
            int has_call = 0;
            for (int ci = 0; ci < coll.count; ci++) {
                if (!strcmp(str_found[si].name, coll.calls[ci].api_name)) {
                    has_call = 1; break;
                }
            }
            if (has_call) continue;

            if (orphan == 0) {
                fields_add(pd, "─ ─ Imported but no call site found ─ ─",
                           0, 0, DETAIL_NONE, -1);
            }

            danger_api_t *api = (danger_api_t *)&DANGER_DB[str_found[si].db_index];
            snprintf(buf, sizeof(buf),
                     "%-9s %-18s  %s",
                     sev_names[api->severity],
                     api->name,
                     cat_names[api->category]);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
            snprintf(buf, sizeof(buf),
                     "    (imported, no call site) — %s",
                     api->reason);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);

            cat_counts[api->category]++;
            sev_counts[api->severity]++;
            orphan++;
        }
    }

    /* 摘要 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "By severity: CRIT=%d HIGH=%d MED=%d LOW=%d INFO=%d",
             sev_counts[4], sev_counts[3], sev_counts[2], sev_counts[1], sev_counts[0]);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    for (int c = 0; c < 9; c++) {
        if (cat_counts[c] > 0) {
            snprintf(buf, sizeof(buf), "  %s: %d", cat_names[c], cat_counts[c]);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
    }

    free(coll.calls);
    return pd->count;
}

/* ================================================================== */
/* 公共接口: parse_danger (DB 优先, mmap 降级)                        */
/* ================================================================== */

int parse_danger(Elf64_Ctx *ctx, PanelData *pd)
{
    if (g_active_db) {
        return parse_danger_db(g_active_db, pd);
    }
    return parse_danger_mmap(ctx, pd);
}
