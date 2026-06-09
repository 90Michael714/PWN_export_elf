/*
 * translate_vuln.c — 漏洞视角自然语言翻译层 (v3 — DB优先, 上下文感知)
 *
 * 输入: DB 的 xrefs/ir_stmts/symbols 表 + ELF 缓解措施状态
 * 输出: 人类可读、上下文感知的风险评估报告
 *
 * 双路径:
 *   DB 路径: 精确 call site 统计 + 参数来源分析 + 缓解措施联动
 *   mmap 路径: 扫描 .dynsym/.symtab 做导入符号匹配 (原有逻辑, DB不可用时降级)
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 漏洞模式规则库                                                       */
/* ================================================================== */

typedef enum { SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRIT } severity_t;

typedef struct {
    const char  *danger_func;
    const char  *pattern;
    const char  *mitigation;
    const char  *exploit_hint;
    severity_t   severity;
} vuln_rule_t;

static const vuln_rule_t VULN_RULES[] = {
    {"gets",    "无边界检查的字符串输入 → 栈缓冲区溢出 (BOF)",
                "替换为 fgets(buf, size, stdin)", "可控输入长度 → RIP劫持 → ROP链",
                SEV_CRIT},
    {"strcpy",  "无目标大小检查的字符串拷贝 → 栈/堆溢出",
                "使用 strncpy(dst, src, maxlen)", "覆盖返回地址 → 控制程序流",
                SEV_HIGH},
    {"strcat",  "无目标大小检查的字符串拼接 → 缓冲区溢出",
                "使用 strncat", "同 strcpy",
                SEV_HIGH},
    {"sprintf", "无目标大小检查的格式化输出 → 缓冲区溢出",
                "使用 snprintf(buf, size, fmt, ...)", "可控格式串+堆栈溢出",
                SEV_HIGH},
    {"scanf",   "格式化输入无长度限制 → 缓冲区溢出",
                "使用 %Ns 限制字段宽度", "超长输入 → 栈/堆破坏",
                SEV_HIGH},
    {"memcpy",  "内存拷贝 — len参数来自外部输入 → 堆溢出",
                "验证 len <= dst_size", "可控拷贝长度 → 堆元数据破坏 → 任意写",
                SEV_HIGH},
    {"memmove", "同 memcpy",
                "同 memcpy", "同 memcpy",
                SEV_HIGH},
    {"system",  "执行shell命令 — 参数来自外部输入 → 命令注入",
                "避免 system(), 使用 execve() + 参数白名单",
                "反弹shell / 提权",
                SEV_CRIT},
    {"popen",   "执行shell命令并捕获输出 — 命令注入",
                "同 system()", "命令执行 + 输出泄漏",
                SEV_CRIT},
    {"execve",  "执行程序 — 路径/参数可控 → 任意代码执行",
                "验证 path 和 argv", "执行 /bin/sh → 完整shell",
                SEV_CRIT},
    {"printf",  "格式化输出 — 格式串来自外部 → 格式化字符串漏洞",
                "使用 printf(\"%s\", str) 而非 printf(str)",
                "信息泄漏 + 任意地址写(%%n)",
                SEV_HIGH},
    {"read",    "读取外部数据 — buf < count → 栈/堆溢出",
                "确保 buf >= count", "可控输入大小 → 数据越界写",
                SEV_HIGH},
    {"recv",    "网络接收 — 同read, 远程攻击面",
                "确保 buf >= len", "远程BOF → 无需本地访问",
                SEV_HIGH},
    {"recvfrom","同 recv, 远程攻击面",
                "确保 buf >= len", "远程BOF → 无需本地访问",
                SEV_HIGH},
    {"mmap",    "内存映射 — 参数可控 → 任意内存分配",
                "验证 prot/flags", "映射可写可执行内存 → shellcode",
                SEV_MEDIUM},
    {"mprotect","修改内存权限 — 参数可控 → 任意权限提升",
                "验证 addr 在合法范围内", "使数据段可执行 → shellcode",
                SEV_HIGH},
    {"dlopen",  "动态加载库 — 路径可控 → 加载恶意.so",
                "白名单库路径", "加载恶意库 → 代码执行",
                SEV_CRIT},
    {"access",  "文件存在性检查 — TOCTOU竞态窗口",
                "使用 faccessat() 或直接 open() 后检查",
                "检查后替换文件 → 符号链接攻击",
                SEV_MEDIUM},
    {"malloc",  "内存分配 — 乘法溢出 → 堆下溢/溢出",
                "检查 nmemb * size 溢出", "整数溢出 → 堆元数据破坏",
                SEV_MEDIUM},
    {"calloc",  "同 malloc, 注意 nmemb*size 溢出",
                "同 malloc", "同 malloc",
                SEV_MEDIUM},
    {NULL, NULL, NULL, NULL, SEV_INFO}
};

#define NRULES (int)(sizeof(VULN_RULES)/sizeof(VULN_RULES[0]) - 1)

/* ================================================================== */
/* 缓解措施检测 (从 ELF Header 直接读, 不依赖 security.c)               */
/* ================================================================== */

typedef struct {
    int nx;       /* 1=栈不可执行 */
    int relro;    /* 0=none 1=partial 2=full */
    int pie;      /* 1=位置无关 */
    int canary;   /* 1=栈金丝雀 */
} mit_status_t;

static void detect_mitigations(Elf64_Ctx *ctx, mit_status_t *m)
{
    memset(m, 0, sizeof(*m));
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
    int shnum = (int)ehdr->e_shnum;

    /* NX: PT_GNU_STACK 的 PF_X */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        if (ph && ph->p_type == PT_GNU_STACK) {
            m->nx = !(ph->p_flags & PF_X);
            break;
        }
    }

    /* RELRO: PT_GNU_RELRO + BIND_NOW */
    int has_relro = 0, has_bindnow = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        if (ph && ph->p_type == PT_GNU_RELRO) { has_relro = 1; break; }
    }
    if (has_relro) {
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_type != SHT_DYNAMIC) continue;
            Elf64_Dyn *dyn = (Elf64_Dyn *)(ctx->map + sh->sh_offset);
            int ndyn = (int)(sh->sh_size / sizeof(Elf64_Dyn));
            for (int d = 0; d < ndyn; d++) {
                if (dyn[d].d_tag == DT_BIND_NOW) has_bindnow = 1;
                if (dyn[d].d_tag == DT_FLAGS && (dyn[d].d_un.d_val & DF_BIND_NOW))
                    has_bindnow = 1;
                if (dyn[d].d_tag == DT_FLAGS_1 && (dyn[d].d_un.d_val & DF_1_NOW))
                    has_bindnow = 1;
            }
        }
        m->relro = has_bindnow ? 2 : 1;
    }

    /* PIE */
    m->pie = (ehdr->e_type == ET_DYN);

    /* Stack Canary: __stack_chk_fail 符号 */
    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || (sh->sh_type != SHT_DYNSYM && sh->sh_type != SHT_SYMTAB)) continue;
        Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
        if (!strsh) continue;
        Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
        int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
        for (int j = 0; j < nsym; j++) {
            const char *nm = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
            if (nm && (strstr(nm, "__stack_chk_fail") || strstr(nm, "__stack_chk_guard")))
                { m->canary = 1; break; }
        }
        if (m->canary) break;
    }
}

/* 根据缓解措施调整利用提示 */
static void adjust_exploit_hint(const mit_status_t *m, const vuln_rule_t *r,
                                 char *hint, size_t hints_sz)
{
    snprintf(hint, hints_sz, "%s", r->exploit_hint);
    size_t hl = strlen(hint);

    if (!m->nx)
        snprintf(hint + hl, hints_sz - hl, " | STACK EXEC → shellcode直接注入");
    if (!m->pie)
        snprintf(hint + hl, hints_sz - hl, " | NO PIE → 地址固定,ROP无需泄露");
    if (m->relro < 2)
        snprintf(hint + hl, hints_sz - hl, " | GOT可写 → GOT覆写可用");
    if (!m->canary)
        snprintf(hint + hl, hints_sz - hl, " | NO CANARY → 直接覆盖返回地址");
    if (m->nx && m->pie && m->relro == 2 && m->canary)
        snprintf(hint + hl, hints_sz - hl, " | 全缓解 → 需要info leak+ROP+ASLR绕过");
}

/* ================================================================== */
/* DB 路径: 精确 call site + 参数分析 + 缓解联动                         */
/* ================================================================== */

static int parse_vuln_db(AnalysisDB *adb, Elf64_Ctx *ctx, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    mit_status_t mit;
    detect_mitigations(ctx, &mit);

    char buf[512];
    int crit=0, high=0, med=0, low=0, info=0;
    int total_calls = 0;

    fields_add(pd, "=== Vulnerability Risk Report [DB] ===", 0, 0, DETAIL_NONE, -1);

    /* 缓解措施摘要 */
    snprintf(buf, sizeof(buf), "NX:%s  PIE:%s  RELRO:%s  CANARY:%s",
             mit.nx ? "+" : "!", mit.pie ? "+" : "!",
             mit.relro == 2 ? "FULL" : mit.relro == 1 ? "PARTIAL" : "NONE",
             mit.canary ? "+" : "!");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 遍历规则库: 对每个危险函数查实际调用点 */
    for (int ri = 0; ri < NRULES; ri++) {
        const vuln_rule_t *r = &VULN_RULES[ri];
        sqlite3_stmt *st = NULL;

        /* 查询: 该危险函数的 call xrefs, 带调用者函数名 */
        sqlite3_prepare_v2(c,
            "SELECT x.from_addr, "
            "  (SELECT name FROM functions "
            "   WHERE start_addr<=x.from_addr AND end_addr>x.from_addr LIMIT 1) "
            "FROM xrefs x "
            "JOIN symbols s ON x.to_addr=s.address "
            "WHERE x.ref_type='call' AND s.name=?1 "
            "ORDER BY x.from_addr LIMIT 10",
            -1, &st, NULL);
        if (!st) continue;

        sqlite3_bind_text(st, 1, r->danger_func, -1, SQLITE_STATIC);

        int call_count = 0;
        while (sqlite3_step(st) == SQLITE_ROW && call_count < 10) {
            uint64_t call_addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *func_name = (const char *)sqlite3_column_text(st, 1);

            if (call_count == 0) {
                const char *sev_names[] = {"INFO","LOW","MEDIUM","HIGH","CRIT"};
                /* 统计总调用次数 */
                sqlite3_stmt *sc = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM xrefs x "
                    "JOIN symbols s ON x.to_addr=s.address "
                    "WHERE x.ref_type='call' AND s.name=?1",
                    -1, &sc, NULL);
                if (sc) {
                    sqlite3_bind_text(sc, 1, r->danger_func, -1, SQLITE_STATIC);
                    if (sqlite3_step(sc) == SQLITE_ROW) call_count = sqlite3_column_int(sc, 0);
                    sqlite3_finalize(sc);
                }

                if (r->severity == SEV_CRIT)  crit++;
                else if (r->severity == SEV_HIGH) high++;
                else if (r->severity == SEV_MEDIUM) med++;
                else if (r->severity == SEV_LOW) low++;
                else info++;

                total_calls += call_count;

                /* 标题: 严重度 + 函数名 + 调用次数 */
                snprintf(buf, sizeof(buf), "[%s] %-10s  (%d call sites)",
                         sev_names[r->severity], r->danger_func, call_count);
                fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)call_addr);
            }

            /* 每个调用点 */
            if (func_name) {
                snprintf(buf, sizeof(buf), "    0x%lx  in %s",
                         (unsigned long)call_addr, func_name);
            } else {
                snprintf(buf, sizeof(buf), "    0x%lx", (unsigned long)call_addr);
            }
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);

        /* 如果有调用点, 显示漏洞描述 + 利用提示 */
        if (call_count > 0) {
            snprintf(buf, sizeof(buf), "    → %s", r->pattern);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

            char hint[512];
            adjust_exploit_hint(&mit, r, hint, sizeof(hint));
            snprintf(buf, sizeof(buf), "    → 利用: %s", hint);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

            snprintf(buf, sizeof(buf), "    → 缓解: %s", r->mitigation);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        }
    }

    /* 仅导入但无调用点的危险函数 */
    fields_add(pd, "── Imported but no call sites ──", 0, 0, DETAIL_NONE, -1);
    int orphan = 0;
    for (int ri = 0; ri < NRULES; ri++) {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT s.name FROM symbols s "
            "WHERE s.name=?1 "
            "AND s.address NOT IN (SELECT DISTINCT to_addr FROM xrefs WHERE ref_type='call')",
            -1, &st, NULL);
        if (!st) continue;
        sqlite3_bind_text(st, 1, VULN_RULES[ri].danger_func, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf, sizeof(buf), "  %s — %s", VULN_RULES[ri].danger_func,
                     VULN_RULES[ri].pattern);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            orphan++;
        }
        sqlite3_finalize(st);
    }
    if (orphan == 0)
        fields_add(pd, "  (all dangerous imports are actively called)", 1, 0, DETAIL_NONE, -1);

    /* 总结 */
    fields_add(pd, "────────────────────", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "CRIT:%d HIGH:%d MED:%d LOW:%d INFO:%d — %d total calls",
             crit, high, med, low, info, total_calls);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (crit + high > 0) {
        snprintf(buf, sizeof(buf), "⚠ %d critical/high-risk functions actively called "
                 "— prioritize audit", crit + high);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        if (!mit.nx || !mit.pie || mit.relro < 2)
            fields_add(pd, "⚠ Mitigations incomplete — exploit surface larger than expected",
                       1, 0, DETAIL_NONE, -1);
    } else if (total_calls == 0) {
        fields_add(pd, "No dangerous functions actively called — low attack surface",
                   1, 0, DETAIL_NONE, -1);
    }

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始实现 (DB 不可用时降级)                                */
/* ================================================================== */

static int parse_vuln_mmap(Elf64_Ctx *ctx, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    char buf[512];
    int crit=0, high=0, med=0, low=0;

    mit_status_t mit;
    detect_mitigations(ctx, &mit);

    fields_add(pd, "=== Vulnerability Risk Report [mmap] ===", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "NX:%s  PIE:%s  RELRO:%s  CANARY:%s  (import scan only)",
             mit.nx ? "+" : "!", mit.pie ? "+" : "!",
             mit.relro == 2 ? "FULL" : mit.relro == 1 ? "PARTIAL" : "NONE",
             mit.canary ? "+" : "!");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "(DB unavailable — showing imported symbols, not actual calls)",
               1, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_DYNSYM : SHT_SYMTAB;
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_type != want) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;

            Elf64_Sym *syms = (Elf64_Sym*)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

            for (int j = 0; j < nsym; j++) {
                const char *n = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
                if (!n || !n[0]) continue;

                for (const vuln_rule_t *r = VULN_RULES; r->danger_func; r++) {
                    if (!strcmp(n, r->danger_func)) {
                        if (r->severity == SEV_CRIT) crit++;
                        else if (r->severity == SEV_HIGH) high++;
                        else if (r->severity == SEV_MEDIUM) med++;
                        else low++;

                        snprintf(buf, sizeof(buf), "[%s] %s",
                                 r->severity==SEV_CRIT?"CRIT":r->severity==SEV_HIGH?"HIGH":
                                 r->severity==SEV_MEDIUM?"MED":"LOW", n);
                        fields_add(pd, buf, 1, 1, DETAIL_NONE, j);
                        fields_add(pd, r->pattern, 2, 0, DETAIL_NONE, -1);
                        break;
                    }
                }
            }
        }
    }

    fields_add(pd, "────────────────────", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "CRIT:%d HIGH:%d MED:%d LOW:%d — "
             "Total: %d dangerous imports", crit, high, med, low, crit+high+med+low);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* 公共 API                                                            */
/* ================================================================== */

int translate_vuln_scan(Elf64_Ctx *ctx, PanelData *pd)
{
    if (g_active_db)
        return parse_vuln_db(g_active_db, ctx, pd);
    return parse_vuln_mmap(ctx, pd);
}

/**
 * 翻译单个危险函数调用到自然语言风险描述。
 * (保持原有 API — 不依赖 DB)
 */
int translate_vuln_single(const char *func_name, char *buf, size_t bufsz)
{
    if (!func_name || !buf) return -1;

    for (const vuln_rule_t *r = VULN_RULES; r->danger_func; r++) {
        if (!strcmp(func_name, r->danger_func)) {
            const char *sevs[] = {"INFO","LOW","MEDIUM","HIGH","CRIT"};
            snprintf(buf, bufsz,
                     "[%s] %s → %s\n"
                     "    缓解: %s\n"
                     "    利用: %s",
                     sevs[r->severity], func_name, r->pattern,
                     r->mitigation, r->exploit_hint);
            return 0;
        }
    }
    snprintf(buf, bufsz, "[LOW] %s → 潜在风险函数 — 需人工审计", func_name);
    return 0;
}
