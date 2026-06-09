/*
 * security.c — 安全加固检查模块 (elf-tui)
 *
 * 对标 checksec 准确性, 检测 8 项缓解措施:
 *   1. NX         — PT_GNU_STACK 的 PF_X 标志
 *   2. RELRO      — PT_GNU_RELRO + DT_BIND_NOW / DF_BIND_NOW
 *   3. PIE        — e_type == ET_DYN (直接读 ELF Header)
 *   4. Stack Canary — __stack_chk_fail / __stack_chk_guard 符号
 *   5. CET        — endbr64 指令扫描
 *   6. Fortify    — _chk 函数变体计数
 *   7. RPATH      — DT_RPATH 检测
 *   8. RUNPATH    — DT_RUNPATH 检测
 *   9. Symbols    — 符号表是否 strip
 *
 * 接口: int parse_security(Elf64_Ctx *ctx, PanelData *pd);
 */

#include "elf_parser.h"
#include "core/query.h"
#include <string.h>
#include <stdio.h>

/* ================================================================== */
/* 动态节辅助: 查找 d_tag 对应的值                                      */
/* ================================================================== */

static int dyn_find(Elf64_Ctx *ctx, Elf64_Sxword tag, uint64_t *out)
{
    /* PT_DYNAMIC 的 p_offset 直接指向文件中的动态表 — 不用 vaddr 转换 */
    Elf64_Ehdr *eh = (Elf64_Ehdr *)ctx->map;
    int phnum = (int)eh->e_phnum;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(ctx->map + eh->e_phoff);

    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC && phdrs[i].p_filesz > 0) {
            Elf64_Dyn *dyn = (Elf64_Dyn *)(ctx->map + phdrs[i].p_offset);
            int ndyn = (int)(phdrs[i].p_filesz / sizeof(Elf64_Dyn));
            for (int j = 0; j < ndyn; j++) {
                if (dyn[j].d_tag == tag) {
                    *out = dyn[j].d_un.d_val;
                    return 0;
                }
            }
            return -1;  /* 找到了段但没找到 tag */
        }
    }
    return -1;
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int parse_security(Elf64_Ctx *ctx, PanelData *pd)
{
    QueryDB *qdb = query_open(ctx);
    char buf[400];
    int score = 0, total = 9;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)ctx->map;
    int phnum = (int)eh->e_phnum;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(ctx->map + eh->e_phoff);
    int shnum = (int)eh->e_shnum;

    fields_add(pd, "=== Security Mitigation Report ===", 0, 0, DETAIL_NONE, -1);

    /* 1. NX — PT_GNU_STACK 的 PF_X 标志 */
    {
        int nx = 1, has = 0;
        for (int i = 0; i < phnum; i++) {
            if (phdrs[i].p_type == PT_GNU_STACK) {
                has = 1;
                nx = !(phdrs[i].p_flags & PF_X);
                break;
            }
        }
        if (has)
            snprintf(buf, sizeof(buf), "[%s] NX — GNU_STACK %s",
                     nx ? "+" : "!", nx ? "NX enabled" : "EXECUTABLE (!)");
        else
            snprintf(buf, sizeof(buf), "[%s] NX — kernel default (no GNU_STACK segment)",
                     nx ? "+" : "!");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (nx) score++;
    }

    /* 2. RELRO — PT_GNU_RELRO + DT_BIND_NOW */
    {
        int has_relro = 0, full = 0;
        for (int i = 0; i < phnum; i++) {
            if (phdrs[i].p_type == PT_GNU_RELRO) { has_relro = 1; break; }
        }
        if (has_relro) {
            uint64_t val = 0;
            /* Full RELRO 三种检测方式 (linker版本不同, 用的标志位不同):
             *   DT_BIND_NOW (24) — 独立条目, val 忽略
             *   DT_FLAGS (30)   — DF_BIND_NOW=8 置位
             *   DT_FLAGS_1 (0x6ffffffb) — DF_1_NOW=1 置位 */
            if (dyn_find(ctx, DT_BIND_NOW, &val) == 0)
                full = 1;
            else if (dyn_find(ctx, DT_FLAGS, &val) == 0 && (val & DF_BIND_NOW))
                full = 1;
            else if (dyn_find(ctx, DT_FLAGS_1, &val) == 0 && (val & DF_1_NOW))
                full = 1;
        }
        if (full) {
            snprintf(buf, sizeof(buf), "[+] RELRO (Full) — GOT read-only"); score++;
        } else if (has_relro) {
            snprintf(buf, sizeof(buf), "[~] RELRO (Partial) — .got.plt writable");
        } else {
            snprintf(buf, sizeof(buf), "[!] RELRO (None) — no read-only relocations");
        }
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 3. PIE — e_type == ET_DYN */
    {
        int is_pie = (eh->e_type == ET_DYN);
        snprintf(buf, sizeof(buf), "[%s] PIE (%s) — %s", is_pie ? "+" : "!",
                 is_pie ? "ET_DYN" : "ET_EXEC",
                 is_pie ? "ASLR enabled" : "fixed base, ASLR disabled");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (is_pie) score++;
    }

    /* 4. Stack Canary */
    {
        uint64_t dummy;
        int has_guard = (qdb && query_sym_by_name(qdb, "__stack_chk_guard", &dummy) == 0);
        int has_fail  = (qdb && query_sym_by_name(qdb, "__stack_chk_fail", &dummy) == 0);
        int has = has_guard || has_fail;
        snprintf(buf, sizeof(buf), "[%s] Stack Canary — %s", has ? "+" : "!",
                 has ? "__stack_chk_fail/guard found" : "no stack protector");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (has) score++;
    }

    /* 5. CET — 扫描 endbr64 */
    {
        int has = 0;
        const uint8_t ENDBR64[] = {0xf3, 0x0f, 0x1e, 0xfa};
        for (int i = 0; i < shnum && !has; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (!sh || !(sh->sh_flags & SHF_EXECINSTR) || sh->sh_size < 4) continue;
            const uint8_t *d = ctx->map + sh->sh_offset;
            for (size_t off = 0; off + 4 <= sh->sh_size; off++)
                if (memcmp(d + off, ENDBR64, 4) == 0) { has = 1; break; }
        }
        snprintf(buf, sizeof(buf), "[%s] CET (IBT) — %s", has ? "+" : "!",
                 has ? "endbr64 detected" : "no CET");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (has) score++;
    }

    /* 6. Fortify Source — 对标 checksec:
     *    从系统 libc 的 .dynsym 动态获取全部 _chk 函数列表,
     *    而非硬编码静态函数对。不同 glibc 版本 _chk 集合不同。 */
    {
        uint64_t dummy;
        int fortified = 0, fortifiable = 0;

        /* 找 libc */
        static const char *libc_paths[] = {
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/lib/libc.so.6", NULL
        };
        const char *libc_path = NULL;
        for (const char **sp = libc_paths; *sp; sp++) {
            FILE *fp = fopen(*sp, "r");
            if (fp) { fclose(fp); libc_path = *sp; break; }
        }

        if (libc_path) {
            Elf64_Ctx *lc = elf_open(libc_path);
            if (lc) {
                QueryDB *lqdb = query_open(lc);
                if (lqdb) {
                    int nsym = query_sym_count(lqdb);
                    char name[128]; uint64_t a; unsigned char info;
                    for (int i = 0; i < nsym; i++) {
                        if (query_sym_by_index(lqdb, i, &a, name, sizeof(name), &info) != 0)
                            continue;
                        /* 匹配 __xxx_chk: 去掉 __ 前缀和 _chk 后缀 */
                        if (!strstr(name, "_chk") || name[0]!='_' || name[1]!='_')
                            continue;
                        const char *base = name + 2;
                        char *chk = strstr(base, "_chk");
                        if (!chk || chk == base) continue;
                        size_t blen = (size_t)(chk - base);
                        char plain[128];
                        memcpy(plain, base, blen); plain[blen] = '\0';
                        /* 在目标二进制中查 */
                        if (query_sym_by_name(qdb, plain, &dummy) == 0)
                            fortifiable++;
                        if (query_sym_by_name(qdb, name, &dummy) == 0)
                            fortified++;
                    }
                    query_close(lqdb);
                }
                elf_close(lc);
            }
        }

        if (fortified > 0) {
            snprintf(buf, sizeof(buf), "[+] Fortify Source — FORTIFY: Yes  "
                     "Fortified: %d  Fortifiable: %d", fortified, fortifiable);
            score++;
        } else if (fortifiable > 0) {
            snprintf(buf, sizeof(buf), "[!] Fortify Source — FORTIFY: No   "
                     "Fortified: 0  Fortifiable: %d", fortifiable);
        } else {
            snprintf(buf, sizeof(buf), "[~] Fortify Source — "
                     "libc not found or no fortifiable imports");
        }
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 7. RPATH */
    {
        uint64_t val = 0;
        int has = (dyn_find(ctx, DT_RPATH, &val) == 0);
        snprintf(buf, sizeof(buf), "[%s] RPATH — %s", has ? "!" : "+",
                 has ? "present (insecure library path)" : "not set");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (!has) score++;
    }

    /* 8. RUNPATH */
    {
        uint64_t val = 0;
        int has = (dyn_find(ctx, DT_RUNPATH, &val) == 0);
        snprintf(buf, sizeof(buf), "[%s] RUNPATH — %s", has ? "!" : "+",
                 has ? "present" : "not set");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (!has) score++;
    }

    /* 9. Symbols — 是否被 strip */
    {
        int has = 0;
        for (int i = 0; i < shnum && !has; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (sh && sh->sh_type == SHT_SYMTAB && sh->sh_size > 0) has = 1;
        }
        snprintf(buf, sizeof(buf), "[%s] Symbols — %s", has ? "!" : "+",
                 has ? "not stripped (info leak risk)" : "stripped");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
        if (!has) score++;
    }

    /* ── 总结 ── */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);
    const char *verdict;
    if (score == total)      verdict = "Excellent — all mitigations";
    else if (score >= total-2) verdict = "Good — nearly all enabled";
    else if (score >= total/2) verdict = "Fair — some protections missing";
    else                      verdict = "Weak — easy exploitation possible";
    snprintf(buf, sizeof(buf), "Score: %d/%d — %s", score, total, verdict);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    query_close(qdb);
    return pd->count;
}
