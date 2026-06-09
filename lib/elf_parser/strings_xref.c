/*
 * strings_xref.c — 字符串交叉引用
 *
 * 功能: 找出代码中 LEA/MOV 指令引用了哪些字符串。
 * 混合方案: DB 有 strings 表 → 直接查 (免字节扫描)
 *           DB 不可用 → 全量扫描降级
 * 代码段始终用 Capstone 扫描, bsearch 匹配。
 *
 * 接口: int parse_strings_xref(Elf64_Ctx *ctx, PanelData *pd);
 */
#include "elf_parser.h"
#include "core/db.h"
#include "disasm.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

extern AnalysisDB *g_active_db;

#define S_MAX 16384
#define R_MAX 16384

typedef struct { uint64_t a; char t[128]; int l, rc; } srec_t;
typedef struct { uint64_t ra; int si; } ref_t;

static int s_cmp(const void *x, const void *y) {
    return ((const srec_t *)x)->a < ((const srec_t *)y)->a ? -1 : 1;
}

static void clean_str(const char *s, char *d, int max) {
    int j = 0;
    for (const char *p = s; *p && j < max; p++)
        d[j++] = (*p == '\n' || *p == '\r' || *p == '\t') ? ' ' : *p;
    d[j] = '\0';
}

/* ── 从 raw 字节提取字符串 ──────────────────────────────────── */

static int extract_raw(Elf64_Ctx *ctx, srec_t *ss, int cap)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum, ns = 0;
    for (int si = 0; si < shnum && ns < cap; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_flags & SHF_EXECINSTR) continue;
        const uint8_t *d = ctx->map + sh->sh_offset;
        size_t sz = sh->sh_size, p = 0;
        while (p < sz && ns < cap) {
            while (p < sz && !isprint(d[p]) && d[p] != '\t') p++;
            if (p >= sz) break;
            size_t e = p;
            while (e < sz && (isprint(d[e]) || d[e] == '\t')) e++;
            int l = (int)(e - p);
            while (l > 0 && d[p+l-1] == ' ') l--;
            if (l >= 4 && l < 128) {
                ss[ns].a = sh->sh_addr + p;
                memcpy(ss[ns].t, d+p, (size_t)l); ss[ns].t[l] = '\0';
                ss[ns].l = l; ns++;
            }
            p = e + 1;
        }
    }
    return ns;
}

/* ── 从 DB strings 表读取字符串 ────────────────────────────── */

static int extract_db(AnalysisDB *adb, srec_t *ss, int cap)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT address, value, length FROM strings ORDER BY address",
        -1, &st, NULL);
    if (!st) return 0;
    int ns = 0;
    while (sqlite3_step(st) == SQLITE_ROW && ns < cap) {
        ss[ns].a = (uint64_t)sqlite3_column_int64(st, 0);
        const char *txt = (const char *)sqlite3_column_text(st, 1);
        int len = sqlite3_column_int(st, 2);
        if (txt && len >= 4 && len < 128) {
            clean_str(txt, ss[ns].t, 100);
            ss[ns].l = len; ns++;
        }
    }
    sqlite3_finalize(st);
    return ns;
}

/* ── 扫描代码段找引用 (bsearch 匹配) ────────────────────────── */

static int scan_code(Elf64_Ctx *ctx, srec_t *ss, int ns, ref_t *rr, int cap)
{
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum, nr = 0;
    for (int si = 0; si < shnum && nr < cap; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size == 0) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;
        disasm_ctx *d = disasm_open();
        if (!d) continue;
        const uint8_t *cd = ctx->map + sh->sh_offset;
        size_t sz = sh->sh_size; uint64_t ad = sh->sh_addr;
        while (sz > 0 && disasm_next(d, &cd, &sz, &ad)) {
            cs_insn *in = disasm_insn(d);
            if (!in->detail) continue;
            if (in->id != X86_INS_LEA && in->id != X86_INS_MOV &&
                in->id != X86_INS_MOVABS) continue;
            cs_x86 *x = &in->detail->x86;
            for (uint8_t oi = 0; oi < x->op_count; oi++) {
                uint64_t t = 0;
                if (in->id == X86_INS_LEA && x->operands[oi].type == X86_OP_MEM
                    && x->operands[oi].mem.base == X86_REG_RIP)
                    t = (uint64_t)((int64_t)in->address + (int64_t)in->size
                                   + x->operands[oi].mem.disp);
                else if ((in->id == X86_INS_MOV || in->id == X86_INS_MOVABS)
                         && x->operands[oi].type == X86_OP_IMM)
                    t = (uint64_t)x->operands[oi].imm;
                if (t < 0x1000) continue;
                srec_t k = {t}; srec_t *f = bsearch(&k, ss, (size_t)ns, sizeof(srec_t), s_cmp);
                if (f && nr < cap) {
                    int idx = (int)(f - ss);
                    rr[nr].ra = in->address; rr[nr].si = idx;
                    ss[idx].rc++; nr++;
                }
            }
        }
        disasm_close(d);
    }
    return nr;
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int parse_strings_xref(Elf64_Ctx *ctx, PanelData *pd)
{
    srec_t *ss = calloc(S_MAX, sizeof(srec_t));
    ref_t  *rr = calloc(R_MAX, sizeof(ref_t));
    if (!ss || !rr) { free(ss); free(rr);
        fields_add(pd, "(memory error)", 0, 0, DETAIL_NONE, -1); return -1; }

    /* Step 1: 提取字符串 — DB 优先 (快), raw 降级 */
    int ns;
    if (g_active_db)
        ns = extract_db(g_active_db, ss, S_MAX);
    else
        ns = extract_raw(ctx, ss, S_MAX);

    /* Step 2: 排序, 然后扫描代码段找引用 */
    qsort(ss, (size_t)ns, sizeof(srec_t), s_cmp);
    int nr = scan_code(ctx, ss, ns, rr, R_MAX);

    /* Step 3: 按引用次数降序 */
    for (int i = 0; i < ns-1; i++) {
        int best = i;
        for (int j = i+1; j < ns; j++)
            if (ss[j].rc > ss[best].rc) best = j;
        if (best != i) { srec_t t = ss[i]; ss[i] = ss[best]; ss[best] = t; }
    }

    /* Step 4: 输出 */
    char buf[512];
    fields_add(pd, "=== String Cross-References ===", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "%d strings, %d refs  |  Enter on address = jump to disasm",
             ns, nr);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    int seq = 0;

    /* 有引用的字符串 */
    for (int i = 0; i < ns; i++) {
        if (ss[i].rc == 0) continue;
        seq++;
        char cl[100]; clean_str(ss[i].t, cl, 90);
        snprintf(buf, sizeof(buf), "[%d] \"%s\"%s", seq, cl, ss[i].l>90?"...":"");
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

        uint64_t seen[64]; int ns2 = 0;
        for (int r = 0; r < nr && ns2 < 64; r++) {
            if (rr[r].si != i) continue;
            int dup = 0;
            for (int s2 = 0; s2 < ns2; s2++) if (seen[s2]==rr[r].ra) {dup=1;break;}
            if (!dup) seen[ns2++] = rr[r].ra;
        }
        for (int s2 = 0; s2 < ns2; s2++) {
            snprintf(buf, sizeof(buf), "     ← 0x%lx", (unsigned long)seen[s2]);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)(seen[s2] & 0x7FFFFFFF));
        }
    }

    if (seq == 0) {
        fields_add(pd, "(no string references found)", 0, 0, DETAIL_NONE, -1);
    }

    /* 未引用的字符串 */
    int unref = 0;
    for (int i = 0; i < ns; i++) {
        if (ss[i].rc > 0) continue;
        if (unref == 0) {
            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            fields_add(pd, "── Unreferenced strings ──", 0, 0, DETAIL_NONE, -1);
        }
        seq++; unref++;
        char cl[100]; clean_str(ss[i].t, cl, 90);
        snprintf(buf, sizeof(buf), "[%d] \"%s\"%s", seq, cl, ss[i].l>90?"...":"");
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    snprintf(buf, sizeof(buf), "── %d total, %d referenced, %d unreferenced ──",
             ns, seq - unref, unref);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    free(ss); free(rr);
    return pd->count;
}
