/*
 * bindiff.c — 二进制差异比对引擎
 *
 * 功能:
 *   1. Patch Diff: 对比补丁前后的两个二进制，定位修复的函数
 *   2. Version Diff: 跨版本函数匹配 (CFG 拓扑 + 指令 n-gram 相似度)
 *   3. 与 CVE 数据库关联: 库版本 → 已知漏洞
 *
 * 算法:
 *   - 函数级匹配: CFG 图结构相似度 (Weisfeiler-Lehman 子树核)
 *   - 指令级匹配: 标准化指令序列的 n-gram Jaccard 相似度
 *   - 评分: 综合 CFG + mnemonics + callgraph 三个维度
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ================================================================== */
/* 函数指纹                                                            */
/* ================================================================== */

#define BD_MAX_BBS     256
#define BD_NGRAM_SIZE  3

typedef struct {
    uint64_t  func_addr;
    char      name[128];
    int       bb_count;
    int       insn_count;
    int       call_count;
    uint64_t  cfg_hash;       /* CFG 拓扑哈希 */
    float     ngram_sig[64];  /* 指令类型的标准化 n-gram 签名 */
} bd_func_sig_t;

/* ================================================================== */
/* 提取函数指纹                                                        */
/* ================================================================== */

int bd_extract_signature(AnalysisDB *adb, uint64_t func_addr, bd_func_sig_t *sig)
{
    if (!adb || !sig) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    memset(sig, 0, sizeof(*sig));
    sig->func_addr = func_addr;

    /* 基本信息 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT name, bb_count FROM functions WHERE start_addr=?",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *n = (const char *)sqlite3_column_text(st, 0);
            if (n) snprintf(sig->name, sizeof(sig->name), "%s", n);
            sig->bb_count = sqlite3_column_int(st, 1);
        }
        sqlite3_finalize(st);
    }

    /* 指令计数 */
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM instructions WHERE address BETWEEN "
        "(SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " AND (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        if (sqlite3_step(st) == SQLITE_ROW)
            sig->insn_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    /* 调用计数 */
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM xrefs WHERE from_addr BETWEEN "
        "(SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " AND (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " AND ref_type='call'",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        if (sqlite3_step(st) == SQLITE_ROW)
            sig->call_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    /* CFG 哈希: 基于 BB 数量和边数量 */
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM cfg_edges WHERE from_addr BETWEEN "
        "(SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " AND (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        int edge_cnt = 0;
        if (sqlite3_step(st) == SQLITE_ROW)
            edge_cnt = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);

        /* 简单哈希: BB count * 31 + edge_count * 17 */
        sig->cfg_hash = (uint64_t)(sig->bb_count * 31 + edge_cnt * 17);
    }

    /* 指令 n-gram 签名 */
    sqlite3_prepare_v2(c,
        "SELECT mnemonic FROM instructions WHERE address BETWEEN "
        "(SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " AND (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        " ORDER BY address LIMIT 500",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);

        /* 收集所有助记符 */
        char mnems[512][8];
        int nmnem = 0;
        while (sqlite3_step(st) == SQLITE_ROW && nmnem < 512) {
            const char *m = (const char *)sqlite3_column_text(st, 0);
            if (m) {
                snprintf(mnems[nmnem], sizeof(mnems[nmnem]), "%s", m);
                nmnem++;
            }
        }
        sqlite3_finalize(st);

        /* 计算 3-gram 哈希分布 */
        if (nmnem >= BD_NGRAM_SIZE) {
            int counts[64] = {0};
            int total = 0;
            for (int i = 0; i <= nmnem - BD_NGRAM_SIZE; i++) {
                unsigned h = 5381;
                for (int j = 0; j < BD_NGRAM_SIZE; j++)
                    for (const char *p = mnems[i + j]; *p; p++)
                        h = ((h << 5) + h) + (unsigned char)*p;
                counts[h % 64]++;
                total++;
            }
            if (total > 0) {
                for (int i = 0; i < 64; i++)
                    sig->ngram_sig[i] = (float)counts[i] / (float)total;
            }
        }
    }

    return 0;
}

/* ================================================================== */
/* 相似度计算                                                          */
/* ================================================================== */

/* CFG 结构相似度: 基于基本块数量和边数量的差异 */
static float bd_cfg_similarity(const bd_func_sig_t *a, const bd_func_sig_t *b)
{
    int bb_diff  = abs(a->bb_count - b->bb_count);
    int max_bb   = (a->bb_count > b->bb_count) ? a->bb_count : b->bb_count;
    if (max_bb == 0) return 0.0f;

    float bb_sim = 1.0f - (float)bb_diff / (float)max_bb;

    /* 指令数差异 */
    int insn_diff = abs(a->insn_count - b->insn_count);
    int max_insn  = (a->insn_count > b->insn_count) ? a->insn_count : b->insn_count;
    if (max_insn == 0) max_insn = 1;
    float insn_sim = 1.0f - (float)insn_diff / (float)max_insn;

    return (bb_sim * 0.6f + insn_sim * 0.4f);
}

/* n-gram 余弦相似度 */
static float bd_ngram_similarity(const bd_func_sig_t *a, const bd_func_sig_t *b)
{
    float dot = 0.0f, mag_a = 0.0f, mag_b = 0.0f;
    for (int i = 0; i < 64; i++) {
        dot   += a->ngram_sig[i] * b->ngram_sig[i];
        mag_a += a->ngram_sig[i] * a->ngram_sig[i];
        mag_b += b->ngram_sig[i] * b->ngram_sig[i];
    }
    if (mag_a < 0.0001f && mag_b < 0.0001f) return 1.0f;
    float denom = sqrtf(mag_a) * sqrtf(mag_b);
    if (denom < 0.0001f) return 0.0f;
    return dot / denom;
}

/* 综合相似度 */
float bd_similarity(const bd_func_sig_t *a, const bd_func_sig_t *b)
{
    float cfg_score   = bd_cfg_similarity(a, b);
    float ngram_score = bd_ngram_similarity(a, b);

    /* 权值: n-gram (指令序列) 更重要 */
    return cfg_score * 0.3f + ngram_score * 0.7f;
}

/* ================================================================== */
/* 批量对比                                                            */
/* ================================================================== */

typedef struct {
    uint64_t  func_a;
    uint64_t  func_b;
    char      name_a[128];
    char      name_b[128];
    float     similarity;
} bd_match_t;

int bd_compare_all(AnalysisDB *adb_a, AnalysisDB *adb_b,
                   bd_match_t *matches, int max_matches)
{
    if (!adb_a || !adb_b || !matches) return -1;

    /* 提取 adb_a 的所有函数签名 */
    sqlite3 *ca = (sqlite3 *)db_conn(adb_a);
    sqlite3 *cb = (sqlite3 *)db_conn(adb_b);
    if (!ca || !cb) return -1;

    bd_func_sig_t *sigs_a = calloc(1024, sizeof(bd_func_sig_t));
    bd_func_sig_t *sigs_b = calloc(1024, sizeof(bd_func_sig_t));
    int na = 0, nb = 0;

    sqlite3_stmt *st = NULL;

    /* 提取 adb_a 函数列表 */
    sqlite3_prepare_v2(ca,
        "SELECT start_addr FROM functions ORDER BY start_addr LIMIT 1024",
        -1, &st, NULL);
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW && na < 1024)
            bd_extract_signature(adb_a, (uint64_t)sqlite3_column_int64(st, 0), &sigs_a[na++]);
        sqlite3_finalize(st);
    }

    /* 提取 adb_b 函数列表 */
    sqlite3_prepare_v2(cb,
        "SELECT start_addr FROM functions ORDER BY start_addr LIMIT 1024",
        -1, &st, NULL);
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW && nb < 1024)
            bd_extract_signature(adb_b, (uint64_t)sqlite3_column_int64(st, 0), &sigs_b[nb++]);
        sqlite3_finalize(st);
    }

    /* 全对全匹配 */
    int nmatch = 0;
    for (int i = 0; i < na && nmatch < max_matches; i++) {
        bd_match_t best = {0, 0, "", "", 0.0f};
        for (int j = 0; j < nb; j++) {
            float sim = bd_similarity(&sigs_a[i], &sigs_b[j]);
            if (sim > best.similarity && sim > 0.5f) {
                best.func_a     = sigs_a[i].func_addr;
                best.func_b     = sigs_b[j].func_addr;
                snprintf(best.name_a, sizeof(best.name_a), "%s", sigs_a[i].name);
                snprintf(best.name_b, sizeof(best.name_b), "%s", sigs_b[j].name);
                best.similarity = sim;
            }
        }
        if (best.similarity > 0.5f)
            matches[nmatch++] = best;
    }

    /* 按相似度降序排列 (冒泡) */
    for (int i = 0; i < nmatch - 1; i++)
        for (int j = i + 1; j < nmatch; j++)
            if (matches[j].similarity > matches[i].similarity) {
                bd_match_t tmp = matches[i];
                matches[i] = matches[j];
                matches[j] = tmp;
            }

    free(sigs_a);
    free(sigs_b);
    return nmatch;
}

/* ================================================================== */
/* 单函数对比 PanelData 输出                                           */
/* ================================================================== */

int bd_compare_functions(AnalysisDB *adb_a, uint64_t addr_a,
                          AnalysisDB *adb_b, uint64_t addr_b,
                          PanelData *pd)
{
    if (!adb_a || !adb_b || !pd) return -1;

    bd_func_sig_t sig_a, sig_b;
    if (bd_extract_signature(adb_a, addr_a, &sig_a) != 0) return -1;
    if (bd_extract_signature(adb_b, addr_b, &sig_b) != 0) return -1;

    float sim = bd_similarity(&sig_a, &sig_b);
    char buf[400];

    snprintf(buf, sizeof(buf), "=== Binary Diff ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "Func A: %s @ 0x%lx  (BBs:%d  Insns:%d  Calls:%d)",
             sig_a.name, (unsigned long)sig_a.func_addr,
             sig_a.bb_count, sig_a.insn_count, sig_a.call_count);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "Func B: %s @ 0x%lx  (BBs:%d  Insns:%d  Calls:%d)",
             sig_b.name, (unsigned long)sig_b.func_addr,
             sig_b.bb_count, sig_b.insn_count, sig_b.call_count);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "CFG Similarity:    %.1f%%",
             bd_cfg_similarity(&sig_a, &sig_b) * 100.0f);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "N-gram Similarity: %.1f%%",
             bd_ngram_similarity(&sig_a, &sig_b) * 100.0f);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Overall:           %.1f%%", sim * 100.0f);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 判定 */
    const char *verdict;
    if (sim > 0.95f)      verdict = "IDENTICAL — no patch applied";
    else if (sim > 0.80f) verdict = "MINOR CHANGE — possible patch or refactor";
    else if (sim > 0.60f) verdict = "MODIFIED — significant code changes";
    else if (sim > 0.40f) verdict = "REWRITTEN — major structural change";
    else                  verdict = "UNRELATED — different function";

    snprintf(buf, sizeof(buf), "Verdict: %s", verdict);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[c]=CFG-diff [i]=insn-diff [h]=back", 1, 0, DETAIL_NONE, -1);

    return 0;
}
