/*
 * callgraph.c — 函数交叉引用图 (Caller/Callee Graph)
 *
 * 双路径架构:
 *   DB 路径:  从 xrefs/instructions/symbols 表直接查询 (零反汇编)
 *   mmap 路径: 反汇编所有代码段, 收集 call 指令 (原有逻辑, DB 不可用时降级)
 *
 * 接口: int parse_callgraph(Elf64_Ctx *ctx, PanelData *pd);
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
/* 数据结构                                                           */
/* ================================================================== */

#define MAX_RELS 8192

typedef struct {
    uint64_t from_addr;        /* call 指令所在地址       */
    uint64_t to_addr;          /* 被调用函数的地址         */
    char     from_name[128];   /* caller 函数名           */
    char     to_name[128];     /* callee 函数名           */
} cg_edge_t;

typedef struct {
    cg_edge_t *edges;
    int        count;
    int        capacity;
} cg_graph_t;

/* ── 符号地址→名称快速查找表 (排序数组 + 二分查找) ─────────────── */

typedef struct {
    uint64_t addr;
    char     name[128];
} sym_lookup_t;

static int sym_cmp_by_addr(const void *a, const void *b)
{
    uint64_t ua = ((const sym_lookup_t *)a)->addr;
    uint64_t ub = ((const sym_lookup_t *)b)->addr;
    if (ua < ub) return -1;
    if (ua > ub) return  1;
    return 0;
}

/* 从 ELF 符号表构建排序查找表, 返回条目数 */
static int sym_lookup_build(Elf64_Ctx *ctx, sym_lookup_t **out, int *out_cap)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    int cap = 256, count = 0;
    sym_lookup_t *tab = calloc((size_t)cap, sizeof(sym_lookup_t));
    if (!tab) return 0;

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
                if (syms[j].st_value == 0) continue;
                if (ELF64_ST_TYPE(syms[j].st_info) != STT_FUNC) continue;
                if (count >= cap) {
                    cap *= 2;
                    sym_lookup_t *nt = realloc(tab, (size_t)cap * sizeof(sym_lookup_t));
                    if (!nt) { free(tab); return 0; }
                    tab = nt;
                }
                tab[count].addr = syms[j].st_value;
                const char *n = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
                snprintf(tab[count].name, sizeof(tab[count].name), "%s", n ? n : "");
                count++;
            }
        }
    }

    qsort(tab, (size_t)count, sizeof(sym_lookup_t), sym_cmp_by_addr);
    *out = tab;
    if (out_cap) *out_cap = cap;
    return count;
}

/* 二分查找: 找 <= addr 的最大函数地址 (包含关系) */
static const char *sym_lookup_resolve(sym_lookup_t *tab, int count,
                                       uint64_t addr, char *buf, size_t bufsz)
{
    if (!tab || count <= 0) goto fallback;

    /* 精确匹配 */
    sym_lookup_t key = {addr, ""};
    sym_lookup_t *hit = (sym_lookup_t *)bsearch(&key, tab, (size_t)count,
                                                  sizeof(sym_lookup_t), sym_cmp_by_addr);
    if (hit) {
        snprintf(buf, bufsz, "%s", hit->name);
        return buf;
    }

    /* 查找包含该地址的最大函数 (addr 在某个函数体内) */
    int lo = 0, hi = count - 1, best = -1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (tab[mid].addr <= addr) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best >= 0 && addr - tab[best].addr < 4096) {
        snprintf(buf, bufsz, "%s+0x%lx", tab[best].name,
                 (unsigned long)(addr - tab[best].addr));
        return buf;
    }

fallback:
    snprintf(buf, bufsz, "sub_%lx", (unsigned long)addr);
    return buf;
}

/* 边排序比较器 (按 from_addr) */
static int cg_edge_cmp(const void *a, const void *b)
{
    uint64_t ua = ((const cg_edge_t *)a)->from_addr;
    uint64_t ub = ((const cg_edge_t *)b)->from_addr;
    if (ua < ub) return -1;
    if (ua > ub) return  1;
    return 0;
}

/* ================================================================== */
/* 辅助: 地址 → 函数名                                                */
/* ================================================================== */

/**
 * 在 .symtab 和 .dynsym 中查找地址对应的函数名。
 * 如果找不到，返回格式化的地址字符串。
 */
static const char *resolve_name(Elf64_Ctx *ctx, uint64_t addr,
                                char *buf, size_t bufsz)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (int i = 0; i < shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (!sh || sh->sh_type != want) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;

            Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

            /* 找精确匹配或包含该地址的函数 */
            const char *candidate = NULL;
            uint64_t    cand_addr = 0;

            for (int j = 0; j < nsym; j++) {
                if (ELF64_ST_TYPE(syms[j].st_info) != STT_FUNC) continue;
                if (syms[j].st_value == 0) continue;
                if (syms[j].st_value == addr) {
                    /* 精确匹配 */
                    const char *n = elf_strtab_get(ctx, strsh->sh_offset,
                                                   syms[j].st_name);
                    if (n && n[0]) { snprintf(buf, bufsz, "%s", n); return buf; }
                }
                if (syms[j].st_value <= addr &&
                    syms[j].st_value > cand_addr) {
                    cand_addr = syms[j].st_value;
                    candidate = elf_strtab_get(ctx, strsh->sh_offset,
                                               syms[j].st_name);
                }
            }

            if (candidate && addr < cand_addr + 4096) {
                /* 在候选函数 +4KB 范围内, 假设属于该函数 */
                snprintf(buf, bufsz, "%s+0x%lx",
                         candidate, (unsigned long)(addr - cand_addr));
                return buf;
            }
        }
    }

    snprintf(buf, bufsz, "sub_%lx", (unsigned long)addr);
    return buf;
}

/* ================================================================== */
/* 反汇编回调: 收集 call 边                                           */
/* ================================================================== */

typedef struct {
    cg_graph_t *g;
    Elf64_Ctx  *ctx;
    char        current_func[128];  /* 当前正在扫描的函数名 */
    /* 快速符号查找表 (预构建, 二分查找) */
    sym_lookup_t *sym_tab;
    int           sym_count;
} cg_collect_t;

static bool cg_on_insn(const cs_insn *insn, void *user)
{
    cg_collect_t *coll = (cg_collect_t *)user;

    if (!insn->detail) return true;

    /* 只关心 call 指令 */
    int is_call = 0;
    for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
        if (insn->detail->groups[g] == X86_GRP_CALL) { is_call = 1; break; }
    }
    if (!is_call) return true;

    /* 提取目标地址 */
    uint64_t target = 0;
    cs_x86 *x86 = &insn->detail->x86;
    for (uint8_t oi = 0; oi < x86->op_count; oi++) {
        if (x86->operands[oi].type == X86_OP_IMM) {
            target = (uint64_t)x86->operands[oi].imm;
            break;
        }
    }
    if (target == 0) return true;

    /* 扩容 */
    if (coll->g->count >= coll->g->capacity) {
        coll->g->capacity = coll->g->capacity ? coll->g->capacity * 2 : 512;
        cg_edge_t *ne = realloc(coll->g->edges,
            (size_t)coll->g->capacity * sizeof(cg_edge_t));
        if (!ne) return false;
        coll->g->edges = ne;
    }

    /* 记录边 */
    cg_edge_t *e = &coll->g->edges[coll->g->count++];
    e->from_addr = insn->address;
    e->to_addr   = target;

    /* 解析名称: 使用预构建的二分查找表 (O(log N) vs 原始 O(N)) */
    char buf[192];
    snprintf(e->from_name, sizeof(e->from_name), "%s",
             coll->current_func);
    sym_lookup_resolve(coll->sym_tab, coll->sym_count, target, buf, sizeof(buf));
    snprintf(e->to_name, sizeof(e->to_name), "%.127s", buf);

    return true;
}

/* ================================================================== */
/* DB 路径: 从 xrefs + symbols 表直接查询                              */
/* ================================================================== */

static int parse_callgraph_db(AnalysisDB *adb, Elf64_Ctx *ctx, PanelData *pd)
{
    (void)ctx;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[256];
    int total_edges = 0;

    /* 统计总边数 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM xrefs WHERE ref_type='call'",
        -1, &st, NULL);
    if (st) {
        if (sqlite3_step(st) == SQLITE_ROW)
            total_edges = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    snprintf(buf, sizeof(buf),
             "=== Call Graph (%d call edges) [DB] ===", total_edges);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (total_edges == 0) {
        fields_add(pd, "(no call instructions in DB — import ELF first)", 1, 0, DETAIL_NONE, -1);
        return 0;
    }

    /* 查询: caller → callees, 带符号名 */
    sqlite3_prepare_v2(c,
        "SELECT x.from_addr, x.to_addr, "
        "  COALESCE(sf.name, 'sub_' || hex(x.from_addr)), "
        "  COALESCE(st.name, 'sub_' || hex(x.to_addr)) "
        "FROM xrefs x "
        "LEFT JOIN symbols sf ON sf.address = x.from_addr "
        "LEFT JOIN symbols st ON st.address = x.to_addr "
        "WHERE x.ref_type='call' "
        "ORDER BY x.from_addr, x.to_addr LIMIT 300",
        -1, &st, NULL);
    if (!st) return -1;

    fields_add(pd, "── Callers → Callees ──", 0, 0, DETAIL_NONE, -1);

    uint64_t last_from = 0;
    int shown = 0, caller_num = 0;
    while (sqlite3_step(st) == SQLITE_ROW && shown < 300) {
        uint64_t from_addr = (uint64_t)sqlite3_column_int64(st, 0);
        uint64_t to_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        const char *from_name = (const char *)sqlite3_column_text(st, 2);
        const char *to_name   = (const char *)sqlite3_column_text(st, 3);

        if (from_addr != last_from) {
            snprintf(buf, sizeof(buf),
                     "[%d] 0x%lx (%s) calls:",
                     ++caller_num,
                     (unsigned long)from_addr,
                     from_name ? from_name : "?");
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)from_addr);
            last_from = from_addr;
        }

        snprintf(buf, sizeof(buf),
                 "  → 0x%lx (%s)",
                 (unsigned long)to_addr,
                 to_name ? to_name : "?");
        fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        shown++;
    }
    sqlite3_finalize(st);

    if (total_edges > 300) {
        snprintf(buf, sizeof(buf), "... (%d more edges — use search to filter)",
                 total_edges - 300);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始实现 (DB 不可用时降级)                               */
/* ================================================================== */

static int parse_callgraph_mmap(Elf64_Ctx *ctx, PanelData *pd)
{
    int shnum = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    disasm_ctx *d = disasm_open();
    if (!d) {
        fields_add(pd, "(disasm engine unavailable)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    /* 预先构建符号地址→名称排序查找表 (O(N log N) 一次性) */
    sym_lookup_t *sym_tab = NULL;
    int sym_count = sym_lookup_build(ctx, &sym_tab, NULL);

    /* 初始化图 */
    cg_graph_t graph = {NULL, 0, 0};
    cg_collect_t coll = {&graph, ctx, "", sym_tab, sym_count};

    /* Pass 1: 扫描所有代码段 */
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        if (sh->sh_type != SHT_PROGBITS) continue;
        if (!(sh->sh_flags & SHF_EXECINSTR)) continue;

        /* 确定当前节的 "当前函数" 名 */
        char sec_func[128];
        sym_lookup_resolve(sym_tab, sym_count, sh->sh_addr,
                           sec_func, sizeof(sec_func));
        snprintf(coll.current_func, sizeof(coll.current_func), "%s", sec_func);

        disasm_run(d, ctx->map + sh->sh_offset, sh->sh_size,
                   sh->sh_addr, cg_on_insn, &coll);
    }

    disasm_close(d);
    free(sym_tab);  /* 符号表已不再需要 */

    /* 输出 */
    char buf[256];
    snprintf(buf, sizeof(buf),
             "=== Call Graph (%d call edges) ===", graph.count);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    if (graph.count == 0) {
        fields_add(pd, "(no call instructions found)", 1, 0, DETAIL_NONE, -1);
        free(graph.edges);
        return pd->count;
    }

    /* 按 caller 分组 */
    fields_add(pd, "─ ─ ─ Callers → Callees ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    /* 对边排序: 按 from_addr (qsort O(N log N) 替代冒泡 O(N²)) */
    qsort(graph.edges, (size_t)graph.count, sizeof(cg_edge_t), cg_edge_cmp);

    uint64_t last_from = 0;
    int shown = 0, caller_num = 0;
    for (int i = 0; i < graph.count && shown < 200; i++) {
        cg_edge_t *e = &graph.edges[i];

        if (e->from_addr != last_from) {
            snprintf(buf, sizeof(buf),
                     "[%d] 0x%lx (%s) calls:",
                     ++caller_num,
                     (unsigned long)e->from_addr, e->from_name);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)e->from_addr);
            last_from = e->from_addr;
        }

        snprintf(buf, sizeof(buf),
                 "  → 0x%lx (%s)",
                 (unsigned long)e->to_addr, e->to_name);
        fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        shown++;
    }


    free(graph.edges);
    return pd->count;
}

/* ================================================================== */
/* 公共接口: parse_callgraph (DB 优先, mmap 降级)                     */
/* ================================================================== */

int parse_callgraph(Elf64_Ctx *ctx, PanelData *pd)
{
    /* 路径 1: DB 可用 → 直接用 xrefs 表查询 */
    if (g_active_db) {
        return parse_callgraph_db(g_active_db, ctx, pd);
    }
    /* 路径 2: DB 不可用 → 降级到 mmap 反汇编 */
    return parse_callgraph_mmap(ctx, pd);
}
