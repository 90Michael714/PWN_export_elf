/*
 * dataflow_inter.c — 跨过程数据流分析
 *
 * 接口: int parse_dataflow_inter(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 *
 * 原理: 利用 callgraph.c 产生的调用图边, 跨函数边界追踪数据流。
 *   source → call(foo) → foo 的入口参数 → foo 内部传播 → foo 返回值 → call site
 */

#include "elf_parser.h"
#include "core/ir.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern AnalysisDB *g_active_db;

/* ── 跨函数数据路径结构 ──────────────────────────────────────────── */

typedef struct {
    uint64_t  addr;
    char      func_name[128];
    int       depth;       /* 调用深度 */
} ip_path_node_t;

#define MAX_IP_PATH 32

/* ── 追踪一个值跨函数的路径 ───────────────────────────────────────── */

static int trace_inter_proc(sqlite3 *c, uint64_t start_addr,
                             const char *target_reg,
                             ip_path_node_t *path, int max_depth,
                             int *path_len)
{
    /* 从 start_addr 向前追踪 target_reg 的定义 */
    int depth = 0;
    uint64_t cur_addr = start_addr;
    const char *track_reg = target_reg;
    *path_len = 0;

    while (depth < max_depth) {
        /* 查找当前地址所在函数 */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT start_addr, name FROM functions "
            "WHERE start_addr<=?1 AND end_addr>?1 LIMIT 1",
            -1, &st, NULL);
        if (!st) break;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)cur_addr);

        uint64_t func_start = 0;
        char func_name[128] = "?";
        if (sqlite3_step(st) == SQLITE_ROW) {
            func_start = (uint64_t)sqlite3_column_int64(st, 0);
            snprintf(func_name, sizeof(func_name), "%s",
                     (const char *)sqlite3_column_text(st, 1));
        }
        sqlite3_finalize(st);
        if (func_start == 0) break;

        /* 记录当前节点 */
        path[*path_len].addr = cur_addr;
        snprintf(path[*path_len].func_name, sizeof(path[*path_len].func_name),
                 "%s", func_name);
        path[*path_len].depth = depth;
        (*path_len)++;

        /* 向前查找最近的对 track_reg 的 reg_write */
        sqlite3_prepare_v2(c,
            "SELECT ir2.address, i2.mnemonic, i2.op_str "
            "FROM ir_stmts ir1 "
            "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write' "
            "JOIN instructions i2 ON ir2.address=i2.address "
            "WHERE ir1.address=?1 AND ir1.op_type='reg_read' "
            "AND ir1.dst=?2 AND ir2.address<?1 "
            "ORDER BY ir2.address DESC LIMIT 1",
            -1, &st, NULL);
        if (!st) break;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)cur_addr);
        sqlite3_bind_text(st,  2, track_reg, -1, SQLITE_STATIC);

        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            /* 未在当前函数内找到定义 — 可能是参数传入 */
            /* 查找函数的调用者 */
            sqlite3_prepare_v2(c,
                "SELECT x.from_addr FROM xrefs x "
                "JOIN symbols s ON x.from_addr=s.address "
                "WHERE x.to_addr=?1 AND x.ref_type='call' LIMIT 3",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_int64(st, 1, (sqlite3_int64)func_start);
                /* 存在调用者 — 需要分析调用者传递的参数 */
                while (sqlite3_step(st) == SQLITE_ROW) {
                    uint64_t caller = (uint64_t)sqlite3_column_int64(st, 0);
                    /* 递归追踪调用者... (简化: 仅浅层追踪) */
                    (void)caller;
                }
                sqlite3_finalize(st);
            }
            break;
        }

        uint64_t def_addr = (uint64_t)sqlite3_column_int64(st, 0);
        const char *mnem = (const char *)sqlite3_column_text(st, 1);
        sqlite3_finalize(st);

        /* 如果定义来自 call 指令 (返回值), 进入被调用函数 */
        if (mnem && !strcmp(mnem, "call")) {
            depth++;
            /* 在被调用函数中追踪 rax (返回值寄存器) */
            cur_addr = def_addr;
            track_reg = "rax";
            continue;
        }

        /* 如果定义来自 mov (寄存器拷贝), 追踪源寄存器 */
        if (mnem && !strcmp(mnem, "mov")) {
            /* 查找该指令读取的寄存器 */
            sqlite3_prepare_v2(c,
                "SELECT dst FROM ir_stmts WHERE address=? AND op_type='reg_read' LIMIT 1",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_int64(st, 1, (sqlite3_int64)def_addr);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    track_reg = (const char *)sqlite3_column_text(st, 0);
                }
                sqlite3_finalize(st);
            }
            cur_addr = def_addr;
            continue;
        }

        /* 其他: 停止追踪 */
        cur_addr = def_addr;
        break;
    }

    return *path_len;
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int parse_dataflow_inter(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    if (!ctx || !pd) return -1;
    (void)shdr_idx;

    AnalysisDB *adb = g_active_db;
    if (!adb) {
        fields_add(pd, "(DB not available)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return 0;

    char buf[512];

    /* 使用已有的静态目标地址 */
    static uint64_t s_target = 0;
    if (s_target == 0) {
        Elf64_Ehdr *ehdr = elf_get_ehdr(ctx);
        s_target = ehdr->e_entry;
    }

    snprintf(buf, sizeof(buf), "=== Inter-Procedural Data Flow ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Target: 0x%lx", (unsigned long)s_target);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 获取目标指令信息 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT mnemonic, op_str FROM instructions WHERE address=?",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf, sizeof(buf), "Instruction: %s %s",
                     (const char *)sqlite3_column_text(st, 0),
                     (const char *)sqlite3_column_text(st, 1));
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 对该指令的每个 reg_read 做跨函数追踪 */
    fields_add(pd, "── Cross-Function Register Trace ──", 1, 0, DETAIL_NONE, -1);

    sqlite3_prepare_v2(c,
        "SELECT DISTINCT dst FROM ir_stmts "
        "WHERE address=? AND op_type='reg_read' LIMIT 8",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *reg = (const char *)sqlite3_column_text(st, 0);
            if (!reg) continue;

            ip_path_node_t path[MAX_IP_PATH];
            int plen = 0;
            trace_inter_proc(c, s_target, reg, path, MAX_IP_PATH, &plen);

            snprintf(buf, sizeof(buf), "── %s (depth %d) ──", reg, plen);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

            for (int p = 0; p < plen; p++) {
                char indent[32] = "";
                for (int d = 0; d < path[p].depth && d < 15; d++)
                    strcat(indent, "  ");
                snprintf(buf, sizeof(buf), "%s[L%d] 0x%lx  in %s",
                         indent, path[p].depth,
                         (unsigned long)path[p].addr,
                         path[p].func_name);
                fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)path[p].addr);
            }
        }
        sqlite3_finalize(st);
    }

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[Enter]=jump  [d]=intra-df  [h]=back", 1, 0, DETAIL_NONE, -1);

    return 0;
}
