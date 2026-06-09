/*
 * dataflow.c — 基于 IR 的数据流分析视图 (PanelData 生产者)
 *
 * 接口: int parse_dataflow(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 *
 * 功能:
 *   - 函数内 use-def 链可视化
 *   - 寄存器数据流追踪
 *   - 危险调用的参数来源分析
 *   - 缓冲区安全评估
 *
 * 依赖: core/ir.h, core/db.h (消费 ir_stmts 表数据)
 */

#include "elf_parser.h"
#include "core/ir.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── 通用寄存器名列表 ────────────────────────────────────────────── */

static const char *X64_REGS[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags", "cs", "ds", "es", "fs", "gs", "ss"
};
#define N_X64_REGS (int)(sizeof(X64_REGS) / sizeof(X64_REGS[0]))

/* ── 获取指令的函数上下文 ────────────────────────────────────────── */

static int get_func_context(sqlite3 *c, uint64_t addr,
                            uint64_t *func_start, char *func_name, size_t name_sz)
{
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT start_addr, name FROM functions "
        "WHERE start_addr<=?1 AND end_addr>?1 LIMIT 1",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);

    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *func_start = (uint64_t)sqlite3_column_int64(st, 0);
        const char *n = (const char *)sqlite3_column_text(st, 1);
        snprintf(func_name, name_sz, "%s", n ? n : "sub_unknown");
        found = 1;
    }
    sqlite3_finalize(st);
    return found ? 0 : -1;
}

/* ================================================================== */
/* 公共接口: parse_dataflow                                            */
/* ================================================================== */

/* ── 持久化分析状态 (跨调用保留, 支持 Enter 导航) ───────────────── */

static uint64_t s_target_addr = 0;
static uint64_t s_func_start  = 0;
static char     s_func_name[128] = "";

/* 供外部设置分析目标地址 */
void dataflow_set_target(uint64_t addr)
{
    s_target_addr = addr;
    s_func_start  = 0;      /* 强制下次重新查询函数上下文 */
    s_func_name[0] = '\0';
}

int parse_dataflow(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    if (!ctx || !pd) return -1;

    /* 需要 AnalysisDB 句柄 */
    AnalysisDB *adb = NULL;
    (void)shdr_idx; /* dataflow 不依赖于特定 section */

    sqlite3 *c = NULL;
    {
        /* 从 PanelData 的上下文中获取 DB — 通过全局变量桥接 */
        extern AnalysisDB *g_active_db;  /* tui.c 设置的全局 DB 句柄 */
        adb = g_active_db;
        if (!adb) {
            fields_add(pd, "(DB not available — import ELF first)", 0, 0, DETAIL_NONE, -1);
            return 0;
        }
        c = (sqlite3 *)db_conn(adb);
        if (!c) {
            fields_add(pd, "(DB connection failed)", 0, 0, DETAIL_NONE, -1);
            return 0;
        }
    }

    /* 如果未指定目标, 使用默认: ELF entry point */
    if (s_target_addr == 0) {
        Elf64_Ehdr *ehdr = elf_get_ehdr(ctx);
        s_target_addr = ehdr->e_entry;
    }

    char buf[512];
    snprintf(buf, sizeof(buf), "=== Data Flow Analysis ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 函数上下文 */
    if (get_func_context(c, s_target_addr, &s_func_start, s_func_name, sizeof(s_func_name)) == 0) {
        snprintf(buf, sizeof(buf), "Function: %s  (0x%lx — 0x%lx)",
                 s_func_name, (unsigned long)s_func_start, (unsigned long)s_target_addr);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    snprintf(buf, sizeof(buf), "Target: 0x%lx", (unsigned long)s_target_addr);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* ── Section 1: 当前指令的 IR 语义 ── */
    fields_add(pd, "── Current Instruction IR ──", 1, 0, DETAIL_NONE, -1);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT mnemonic, op_str FROM instructions WHERE address=?",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf, sizeof(buf), "%s %s",
                     (const char *)sqlite3_column_text(st, 0),
                     (const char *)sqlite3_column_text(st, 1));
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 显示该指令的所有 IR 操作 */
    sqlite3_prepare_v2(c,
        "SELECT op_type, dst, src, mem_base, mem_disp, imm_value "
        "FROM ir_stmts WHERE address=? ORDER BY rowid",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        int irn = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ot = (const char *)sqlite3_column_text(st, 0);
            const char *ds = (const char *)sqlite3_column_text(st, 1);
            const char *sc = (const char *)sqlite3_column_text(st, 2);
            const char *mb = (const char *)sqlite3_column_text(st, 3);
            int  disp       = sqlite3_column_int(st, 4);
            int64_t imm     = sqlite3_column_int64(st, 5);

            if (!strcmp(ot, "reg_read")) {
                snprintf(buf, sizeof(buf), "[%d] READ  %s ← prev write", irn, ds ? ds : "?");
            } else if (!strcmp(ot, "reg_write")) {
                snprintf(buf, sizeof(buf), "[%d] WRITE %s (from %s)", irn, ds ? ds : "?", sc ? sc : "?");
            } else if (!strcmp(ot, "mem_access")) {
                snprintf(buf, sizeof(buf), "[%d] MEM   [%s+0x%x] via %s",
                         irn, mb ? mb : "?", disp, ds ? ds : "?");
            } else if (!strcmp(ot, "immediate")) {
                snprintf(buf, sizeof(buf), "[%d] IMM   %s = 0x%lx (%ld)",
                         irn, ds ? ds : "?", (unsigned long)imm, (long)imm);
            } else {
                snprintf(buf, sizeof(buf), "[%d] %s %s", irn, ot ? ot : "?", ds ? ds : "");
            }
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            irn++;
        }
        sqlite3_finalize(st);
    }

    /* ── Section 2: Use-Def 链 (谁定义了这些寄存器?) ── */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "── Use-Def Chain (Register Sources) ──", 1, 0, DETAIL_NONE, -1);

    sqlite3_prepare_v2(c,
        "SELECT ir1.dst, i2.address, i2.mnemonic, i2.op_str, "
        "  ?1 - i2.address as dist "
        "FROM ir_stmts ir1 "
        "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write' "
        "JOIN instructions i2 ON ir2.address=i2.address "
        "WHERE ir1.address=?1 AND ir1.op_type='reg_read' "
        "AND ir2.address<=?1 "
        "ORDER BY ir2.address DESC LIMIT 16",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 16) {
            const char *reg  = (const char *)sqlite3_column_text(st, 0);
            uint64_t def_a   = (uint64_t)sqlite3_column_int64(st, 1);
            const char *m    = (const char *)sqlite3_column_text(st, 2);
            const char *o    = (const char *)sqlite3_column_text(st, 3);
            int dist         = sqlite3_column_int(st, 4);

            snprintf(buf, sizeof(buf), "%-6s ← 0x%lx  %-8s %-28s  (-%d insns)",
                     reg ? reg : "?", (unsigned long)def_a,
                     m ? m : "?", o ? o : "?", dist);
            fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)def_a);
            n++;
        }
        sqlite3_finalize(st);
        if (n == 0)
            fields_add(pd, "(no reg_reads — may be pure memory/immediate instruction)", 2, 0, DETAIL_NONE, -1);
    }

    /* ── Section 3: Def-Use 链 (这里定义的值被谁使用?) ── */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "── Def-Use Chain (Register Consumers) ──", 1, 0, DETAIL_NONE, -1);

    sqlite3_prepare_v2(c,
        "SELECT ir1.dst, i2.address, i2.mnemonic, i2.op_str, "
        "  i2.address - ?1 as dist "
        "FROM ir_stmts ir1 "
        "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_read' "
        "JOIN instructions i2 ON ir2.address=i2.address "
        "WHERE ir1.address=?1 AND ir1.op_type='reg_write' "
        "AND ir2.address>=?1 "
        "ORDER BY ir2.address LIMIT 16",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 16) {
            const char *reg = (const char *)sqlite3_column_text(st, 0);
            uint64_t use_a  = (uint64_t)sqlite3_column_int64(st, 1);
            const char *m   = (const char *)sqlite3_column_text(st, 2);
            const char *o   = (const char *)sqlite3_column_text(st, 3);
            int dist        = sqlite3_column_int(st, 4);

            snprintf(buf, sizeof(buf), "%-6s → 0x%lx  %-8s %-28s  (+%d insns)",
                     reg ? reg : "?", (unsigned long)use_a,
                     m ? m : "?", o ? o : "?", dist);
            fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)use_a);
            n++;
        }
        sqlite3_finalize(st);
        if (n == 0)
            fields_add(pd, "(no downstream consumers — register may be dead)", 2, 0, DETAIL_NONE, -1);
    }

    /* ── Section 4: 活跃寄存器分析 ── */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "── Liveness @ Instruction ──", 1, 0, DETAIL_NONE, -1);

    /* 查询: 该点之后哪些寄存器被读取 (live out) */
    sqlite3_prepare_v2(c,
        "SELECT DISTINCT ir.dst FROM ir_stmts ir "
        "JOIN instructions i ON ir.address=i.address "
        "WHERE ir.op_type='reg_read' AND ir.address>?1 "
        "AND ir.address<=(SELECT end_addr FROM functions "
        "  WHERE start_addr<=?1 AND end_addr>?1 LIMIT 1) "
        "ORDER BY ir.dst",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)(s_func_start ? s_func_start : s_target_addr));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(s_func_start ? s_func_start : s_target_addr));
        char live_list[512] = "";
        int nl = 0, lp = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *r = (const char *)sqlite3_column_text(st, 0);
            if (r && lp < (int)sizeof(live_list) - 16) {
                lp += snprintf(live_list + lp, sizeof(live_list) - (size_t)lp,
                               "%s%s", nl > 0 ? " " : "", r);
                nl++;
            }
        }
        sqlite3_finalize(st);
        if (nl > 0) {
            snprintf(buf, sizeof(buf), "Live-out registers (%d): %s", nl, live_list);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        } else {
            fields_add(pd, "(all registers dead — likely function epilogue)", 2, 0, DETAIL_NONE, -1);
        }
    }

    /* ── Section 5: 缓冲区安全评估 (如果是危险调用) ── */
    sqlite3_prepare_v2(c,
        "SELECT 1 FROM ir_stmts WHERE address=?1 AND src LIKE '%call%' LIMIT 1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)s_target_addr);
        int is_call = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);

        if (is_call) {
            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            ir_check_buffer_safety(adb, s_target_addr, pd);
        }
    }

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[Enter]=re-analyze [f]=buffer-check [v]=value-range [h]=back",
               1, 0, DETAIL_NONE, -1);

    return 0;
}

/* 全局 DB 句柄 (由 tui.c 设置) */
AnalysisDB *g_active_db = NULL;
