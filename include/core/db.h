/*
 * db.h — SQLite3 分析数据库接口 (v2 — Address-Centric Schema)
 *
 * Address = 全局主键。11 张表覆盖静态分析+动态调试:
 *   sections, segments, symbols, instructions, strings,
 *   functions, basic_blocks, cfg_edges, xrefs,
 *   reg_snapshots, mem_snapshots
 *
 * 依赖: sqlite3, elf_parser.h
 */

#ifndef DB_H
#define DB_H

#include "elf_parser.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

/* ── 前向声明 ────────────────────────────────────────────────────── */
struct DebugState;

/* ── 不透明句柄 ──────────────────────────────────────────────────── */
typedef struct AnalysisDB AnalysisDB;

/* ── 查询结果结构 ────────────────────────────────────────────────── */

typedef struct {
    uint64_t address;       uint8_t  bytes[16];
    char     mnemonic[32];  char     op_str[160];
    int      size;          char     section[64];
} DbInsn;

typedef struct {
    uint64_t start_addr;    uint64_t end_addr;
    char     name[128];     int      bb_count;
} DbFunc;

typedef struct {
    uint64_t start_addr;    uint64_t end_addr;
    uint64_t function_addr; int      insn_count;
} DbBB;

typedef struct {
    uint64_t from_addr;     uint64_t to_addr;
    char     edge_type[16]; /* fallthrough/jump/conditional/call/ret */
} DbCfgEdge;

typedef struct {
    uint64_t from_addr;     uint64_t to_addr;
    char     ref_type[16];  /* JMP/CALL/DATA/STRING/REG_W/REG_R */
    char     detail[128];
} DbXref;

typedef struct {
    uint64_t address;       char     name[256];
    int      size;          char     type[16];
    char     bind[16];      char     table_name[16];
} DbSymbol;

typedef struct {
    uint64_t rip;           int      step_num;
    uint64_t regs[22];      /* RAX RBX RCX RDX RSI RDI RBP RSP
                                R8-R15 EFLAGS CS-FS-GS-SS */
} DbRegSnap;

/* ── 生命周期 ────────────────────────────────────────────────────── */
AnalysisDB* db_open(const char *path);   /* path=NULL → :memory: */
void        db_close(AnalysisDB *db);
void*       db_conn(AnalysisDB *db);     /* 获取 sqlite3* 句柄 */

/* ── 全量导入 (替代旧的 db_import_disasm) ───────────────────────── */
int  db_import_all(AnalysisDB *db, Elf64_Ctx *ctx);
void db_build_indexes(AnalysisDB *db);

/* ── 查询: 地址 → 一切 ──────────────────────────────────────────── */
int db_query_insn(AnalysisDB *db, uint64_t addr, DbInsn *out);
int db_query_func(AnalysisDB *db, uint64_t addr, DbFunc *out);
int db_query_bb(AnalysisDB *db, uint64_t addr, DbBB *out);
int db_query_cfg_from(AnalysisDB *db, uint64_t addr, DbCfgEdge *out, int max);
int db_query_cfg_to(AnalysisDB *db, uint64_t addr, DbCfgEdge *out, int max);
int db_query_xref_to(AnalysisDB *db, uint64_t addr, DbXref *out, int max);
int db_query_xref_from(AnalysisDB *db, uint64_t addr, DbXref *out, int max);
int db_query_symbol_by_addr(AnalysisDB *db, uint64_t addr, DbSymbol *out);
int db_query_symbol_by_name(AnalysisDB *db, const char *name, DbSymbol *out);

/* 一键全查: addr 对应的所有信息 → PanelData */
int db_query_addr_all(AnalysisDB *db, uint64_t addr,
                      const struct DebugState *ds, PanelData *pd,
                      int depth);

/* ── 查询: 函数级 ───────────────────────────────────────────────── */
int db_query_func_bbs(AnalysisDB *db, uint64_t func_addr, DbBB *out, int max);
int db_query_func_callers(AnalysisDB *db, uint64_t func_addr,
                          uint64_t *callers, int max);
int db_query_func_callees(AnalysisDB *db, uint64_t func_addr,
                          uint64_t *callees, int max);

/* ── 动态数据查询 ───────────────────────────────────────────────── */
int db_query_reg_at_insn(AnalysisDB *db, uint64_t addr, DbRegSnap *out, int max);

/* ── 动态数据写入 ───────────────────────────────────────────────── */
int db_insert_reg_snapshot(AnalysisDB *db, const struct DebugState *ds,
                           int step_num);

/* ── IR 语义数据流 ─────────────────────────────────────────────── */
int db_dataflow_query(AnalysisDB *db, uint64_t addr, PanelData *pd);

/* ── 漏洞分析 ───────────────────────────────────────────────────── */
int db_scan_vulns(AnalysisDB *db);
int db_vuln_count(AnalysisDB *db);
int db_vuln_query(AnalysisDB *db, PanelData *pd);
int db_vuln_detail(AnalysisDB *db, uint64_t addr, PanelData *pd);
int db_taint_for_addr(AnalysisDB *db, uint64_t addr, PanelData *pd);
int db_taint_sources(AnalysisDB *db, PanelData *pd);

/* ── 反向数据流追踪 ─────────────────────────────────────────────── */
int db_trace_args(AnalysisDB *db, uint64_t call_addr, PanelData *pd);

/* ── CFG 可视化 ────────────────────────────────────────────────── */
int db_render_cfg_graph(AnalysisDB *db, uint64_t addr, PanelData *pd);

/* ── 全局搜索 ───────────────────────────────────────────────────── */
int db_search(AnalysisDB *db, const char *query, PanelData *pd);

/* ── Strategy 1: Crash Auto-Triage ──────────────────────────────── */
int db_crash_triage(AnalysisDB *db, const struct DebugState *ds,
                    uint64_t fault_addr, int signal,
                    uint64_t *regs, PanelData *pd);

/* ── 工具 ────────────────────────────────────────────────────────── */
int db_insn_count(AnalysisDB *db);
int db_snapshot_count(AnalysisDB *db);
int db_func_count(AnalysisDB *db);
int db_export(AnalysisDB *db, const char *path);

#endif
