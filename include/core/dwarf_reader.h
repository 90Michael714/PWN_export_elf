/*
 * dwarf_reader.h — DWARF 调试信息解析器
 *
 * 从 .debug_line, .debug_str, .debug_info 等节提取源码级信息:
 *   - 地址 → 源文件:行号 映射 (.debug_line)
 *   - 函数名 (DWARF 声明的权威名称)
 *   - 变量名和类型
 *   - 源文件路径列表
 *
 * 接口:
 *   dwarf_read_all(db, ctx) — 主入口, 解析所有 DWARF 节并写入 DB
 *   dwarf_query_line(db, addr) — 查询地址对应的源文件和行号
 *   dwarf_query_func(db, addr) — 查询函数的 DWARF 声明信息
 */

#ifndef DWARF_READER_H
#define DWARF_READER_H

#include "core/db.h"
#include "elf_parser.h"

/* 解析所有 DWARF 节并将结果写入 DB */
int  dwarf_read_all(AnalysisDB *db, Elf64_Ctx *ctx);

/* 查询地址对应的源位置 (写入 PanelData) */
int  dwarf_query_line(AnalysisDB *db, uint64_t addr, PanelData *pd);

/* 查询函数的 DWARF 信息 */
int  dwarf_query_func(AnalysisDB *db, uint64_t func_addr, PanelData *pd);

/* 查询地址附近的变量 */
int  dwarf_query_vars(AnalysisDB *db, uint64_t addr, PanelData *pd);

/* 列出所有已知源文件 */
int  dwarf_list_sources(AnalysisDB *db, PanelData *pd);

#endif
