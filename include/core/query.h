/*
 * query.h — 分析数据总线接口
 *
 * 所有模块通过此接口获取反汇编/符号/节信息, 不再各自遍历节表。
 * 线程安全: 所有查询是只读操作, 多线程可并发调用。
 * 生命周期: query_open() → 建立索引 → 查询 → query_close()
 */

#ifndef QUERY_H
#define QUERY_H

#include "elf_parser.h"
#include <stdint.h>
#include <stddef.h>

/* ── 不透明句柄 ─────────────────────────────────────────────────── */
typedef struct QueryDB QueryDB;

/* ── 生命周期 ────────────────────────────────────────────────────── */
QueryDB* query_open(Elf64_Ctx *ctx);
void     query_close(QueryDB *db);

/* ── 反汇编查询 ──────────────────────────────────────────────────── */
int  query_disasm(QueryDB *db, uint64_t addr, char *mnemonic, size_t msz,
                  char *ops, size_t osz);

/* ── 符号查询 ────────────────────────────────────────────────────── */
int  query_symbol(QueryDB *db, uint64_t addr, char *name, size_t nsz,
                  int64_t *offset);
int  query_sym_by_name(QueryDB *db, const char *name, uint64_t *addr);

/* ── 节查询 ──────────────────────────────────────────────────────── */
int  query_section(QueryDB *db, uint64_t addr, const char **sec_name,
                   uint64_t *sh_flags);

/* ── GOT/PLT 查询 ────────────────────────────────────────────────── */
int  query_got(QueryDB *db, uint64_t got_addr, const char **sym_name);

/* ── 交叉引用 (暂存接口, Phase 7 实现) ──────────────────────────── */
int  query_xrefs(QueryDB *db, uint64_t addr, uint64_t *refs, int max);

/* ── 批量扫描 ────────────────────────────────────────────────────── */
int  query_sym_count(QueryDB *db);
int  query_sym_by_index(QueryDB *db, int idx, uint64_t *addr,
                        char *name, size_t nsz, unsigned char *info);

#endif
