/*
 * rt_resolver.h — 运行时感知分析引擎
 *
 * 利用 ptrace 附加的进程运行时状态, 解析:
 *   1. 所有节的运行时地址 (ASLR 偏移计算)
 *   2. GOT/PLT 条目的运行时解析值 (库名 + 符号名)
 *   3. 间接调用/跳转的运行时目标 (CFG 补全)
 *   4. 数据引用的运行时内容 (字符串/函数指针)
 *
 * 结果写入 AnalysisDB 的 rt_* 表中, 供反编译引擎查询。
 */

#ifndef RT_RESOLVER_H
#define RT_RESOLVER_H

#include "core/db.h"
#include "core/debug_worker.h"
#include "elf_parser.h"
#include <stdint.h>

/* ── vmmap 入口 (声明在 vmmap_live.c) ─────────────────────────────── */
typedef struct { uint64_t start,end;char perms[5];uint64_t offset;
    unsigned int dev_major,dev_minor;unsigned long inode;char path[256];} vmmap_entry_t;
extern int vmmap_read(const struct DebugState *ds, vmmap_entry_t *e, int *c);

/* ── 运行时解析符号 ───────────────────────────────────────────────── */
typedef struct { char name[128]; uint64_t off; uint64_t sz; } rt_sym_t;

/* 从磁盘 ELF 读取动态符号表 (类似 btn_symresolve.c 中的 elf_read_syms) */
int rt_read_elf_syms(const char *path, rt_sym_t *out, int max);

/* ── Phase 1: 节地址映射 ──────────────────────────────────────────── */
int rt_resolve_addresses(struct DebugState *ds, Elf64_Ctx *elf,
                         AnalysisDB *adb, PanelData *pd);

/* ── Phase 2: GOT/PLT 运行时解析 ──────────────────────────────────── */
int rt_resolve_got(struct DebugState *ds, Elf64_Ctx *elf,
                   AnalysisDB *adb, PanelData *pd);

/* ── Phase 3: 间接调用目标解析 ───────────────────────────────────── */
int rt_resolve_indirect_calls(struct DebugState *ds, AnalysisDB *adb,
                              PanelData *pd);

/* ── Phase 4: 数据引用运行时内容 ──────────────────────────────────── */
int rt_resolve_data_refs(struct DebugState *ds, Elf64_Ctx *elf,
                         AnalysisDB *adb, PanelData *pd);

/* ── 一键全解析 ───────────────────────────────────────────────────── */
int rt_resolve_all(struct DebugState *ds, Elf64_Ctx *elf,
                   AnalysisDB *adb, PanelData *pd);

/* ── 运行时增强反编译 ─────────────────────────────────────────────── */
int rt_decompile_function(AnalysisDB *adb, uint64_t func_addr,
                          PanelData *pd);

#endif /* RT_RESOLVER_H */
