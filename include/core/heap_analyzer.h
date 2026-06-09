/*
 * heap_analyzer.h — Allocator-Agnostic 堆分析器接口
 *
 * 三层架构:
 *   Memory Layer   → memory_region (纯内存元数据)
 *   Allocator Layer → allocator_parser (可插拔分配器)
 *   DB Layer       → heap_chunks + heap_links + heap_anomalies (图结构)
 *
 * 不绑定 glibc — ptmalloc/jemalloc/tcmalloc/mimalloc 通过统一接口接入。
 */

#ifndef HEAP_ANALYZER_H
#define HEAP_ANALYZER_H

#include <stdint.h>
#include <stddef.h>

/* ── 前向声明 ────────────────────────────────────────────────────── */
struct DebugState;
typedef struct AnalysisDB AnalysisDB;

/* ================================================================== */
/* Memory Layer                                                        */
/* ================================================================== */

typedef struct {
    uint64_t start;
    uint64_t end;
    int      readable;
    int      writable;
    int      executable;
} memory_region_t;

/* 从 /proc/pid/maps 获取堆区域 */
int heap_get_regions(struct DebugState *ds, memory_region_t *regions, int max);

/* ================================================================== */
/* Allocator Layer (allocator-agnostic)                                */
/* ================================================================== */

typedef struct {
    uint64_t addr;            /* 用户数据起始地址 */
    uint64_t size;            /* 用户请求大小 (不含头部) */
    int      allocated;       /* 0=free, 1=in_use */
    uint64_t next;            /* 链表中下一个 (fd / tcache_next) */
    uint64_t prev;            /* 链表中上一个 (bk) */
} heap_chunk_t;

/* 分配器解析器 (可插拔) */
typedef struct allocator_parser {
    const char *name;
    int (*detect)(struct DebugState *ds);
    int (*parse_chunks)(struct DebugState *ds, memory_region_t *regions,
                        int nregions, AnalysisDB *adb, int session_id);
    int (*consistency)(struct DebugState *ds, AnalysisDB *adb, int session_id);
} allocator_parser_t;

/* 注册的解析器列表 (NULL 终止) */
extern allocator_parser_t *allocator_parsers[];

/* 自动检测并使用第一个匹配的解析器 */
allocator_parser_t *heap_detect_allocator(struct DebugState *ds);

/* ================================================================== */
/* DB Layer                                                            */
/* ================================================================== */

/* 创建新会话, 返回 session_id */
int heap_session_begin(AnalysisDB *adb, int pid, const char *allocator);

/* 写入单个 chunk 事实 */
int heap_chunk_insert(AnalysisDB *adb, int session_id,
                      uint64_t addr, uint64_t size, int allocated,
                      uint64_t prev_size, int flags);

/* 写入链接边 */
int heap_link_insert(AnalysisDB *adb, int session_id,
                     uint64_t src, uint64_t dst, const char *link_type);

/* 写入异常 */
int heap_anomaly_insert(AnalysisDB *adb, int session_id,
                        uint64_t addr, const char *type, double confidence,
                        const char *desc, const char *severity);

/* 一致性检查 (遍历 chunk → 验证 → 写异常) */
int heap_consistency_run(AnalysisDB *adb, int session_id);

/* ================================================================== */
/* TUI 查询                                                            */
/* ================================================================== */

#include "elf_parser.h"   /* PanelData */

int heap_query_overview(AnalysisDB *adb, int session_id, PanelData *pd);
int heap_query_chunks(AnalysisDB *adb, int session_id, PanelData *pd);
int heap_query_links(AnalysisDB *adb, int session_id, PanelData *pd);
int heap_query_anomalies(AnalysisDB *adb, int session_id, PanelData *pd);
int heap_query_visual(AnalysisDB *adb, int session_id, PanelData *pd);
int heap_query_chunk_detail(AnalysisDB *adb, uint64_t addr, PanelData *pd);
int heap_query_link_detail(AnalysisDB *adb, uint64_t src, uint64_t dst, PanelData *pd);

/* 地址标注: 给定地址 → 返回可读标签 (如 "[stack]", "[libc+0x1234]") */
const char *heap_annotate_addr(AnalysisDB *adb, int session_id,
                               uint64_t addr, char *buf, size_t sz);

#endif /* HEAP_ANALYZER_H */
