/*
 * heap_jemalloc.c — jemalloc 分配器解析器
 *
 * 实现 allocator_parser 接口: detect + parse_chunks + consistency
 *
 * jemalloc 与 ptmalloc 的关键差异:
 *   - 无内联 chunk header (元数据在独立区域)
 *   - 大小类 (size classes): 预定义的分配大小
 *   - 线程缓存 (tcache) 和 arena 分离管理
 *   - extent 结构: 管理大块虚拟内存区域
 *
 * 解析策略:
 *   1. detect: 检查 maps 中是否有 libjemalloc.so
 *   2. parse_chunks: 通过 /proc/pid/mem 读取 extent 元数据
 *   3. consistency: 检查 size class 一致性
 */

#include "core/heap_analyzer.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* jemalloc 大小类 (4.0+ 通用) */
static const uint32_t JEMALLOC_SIZE_CLASSES[] = {
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160,
    192, 224, 256, 320, 384, 448, 512, 640, 768, 896,
    1024, 1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
    5120, 6144, 7168, 8192, 10240, 12288, 14336, 16384
};
#define JEMALLOC_NSC (int)(sizeof(JEMALLOC_SIZE_CLASSES) / sizeof(JEMALLOC_SIZE_CLASSES[0]))

/* jemalloc extent 结构 (简化, 只取关键字段) */
typedef struct {
    uint64_t  addr;         /* extent 起始 (用户数据) */
    uint64_t  size;         /* extent 大小 */
    uint64_t  arena_addr;   /* 所属 arena 地址 */
    int       allocated;
    int       sz_class;     /* 大小类索引 (-1 = 大分配/未分类) */
} jemalloc_extent_t;

/* ── detect: 检查是否链接了 jemalloc ── */
static int jemalloc_detect(struct DebugState *ds)
{
    if (!ds) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libjemalloc")) { found = 1; break; }
    }
    fclose(fp);
    return found;
}

/* ── 大小类查找 ── */
static int jemalloc_find_sz_class(uint64_t size)
{
    for (int i = 0; i < JEMALLOC_NSC; i++) {
        if ((uint64_t)JEMALLOC_SIZE_CLASSES[i] >= size)
            return i;
    }
    return -1;  /* large allocation */
}

/* ── parse_chunks ── */
static int jemalloc_parse_chunks(struct DebugState *ds,
                                  memory_region_t *regions, int nregions,
                                  AnalysisDB *adb, int session_id)
{
    if (!ds || !regions || !adb) return -1;

    for (int ri = 0; ri < nregions; ri++) {
        uint64_t addr = regions[ri].start;
        uint64_t end  = regions[ri].end;

        if (addr == 0 || end <= addr) continue;

        /* jemalloc 分配从 arena chunk 开始.
         * 简化策略: 按 size class 边界扫描.
         * 对于每个可能的分配, 读取少量元数据验证. */
        uint64_t cur = addr;
        int chunk_idx = 0;

        while (cur < end && chunk_idx < 10000) {
            /* 尝试读取一个可能的 extent 头.
             * jemalloc extent 在分配之前几字节有元数据,
             * 但精确结构取决于配置. 这里做启发式扫描.
             *
             * 注意: 此方法有较高的误报率 — 任何值为合法 size-class 的
             * 4 字节整数都可能被误判为 extent 头。精确解析需要:
             *   1. 定位 jemalloc 的全局 extent_t 数组 (通过符号表)
             *   2. 或解析 jemalloc 的内部 radix tree 结构
             * 当前实现作为快速概览使用, 不适合精确堆分析。 */

            /* 读取可能的元数据 (4 字节的 size 信息) */
            uint32_t metadata[2];
            if (debug_readmem(ds, cur, metadata, 8) != 8) break;

            /* 验证: 元数据中的 size 是否为合法的大小类 */
            uint32_t field0 = metadata[0];
            uint32_t field1 = metadata[1];

            int sc = jemalloc_find_sz_class((uint64_t)field0);

            /* 如果 field0 匹配大小类, 假定这是分配起点 */
            if (sc >= 0 && field0 > 0 && field0 <= 16384 &&
                /* 验证 field1 看起来合理 (状态字段) */
                (field1 == 0 || field1 == 1 || field1 == 0x80 || field1 == 0x81)) {

                int allocated = (field1 & 0x01) ? 1 : 0;
                uint64_t user_data = cur + 8;  /* 跳过可能的 extent header */
                uint64_t user_size = (uint64_t)field0;

                heap_chunk_insert(adb, session_id, user_data, user_size,
                                  allocated, 0, field1);

                /* 物理邻接链 */
                if (chunk_idx > 0)
                    heap_link_insert(adb, session_id,
                                     user_data - 16, user_data, "next_chunk");

                cur += user_size + 8; /* 对齐到下一块 */
                chunk_idx++;
            } else {
                /* 尝试下一个可能的对齐边界 */
                cur += 16;
            }
        }
    }

    return 0;
}

/* ── consistency ── */
static int jemalloc_consistency(struct DebugState *ds, AnalysisDB *adb,
                                 int session_id)
{
    if (!adb) return -1;

    /* 委托给通用一致性检查 */
    int base_anomalies = heap_consistency_run(adb, session_id);

    /* jemalloc 特有检查: 大小类合法性 */
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return base_anomalies;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT addr, size FROM heap_chunks WHERE session_id=?"
        " AND allocator='jemalloc'",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t chk_addr = (uint64_t)sqlite3_column_int64(st, 0);
            uint64_t chk_size = (uint64_t)sqlite3_column_int64(st, 1);

            int sc = jemalloc_find_sz_class(chk_size);
            if (sc < 0 && chk_size > 0 && chk_size < 16384) {
                /* 小于 large threshold 但不匹配任何 size class */
                char desc[128];
                snprintf(desc, sizeof(desc),
                         "Size %lu does not match any jemalloc size class",
                         (unsigned long)chk_size);
                heap_anomaly_insert(adb, session_id, chk_addr,
                                    "bad_size_class", 0.7, desc, "MEDIUM");
            }
        }
        sqlite3_finalize(st);
    }

    return base_anomalies;
}

/* ── 注册 ── */
allocator_parser_t jemalloc_parser = {
    .name         = "jemalloc",
    .detect       = jemalloc_detect,
    .parse_chunks = jemalloc_parse_chunks,
    .consistency  = jemalloc_consistency,
};
