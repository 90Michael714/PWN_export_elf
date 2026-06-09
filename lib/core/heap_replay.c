/*
 * heap_replay.c — 堆事件回放引擎
 *
 * 功能: 读取 heap_events 表, 模拟任意时刻的堆布局状态。
 *   1. 时间轴: 可视化 alloc/free 序列
 *   2. 布局快照: 跳转到任意时间点, 展示此时的堆布局
 *   3. 统计: 分配模式, 碎片率, 生命周期分布
 */

#include "core/heap_analyzer.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================== */
/* 回放状态                                                            */
/* ================================================================== */

typedef struct {
    uint64_t addr;
    uint64_t size;
    int      allocated;   /* 1=allocated, 0=freed */
} replay_chunk_t;

#define MAX_REPLAY_CHUNKS 4096

/* ================================================================== */
/* 时间轴可视化                                                        */
/* ================================================================== */

int heap_replay_timeline(AnalysisDB *adb, int session_id, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[400];

    fields_add(pd, "=== Heap Alloc Timeline ===", 0, 0, DETAIL_NONE, -1);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT event_type, chunk_addr, size, timestamp "
        "FROM heap_events WHERE session_id=?"
        " ORDER BY timestamp LIMIT 500",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int n = 0, n_alloc = 0, n_free = 0;
        uint64_t total_alloc = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 500) {
            const char *et = (const char *)sqlite3_column_text(st, 0);
            uint64_t addr  = (uint64_t)sqlite3_column_int64(st, 1);
            uint64_t sz    = (uint64_t)sqlite3_column_int64(st, 2);
            uint64_t ts    = (uint64_t)sqlite3_column_int64(st, 3);

            char tag = '?';
            if (!strcmp(et, "malloc"))  { tag = 'M'; n_alloc++; total_alloc += sz; }
            else if (!strcmp(et, "calloc")) { tag = 'C'; n_alloc++; total_alloc += sz; }
            else if (!strcmp(et, "realloc")) { tag = 'R'; n_alloc++; total_alloc += sz; }
            else if (!strcmp(et, "free")) { tag = 'F'; n_free++; }

            snprintf(buf, sizeof(buf), "[%c] %8lu us  ptr=0x%lx  size=%-8lu",
                     tag, (unsigned long)(ts / 1000),
                     (unsigned long)addr, (unsigned long)sz);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)addr);
            n++;
        }
        sqlite3_finalize(st);

        snprintf(buf, sizeof(buf), "── Stats: %d events (%d alloc, %d free)  total_alloc=%lu KB",
                 n, n_alloc, n_free, (unsigned long)(total_alloc / 1024));
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    return 0;
}

/* ================================================================== */
/* 布局快照: 在时间点 T 的堆状态                                        */
/* ================================================================== */

int heap_replay_snapshot_at(AnalysisDB *adb, int session_id,
                            uint64_t timestamp_us, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[400];

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT event_type, chunk_addr, size FROM heap_events "
        "WHERE session_id=?1 AND timestamp<=?2 "
        "ORDER BY timestamp",
        -1, &st, NULL);
    sqlite3_bind_int(st,   1, session_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)(timestamp_us * 1000));

    /* 模拟 chunk 状态 */
    replay_chunk_t chunks[MAX_REPLAY_CHUNKS];
    int nchunks = 0;

    while (sqlite3_step(st) == SQLITE_ROW && nchunks < MAX_REPLAY_CHUNKS) {
        const char *et = (const char *)sqlite3_column_text(st, 0);
        uint64_t addr  = (uint64_t)sqlite3_column_int64(st, 1);
        uint64_t sz    = (uint64_t)sqlite3_column_int64(st, 2);

        if (!strcmp(et, "free")) {
            /* 标记对应地址为已释放 */
            for (int i = 0; i < nchunks; i++) {
                if (chunks[i].addr == addr) {
                    chunks[i].allocated = 0;
                    break;
                }
            }
        } else {
            /* 分配: 添加新 chunk */
            if (addr > 0) {
                chunks[nchunks].addr      = addr;
                chunks[nchunks].size      = sz;
                chunks[nchunks].allocated = 1;
                nchunks++;
            }
        }
    }
    sqlite3_finalize(st);

    /* 显示布局 */
    snprintf(buf, sizeof(buf), "=== Heap Layout @ T=%lu us ===  (%d chunks)",
             (unsigned long)timestamp_us, nchunks);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    int alloc_count = 0, free_count = 0;
    uint64_t total_sz = 0;
    for (int i = 0; i < nchunks; i++) {
        snprintf(buf, sizeof(buf), "0x%lx  [%s]  %lu bytes",
                 (unsigned long)chunks[i].addr,
                 chunks[i].allocated ? "IN_USE" : "FREE",
                 (unsigned long)chunks[i].size);
        fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)chunks[i].addr);
        if (chunks[i].allocated) { alloc_count++; total_sz += chunks[i].size; }
        else free_count++;
    }

    snprintf(buf, sizeof(buf), "── %d allocated (%lu KB), %d freed, %.1f%% in use",
             alloc_count, (unsigned long)(total_sz / 1024), free_count,
             nchunks > 0 ? (double)alloc_count * 100.0 / (double)nchunks : 0);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* 统计报告                                                            */
/* ================================================================== */

int heap_replay_stats(AnalysisDB *adb, int session_id, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[512];

    fields_add(pd, "=== Heap Statistics ===", 0, 0, DETAIL_NONE, -1);

    /* 分配大小分布 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT "
        "  CASE "
        "    WHEN size<=16   THEN '0-16' "
        "    WHEN size<=32   THEN '17-32' "
        "    WHEN size<=64   THEN '33-64' "
        "    WHEN size<=128  THEN '65-128' "
        "    WHEN size<=256  THEN '129-256' "
        "    WHEN size<=512  THEN '257-512' "
        "    WHEN size<=1024 THEN '513-1K' "
        "    WHEN size<=4096 THEN '1K-4K' "
        "    ELSE '>4K' END as bucket, "
        "  COUNT(*), AVG(size) "
        "FROM heap_events "
        "WHERE session_id=? AND event_type!='free' "
        "GROUP BY bucket ORDER BY MIN(size)",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        fields_add(pd, "── Size Distribution ──", 1, 0, DETAIL_NONE, -1);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *b = (const char *)sqlite3_column_text(st, 0);
            int cnt = sqlite3_column_int(st, 1);
            double avg = sqlite3_column_double(st, 2);
            snprintf(buf, sizeof(buf), "%-12s: %4d allocations (avg %3.0f bytes)",
                     b ? b : "?", cnt, avg);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 生命周期 (分配到释放的时间) */
    fields_add(pd, "── Lifetime ──", 1, 0, DETAIL_NONE, -1);
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM heap_events "
        "WHERE session_id=? AND event_type='free'",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            int nfree = sqlite3_column_int(st, 0);
            snprintf(buf, sizeof(buf), "Total free() calls: %d", nfree);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 碎片率: 空闲 chunk / 总 chunk */
    sqlite3_prepare_v2(c,
        "SELECT "
        "  (SELECT COUNT(*) FROM heap_events WHERE session_id=?1 AND event_type='free')*1.0 / "
        "  MAX(1, (SELECT COUNT(*) FROM heap_events WHERE session_id=?1 AND event_type!='free'))",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            double frag = sqlite3_column_double(st, 0);
            snprintf(buf, sizeof(buf), "Fragmentation ratio: %.2f (free/alloc events)", frag);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    return 0;
}
