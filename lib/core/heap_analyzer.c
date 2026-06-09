/*
 * heap_analyzer.c — Memory Layer + DB Layer
 *
 * Memory Layer: /proc/pid/maps → memory_region_t[]
 * DB Layer:     heap_sessions + heap_chunks + heap_links + heap_anomalies
 * Consistency:  逐 chunk 物理验证
 */

#include "core/heap_analyzer.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/* Memory Layer                                                        */
/* ================================================================== */

int heap_get_regions(struct DebugState *ds, memory_region_t *regions, int max) {
    if (!ds || !regions) return -1;
    char path[64]; int n = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[512];
    while (fgets(line, sizeof(line), fp) && n < max) {
        uint64_t s = 0, e = 0; char p[8] = ""; char f[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &s, &e, p, f) < 3) continue;
        /* 找 [heap] 和 anonymous rw- 区域 */
        int is_heap = (strstr(f, "[heap]") != NULL);
        int is_anon_rw = (p[0]=='r' && p[1]=='w' && p[2]=='-' && !f[0]);
        if (is_heap || is_anon_rw) {
            regions[n].start = s; regions[n].end = e;
            regions[n].readable = 1;
            regions[n].writable = (p[1] == 'w');
            regions[n].executable = (p[2] == 'x');
            n++;
        }
    }
    fclose(fp);
    return n;
}

/* ================================================================== */
/* DB Layer                                                            */
/* ================================================================== */

int heap_session_begin(AnalysisDB *adb, int pid, const char *allocator) {
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c,
        "INSERT INTO heap_sessions(pid,timestamp,allocator,chunk_count,anomaly_count)"
        " VALUES(?,strftime('%s','now'),?,0,0)", -1, &st, NULL) != SQLITE_OK || !st)
        return -1;
    sqlite3_bind_int(st, 1, pid);
    sqlite3_bind_text(st, 2, allocator, -1, SQLITE_STATIC);
    sqlite3_step(st);
    int id = (int)sqlite3_last_insert_rowid(c);
    sqlite3_finalize(st);
    return id;
}

int heap_chunk_insert(AnalysisDB *adb, int session_id,
                      uint64_t addr, uint64_t size, int allocated,
                      uint64_t prev_size, int flags) {
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO heap_chunks"
        " (addr,session_id,size,state,prev_size,flags)"
        " VALUES(?,?,?,?,?,?)", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st,   2, session_id);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)size);
    sqlite3_bind_text(st,  4, allocated ? "allocated" : "free", -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)prev_size);
    sqlite3_bind_int(st,   6, flags);
    sqlite3_step(st);
    sqlite3_finalize(st);
    return 0;
}

int heap_link_insert(AnalysisDB *adb, int session_id,
                     uint64_t src, uint64_t dst, const char *link_type) {
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO heap_links(src_addr,dst_addr,link_type,session_id)"
        " VALUES(?,?,?,?)", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)src);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dst);
    sqlite3_bind_text(st,  3, link_type, -1, SQLITE_STATIC);
    sqlite3_bind_int(st,   4, session_id);
    sqlite3_step(st);
    sqlite3_finalize(st);
    return 0;
}

int heap_anomaly_insert(AnalysisDB *adb, int session_id,
                        uint64_t addr, const char *type, double confidence,
                        const char *desc, const char *severity) {
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO heap_anomalies(session_id,chunk_addr,anomaly_type,confidence,description,severity)"
        " VALUES(?,?,?,?,?,?)", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int(st,   1, session_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)addr);
    sqlite3_bind_text(st,  3, type, -1, SQLITE_STATIC);
    sqlite3_bind_double(st,4, confidence);
    sqlite3_bind_text(st,  5, desc, -1, SQLITE_STATIC);
    sqlite3_bind_text(st,  6, severity, -1, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
    return 0;
}

/* ================================================================== */
/* 一致性检查                                                          */
/* ================================================================== */

int heap_consistency_run(AnalysisDB *adb, int session_id) {
    if (!adb) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    int anomalies = 0;
    char buf[256];

    /* 检查 1: addr 对齐 */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT addr FROM heap_chunks WHERE session_id=? AND (addr & 15) != 0",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int(st, 1, session_id);
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
                snprintf(buf,sizeof(buf),"Address 0x%lx not 16-byte aligned",(unsigned long)a);
                heap_anomaly_insert(adb,session_id,a,"bad_alignment",1.0,buf,"HIGH");
                anomalies++;
            }
            sqlite3_finalize(st);
        }
    }

    /* 检查 2: double free (同地址多条 free link) */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT dst_addr,link_type,COUNT(*) FROM heap_links"
            " WHERE session_id=? AND link_type IN ('tcache','fastbin')"
            " GROUP BY dst_addr,link_type HAVING COUNT(*)>1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int(st, 1, session_id);
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
                const char *t = (const char*)sqlite3_column_text(st, 1);
                int cnt = sqlite3_column_int(st, 2);
                snprintf(buf,sizeof(buf),"Appears %d times in %s free list",cnt,t);
                heap_anomaly_insert(adb,session_id,a,"double_free",1.0,buf,"CRITICAL");
                anomalies++;
            }
            sqlite3_finalize(st);
        }
    }

    /* 检查 3: UAF (allocated 但出现在 free list) */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT DISTINCT c.addr FROM heap_chunks c"
            " JOIN heap_links l ON c.addr=l.dst_addr AND c.session_id=l.session_id"
            " WHERE c.session_id=? AND c.state='allocated'"
            " AND l.link_type IN ('tcache','fastbin')",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int(st, 1, session_id);
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
                heap_anomaly_insert(adb,session_id,a,"uaf",0.9,
                    "Allocated chunk appears in free list", "HIGH");
                anomalies++;
            }
            sqlite3_finalize(st);
        }
    }

    /* 检查 4: size 异常 */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT addr,size FROM heap_chunks WHERE session_id=?"
            " AND (size=0 OR (size & 15)!=0 OR size>0x10000000)",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int(st, 1, session_id);
            while (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
                int sz = sqlite3_column_int(st, 1);
                snprintf(buf,sizeof(buf),"Suspicious chunk size: %d (0x%x)",sz,sz);
                heap_anomaly_insert(adb,session_id,a,"size_corruption",0.8,buf,"HIGH");
                anomalies++;
            }
            sqlite3_finalize(st);
        }
    }

    /* 更新 session 的 anomaly_count */
    {
        char sql[128];
        snprintf(sql,sizeof(sql),
            "UPDATE heap_sessions SET anomaly_count=%d WHERE id=%d",
            anomalies, session_id);
        sqlite3_exec(c, sql, NULL, NULL, NULL);
    }
    return anomalies;
}

/* ================================================================== */
/* TUI 查询                                                            */
/* ================================================================== */

int heap_query_overview(AnalysisDB *adb, int session_id, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[400];
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;

    fields_add(pd,"=== Heap Graph ===",0,0,DETAIL_NONE,-1);

    /* Session info */
    sqlite3_prepare_v2(c,
        "SELECT pid,allocator,chunk_count,anomaly_count FROM heap_sessions WHERE id=?",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf,sizeof(buf),"PID %d  allocator: %s  chunks: %d  anomalies: %d",
                sqlite3_column_int(st,0),
                (const char*)sqlite3_column_text(st,1),
                sqlite3_column_int(st,2), sqlite3_column_int(st,3));
            fields_add(pd,buf,1,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);
    }

    /* State breakdown */
    sqlite3_prepare_v2(c,
        "SELECT state,COUNT(*) FROM heap_chunks WHERE session_id=?"
        " GROUP BY state ORDER BY state", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        fields_add(pd,"── State ──",1,0,DETAIL_NONE,-1);
        while (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf,sizeof(buf),"  %-12s: %d",
                (const char*)sqlite3_column_text(st,0), sqlite3_column_int(st,1));
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);
    }

    /* Link type breakdown */
    sqlite3_prepare_v2(c,
        "SELECT link_type,COUNT(*) FROM heap_links WHERE session_id=?"
        " GROUP BY link_type ORDER BY COUNT(*) DESC", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        fields_add(pd,"── Links ──",1,0,DETAIL_NONE,-1);
        while (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf,sizeof(buf),"  %-16s: %d edges",
                (const char*)sqlite3_column_text(st,0), sqlite3_column_int(st,1));
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);
    }

    /* Anomaly summary */
    sqlite3_prepare_v2(c,
        "SELECT severity,anomaly_type,chunk_addr FROM heap_anomalies WHERE session_id=?"
        " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END LIMIT 30",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int na = 0;
        while (sqlite3_step(st) == SQLITE_ROW && na < 30) {
            snprintf(buf,sizeof(buf),"  \xe2\x9a\xa0 %-7s %-18s @ 0x%lx",
                (const char*)sqlite3_column_text(st,0),
                (const char*)sqlite3_column_text(st,1),
                (unsigned long)sqlite3_column_int64(st,2));
            fields_add(pd,buf,2,1,DETAIL_NONE,(int)sqlite3_column_int64(st,2));
            na++;
        }
        sqlite3_finalize(st);
        if (na == 0) fields_add(pd,"  (no anomalies — heap looks clean)",2,0,DETAIL_NONE,-1);
    }

    return pd->count;
}

int heap_query_chunks(AnalysisDB *adb, int session_id, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[400]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    fields_add(pd,"── Heap Chunks (addr order) ──",1,0,DETAIL_NONE,-1);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT addr,size,state FROM heap_chunks WHERE session_id=?"
        " ORDER BY addr LIMIT 500", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
            int sz = sqlite3_column_int(st, 1);
            const char *s = (const char*)sqlite3_column_text(st, 2);
            snprintf(buf,sizeof(buf),"[%d] 0x%lx  [%-5s] 0x%x (%d)",
                ++n, (unsigned long)a, s, sz, sz);
            fields_add(pd,buf,0,1,DETAIL_NONE,(int)a);
        }
        sqlite3_finalize(st);
    }
    return pd->count;
}

int heap_query_links(AnalysisDB *adb, int session_id, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[400]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    fields_add(pd,"── Heap Links (graph edges) ──",1,0,DETAIL_NONE,-1);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT src_addr,dst_addr,link_type FROM heap_links WHERE session_id=?"
        " ORDER BY CASE link_type WHEN 'tcache' THEN 0 WHEN 'fastbin' THEN 1 ELSE 2 END,src_addr LIMIT 500", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
                const char *lt = (const char*)sqlite3_column_text(st,2);
                if (lt && !strcmp(lt,"next_chunk"))
                    snprintf(buf,sizeof(buf),"[%d] 0x%lx -> 0x%lx",
                        ++n,
                        (unsigned long)sqlite3_column_int64(st,0),
                        (unsigned long)sqlite3_column_int64(st,1));
                else
                    snprintf(buf,sizeof(buf),"[%d] %-8s 0x%lx -> 0x%lx",
                        ++n, lt?lt:"?",
                        (unsigned long)sqlite3_column_int64(st,0),
                        (unsigned long)sqlite3_column_int64(st,1));
            fields_add(pd,buf,0,1,DETAIL_NONE,(int)sqlite3_column_int64(st,1));
        }
        sqlite3_finalize(st);
    }
    return pd->count;
}

int heap_query_anomalies(AnalysisDB *adb, int session_id, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[400]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    fields_add(pd,"── Heap Anomalies ──",1,0,DETAIL_NONE,-1);
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT chunk_addr,anomaly_type,severity,description FROM heap_anomalies"
        " WHERE session_id=? ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        while (sqlite3_step(st) == SQLITE_ROW) {
            snprintf(buf,sizeof(buf),"\xe2\x9a\xa0 %-7s %-16s 0x%lx  %s",
                (const char*)sqlite3_column_text(st,2),
                (const char*)sqlite3_column_text(st,1),
                (unsigned long)sqlite3_column_int64(st,0),
                (const char*)sqlite3_column_text(st,3));
            fields_add(pd,buf,1,1,DETAIL_NONE,(int)sqlite3_column_int64(st,0));
        }
        sqlite3_finalize(st);
    }
    return pd->count;
}

int heap_query_visual(AnalysisDB *adb, int session_id, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[512]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;

    sqlite3_prepare_v2(c,
        "SELECT MIN(addr),MAX(addr+size),COUNT(*) FROM heap_chunks WHERE session_id=?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int(st, 1, session_id);
    uint64_t heap_lo=0, heap_hi=0; int total_chunks=0;
    if (sqlite3_step(st)==SQLITE_ROW){
        heap_lo=(uint64_t)sqlite3_column_int64(st,0);
        heap_hi=(uint64_t)sqlite3_column_int64(st,1);
        total_chunks=sqlite3_column_int(st,2);}
    sqlite3_finalize(st);
    if (heap_lo==0||heap_hi<=heap_lo) return -1;

    uint64_t total_bytes = heap_hi - heap_lo;
    snprintf(buf,sizeof(buf),"\xe2\x96\xb8 Heap Layout  0x%lx-0x%lx  %luKB  %d chunks",
        (unsigned long)heap_lo,(unsigned long)heap_hi,
        (unsigned long)(total_bytes/1024), total_chunks);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);

    #define HM_COLS 60
    #define HM_MAX_ROWS 80
    #define HM_MAX_CELLS (HM_COLS * HM_MAX_ROWS)
    uint8_t *cells = calloc(HM_MAX_CELLS, 1);
    if (!cells) return -1;

    uint64_t cell_sz = total_bytes / (HM_COLS * 30);
    if (cell_sz < 16) cell_sz = 16;
    int ncells = (int)(total_bytes / cell_sz);
    if (ncells > HM_MAX_CELLS) ncells = HM_MAX_CELLS;
    if (ncells < HM_COLS) ncells = HM_COLS;
    int nrows = (ncells + HM_COLS - 1) / HM_COLS;

    sqlite3_prepare_v2(c,
        "SELECT addr,size,state FROM heap_chunks WHERE session_id=?"
        " ORDER BY addr", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t ca = (uint64_t)sqlite3_column_int64(st, 0);
            uint64_t cs = (uint64_t)sqlite3_column_int64(st, 1);
            const char *s = (const char*)sqlite3_column_text(st, 2);
            int c_start = (int)((ca - heap_lo) / cell_sz);
            int c_end   = (int)((ca + cs - heap_lo) / cell_sz);
            if (c_start < 0) c_start = 0;
            if (c_end >= ncells) c_end = ncells - 1;
            if (c_end < c_start) c_end = c_start;
            uint8_t val = 1;
            if (s && !strcmp(s, "free")) {
                val = 2;
                sqlite3_stmt *lk = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT link_type FROM heap_links WHERE src_addr=? AND session_id=? LIMIT 1",
                    -1, &lk, NULL);
                if (lk) {
                    sqlite3_bind_int64(lk, 1, (sqlite3_int64)ca);
                    sqlite3_bind_int(lk, 2, session_id);
                    if (sqlite3_step(lk) == SQLITE_ROW) {
                        const char *lt = (const char*)sqlite3_column_text(lk, 0);
                        if (lt && !strcmp(lt, "tcache")) val = 3;
                        else if (lt && !strcmp(lt, "fastbin")) val = 4;
                    }
                    sqlite3_finalize(lk);
                }
            }
            for (int ci = c_start; ci <= c_end && ci < ncells; ci++)
                if (cells[ci] == 0 || (cells[ci] == 1 && val >= 2))
                    cells[ci] = val;
        }
        sqlite3_finalize(st);
    }

    for (int i = ncells - 1; i >= 0; i--) {
        if (cells[i] >= 1 && cells[i] <= 4) break;
        cells[i] = 5;
    }

    const char *sym[] = {" ","\xe2\x96\x93","\xe2\x96\x91","\xe2\x96\x92","\xc2\xb7","\xe2\x96\x88"};
    for (int row = 0; row < nrows; row++) {
        int c0 = row * HM_COLS;
        uint64_t r_start = heap_lo + (uint64_t)c0 * cell_sz;
        char line[512]; int lp = 0;
        lp += snprintf(line+lp, sizeof(line)-(size_t)lp, "0x%010lx\xe2\x94\x82", (unsigned long)r_start);
        for (int ci = c0; ci < c0 + HM_COLS && ci < ncells && lp < 450; ci++) {
            uint8_t v = cells[ci]; if (v > 5) v = 0;
            const char *s = sym[v];
            while (*s && lp < 450) line[lp++] = *s++;
        }
        line[lp] = 0;
        fields_add(pd, line, 1, 0, DETAIL_NONE, -1);
    }

    int cnt[6] = {0};
    for (int i = 0; i < ncells; i++) if (cells[i] < 6) cnt[cells[i]]++;
    free(cells);

    snprintf(buf,sizeof(buf),"\xe2\x96\x93=alloc(%d) \xe2\x96\x91=free(%d) \xe2\x96\x92=tcache(%d) \xc2\xb7=fastbin(%d) \xe2\x96\x88=top(%d)  cell=%luB  %d rows",
        cnt[1],cnt[2],cnt[3],cnt[4],cnt[5],(unsigned long)cell_sz,nrows);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    fields_add(pd,"[v]=visual [o]=overview [c]=chunks [l]=links [Enter]=jump [h]=back",1,0,DETAIL_NONE,-1);
    return pd->count;
}


/* ── Chunk 详情 ── */
int heap_query_chunk_detail(AnalysisDB *adb, uint64_t addr, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[512]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;

    sqlite3_prepare_v2(c,
        "SELECT size,state,allocator,prev_size,flags,session_id"
        " FROM heap_chunks WHERE addr=?", -1, &st, NULL);
    if (!st || sqlite3_bind_int64(st,1,(sqlite3_int64)addr)!=SQLITE_OK
        || sqlite3_step(st)!=SQLITE_ROW) {
        if(st)sqlite3_finalize(st);
        fields_add(pd,"(chunk not found)",0,0,DETAIL_NONE,-1);
        return -1;
    }
    uint64_t size  = (uint64_t)sqlite3_column_int64(st,0);
    const char *state = (const char*)sqlite3_column_text(st,1);
    uint64_t psize = (uint64_t)sqlite3_column_int64(st,3);
    int flags = sqlite3_column_int(st,4);
    int sid  = sqlite3_column_int(st,5);
    sqlite3_finalize(st);

    snprintf(buf,sizeof(buf),"▸ Chunk @ 0x%lx  [%s]",(unsigned long)addr,state?state:"?");
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* Header info */
    fields_add(pd,"── Header ──",1,0,DETAIL_NONE,-1);
    int has_prev_inuse = (flags & 1);
    snprintf(buf,sizeof(buf),"prev_size: 0x%lx (%lu)",(unsigned long)psize,(unsigned long)psize);
    fields_add(pd,buf,2,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"size:     0x%lx (%lu)  flags: %s %s %s",
        (unsigned long)(size+16), (unsigned long)(size+16),
        has_prev_inuse?"PREV_INUSE":"",
        (flags&2)?"IS_MMAPPED":"",
        (flags&4)?"NON_MAIN_ARENA":"");
    fields_add(pd,buf,2,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"user_size: 0x%lx (%luB)",(unsigned long)size,(unsigned long)size);
    fields_add(pd,buf,2,0,DETAIL_NONE,-1);

    /* Free list pointers (if free) */
    if (state && !strcmp(state,"free")) {
        fields_add(pd,"",0,0,DETAIL_NONE,-1);
        fields_add(pd,"── Free List Pointers ──",1,0,DETAIL_NONE,-1);
        sqlite3_prepare_v2(c,
            "SELECT dst_addr,link_type FROM heap_links WHERE src_addr=? AND session_id=?",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st,1,(sqlite3_int64)addr);
            sqlite3_bind_int(st,2,sid);
            while(sqlite3_step(st)==SQLITE_ROW) {
                uint64_t dst = (uint64_t)sqlite3_column_int64(st,0);
                const char *lt = (const char*)sqlite3_column_text(st,1);
                char ann[64]; heap_annotate_addr(adb,sid,dst,ann,sizeof(ann));
                snprintf(buf,sizeof(buf),"%s → 0x%lx  %s",lt?lt:"?",(unsigned long)dst,ann);
                fields_add(pd,buf,2,1,DETAIL_NONE,(int)dst);
            }
            sqlite3_finalize(st);
        }

        /* Links pointing TO this chunk */
        sqlite3_prepare_v2(c,
            "SELECT src_addr,link_type FROM heap_links WHERE dst_addr=? AND session_id=?",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st,1,(sqlite3_int64)addr);
            sqlite3_bind_int(st,2,sid);
            int has_in = 0;
            while(sqlite3_step(st)==SQLITE_ROW) {
                if (!has_in) { fields_add(pd,"(referenced by)",2,0,DETAIL_NONE,-1); has_in=1; }
                uint64_t src = (uint64_t)sqlite3_column_int64(st,0);
                snprintf(buf,sizeof(buf),"← 0x%lx",(unsigned long)src);
                fields_add(pd,buf,3,1,DETAIL_NONE,(int)src);
            }
            sqlite3_finalize(st);
        }
    }

    /* Neighbors */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"── Neighbors ──",1,0,DETAIL_NONE,-1);
    /* prev chunk */
    if (psize > 0 && addr >= psize) {
        uint64_t prev = addr - psize;
        sqlite3_prepare_v2(c,"SELECT size,state FROM heap_chunks WHERE addr=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)prev);
            if(sqlite3_step(st)==SQLITE_ROW) {
                char ann[64]; heap_annotate_addr(adb,sid,prev,ann,sizeof(ann));
                snprintf(buf,sizeof(buf),"← prev: 0x%lx [%s] 0x%lx %s",
                    (unsigned long)prev,(const char*)sqlite3_column_text(st,1),
                    (unsigned long)sqlite3_column_int64(st,0),ann);
                fields_add(pd,buf,2,1,DETAIL_NONE,(int)prev);
            } else {
                snprintf(buf,sizeof(buf),"← prev: 0x%lx (not in DB)",(unsigned long)prev);
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            }
            sqlite3_finalize(st);}
    }
    /* next chunk */
    uint64_t next = addr + 16 + size;
    sqlite3_prepare_v2(c,"SELECT size,state FROM heap_chunks WHERE addr=?",
        -1,&st,NULL);
    if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)next);
        if(sqlite3_step(st)==SQLITE_ROW) {
                char ann_n[64]; heap_annotate_addr(adb,sid,next,ann_n,sizeof(ann_n));
                snprintf(buf,sizeof(buf),"→ next: 0x%lx [%s] 0x%lx %s",
                    (unsigned long)next,(const char*)sqlite3_column_text(st,1),
                    (unsigned long)sqlite3_column_int64(st,0),ann_n);
            fields_add(pd,buf,2,1,DETAIL_NONE,(int)next);
        } else {
            snprintf(buf,sizeof(buf),"→ next: 0x%lx (not in DB)",(unsigned long)next);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);}

    /* Anomalies for this chunk */
    sqlite3_prepare_v2(c,
        "SELECT anomaly_type,severity,description FROM heap_anomalies"
        " WHERE chunk_addr=? AND session_id=?", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st,1,(sqlite3_int64)addr);
        sqlite3_bind_int(st,2,sid);
        int na = 0;
        while(sqlite3_step(st)==SQLITE_ROW) {
            if(!na){fields_add(pd,"",0,0,DETAIL_NONE,-1);
                fields_add(pd,"── Heap Anomalies ──",1,0,DETAIL_NONE,-1);}
            snprintf(buf,sizeof(buf),"\xe2\x9a\xa0 %-7s %s: %s",
                (const char*)sqlite3_column_text(st,1),
                (const char*)sqlite3_column_text(st,0),
                (const char*)sqlite3_column_text(st,2));
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            na++;
        }
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"[f]=data flow [Enter]=jump [h]=back",1,0,DETAIL_NONE,-1);
    return 0;
}

/* ── Link 详情 ── */
int heap_query_link_detail(AnalysisDB *adb, uint64_t src, uint64_t dst, PanelData *pd) {
    if (!adb || !pd) return -1;
    char buf[512]; sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;

    /* Link info */
    sqlite3_prepare_v2(c,
        "SELECT link_type FROM heap_links WHERE src_addr=? AND dst_addr=? LIMIT 1",
        -1, &st, NULL);
    char ltype[32]="?";
    if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)src);
        sqlite3_bind_int64(st,2,(sqlite3_int64)dst);
        if(sqlite3_step(st)==SQLITE_ROW)
            snprintf(ltype,sizeof(ltype),"%s",(const char*)sqlite3_column_text(st,0));
        sqlite3_finalize(st);}

    snprintf(buf,sizeof(buf),"Link: %s  0x%lx  0x%lx",ltype,(unsigned long)src,(unsigned long)dst);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* Source */
    fields_add(pd,"── Source ──",1,0,DETAIL_NONE,-1);
    char ann_s[64]; heap_annotate_addr(adb, 0, src, ann_s, sizeof(ann_s));
    snprintf(buf,sizeof(buf),"0x%lx  %s", (unsigned long)src, ann_s);
    fields_add(pd,buf,2,0,DETAIL_NONE,-1);

    /* Target */
    fields_add(pd,"── Target ──",1,0,DETAIL_NONE,-1);
    char ann_d[64]; heap_annotate_addr(adb, 0, dst, ann_d, sizeof(ann_d));
    snprintf(buf,sizeof(buf),"0x%lx  %s", (unsigned long)dst, ann_d);
    fields_add(pd,buf,2,0,DETAIL_NONE,-1);

    /* Full chain for this link type */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"── Full Chain ──",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(c,
        "SELECT src_addr,dst_addr FROM heap_links"
        " WHERE link_type=?1 ORDER BY src_addr LIMIT 50", -1, &st, NULL);
    if (st) {
        sqlite3_bind_text(st,1,ltype,-1,SQLITE_STATIC);
        char chain[400]=""; int cp=0;
        uint64_t prev_dst=0;
        while(sqlite3_step(st)==SQLITE_ROW) {
            uint64_t s=(uint64_t)sqlite3_column_int64(st,0);
            uint64_t d=(uint64_t)sqlite3_column_int64(st,1);
            if (prev_dst && prev_dst != s && cp < 380)
                cp+=snprintf(chain+cp,sizeof(chain)-(size_t)cp," (gap) ");
            if (s==src) cp+=snprintf(chain+cp,sizeof(chain)-(size_t)cp,"[▶");
            if (cp < 380)
                cp+=snprintf(chain+cp,sizeof(chain)-(size_t)cp,"●→");
            if (s==src) cp+=snprintf(chain+cp,sizeof(chain)-(size_t)cp,"]");
            prev_dst=d;
        }
        if (cp>0) {chain[cp-3]='\0'; /* 去掉最后的 → */ fields_add(pd,chain,2,0,DETAIL_NONE,-1);}
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"● = chunk in chain  [▶] = selected link  [Enter]=jump [h]=back",1,0,DETAIL_NONE,-1);
    return 0;
}

/* ── 地址标注 ──────────────────────────────────────────────────── */

const char *heap_annotate_addr(AnalysisDB *adb, int session_id,
                               uint64_t addr, char *buf, size_t sz) {
    if (!adb || !buf || sz < 32) return "?";
    if (addr == 0) { snprintf(buf, sz, "[NULL]"); return buf; }
    if (addr < 0x1000) { snprintf(buf, sz, "[small]"); return buf; }

    /* 读取 /proc/<pid>/maps 判断地址归属 */
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    sqlite3_stmt *st = NULL;
    int pid = 0;
    sqlite3_prepare_v2(c, "SELECT pid FROM heap_sessions WHERE id=?",
                       -1, &st, NULL);
    if (st) {
        sqlite3_bind_int(st, 1, session_id);
        if (sqlite3_step(st) == SQLITE_ROW) pid = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    if (pid <= 0) { snprintf(buf, sz, "0x%lx", (unsigned long)addr); return buf; }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) { snprintf(buf, sz, "0x%lx", (unsigned long)addr); return buf; }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        uint64_t s = 0, e = 0; char p[8] = ""; char f[256] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &s, &e, p, f) < 2) continue;
        if (addr < s || addr >= e) continue;

        /* 确定标签 */
        if (strstr(f, "[heap]"))       { snprintf(buf,sz,"[heap+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (strstr(f, "[stack]"))      { snprintf(buf,sz,"[stack+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (strstr(f, "[vdso]"))       { snprintf(buf,sz,"[vdso]"); fclose(fp); return buf; }
        if (strstr(f, "[vvar]"))       { snprintf(buf,sz,"[vvar]"); fclose(fp); return buf; }
        if (strstr(f, "[vsyscall]"))   { snprintf(buf,sz,"[vsyscall]"); fclose(fp); return buf; }
        if (strstr(f, "libc") || strstr(f, "libc-") || strstr(f, "libc.so"))
            { snprintf(buf,sz,"[libc+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (strstr(f, "ld-") || strstr(f, "ld.so"))
            { snprintf(buf,sz,"[ld+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (strstr(f, ".so"))
            { snprintf(buf,sz,"[lib+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (p[2] == 'x')
            { snprintf(buf,sz,"[code+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        if (p[0] == 'r' && p[1] == 'w')
            { snprintf(buf,sz,"[rw+0x%lx]",(unsigned long)(addr-s)); fclose(fp); return buf; }
        snprintf(buf,sz,"[%s+0x%lx]",f[0]?f:"anon",(unsigned long)(addr-s));
        fclose(fp); return buf;
    }
    fclose(fp);
    snprintf(buf, sz, "0x%lx (unmapped)", (unsigned long)addr);
    return buf;
}
