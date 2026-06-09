/*
 * trace_view.c — Trace 可视化面板 (PanelData 生产者)
 *
 * 接口: int parse_trace_view(Elf64_Ctx *ctx, int session_id, PanelData *pd);
 *
 * 展示: trace session 列表 + 覆盖率热力图 + BB 执行时间轴
 */

#include "elf_parser.h"
#include "core/pt_trace.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 全局 DB 句柄引用 */
extern AnalysisDB *g_active_db;

int parse_trace_view(Elf64_Ctx *ctx, int session_id, PanelData *pd)
{
    if (!ctx || !pd) return -1;

    AnalysisDB *adb = g_active_db;
    if (!adb) {
        fields_add(pd, "(DB not available)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) {
        fields_add(pd, "(DB connection failed)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }

    char buf[512];

    /* ── 列出所有 trace session ── */
    if (session_id <= 0) {
        fields_add(pd, "=== Trace Sessions ===", 0, 0, DETAIL_NONE, -1);

        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT id, pid, backend, bb_count, unique_bbs, start_time "
            "FROM trace_sessions ORDER BY id DESC LIMIT 20",
            -1, &st, NULL);
        if (st) {
            int n = 0;
            while (sqlite3_step(st) == SQLITE_ROW) {
                int sid = sqlite3_column_int(st, 0);
                int pid = sqlite3_column_int(st, 1);
                const char *be = (const char *)sqlite3_column_text(st, 2);
                int bb_c = sqlite3_column_int(st, 3);
                int u_bb = sqlite3_column_int(st, 4);

                double cov = 0;
                sqlite3_stmt *sc = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT (SELECT COUNT(DISTINCT bb_addr) FROM trace_blocks"
                    " WHERE session_id=?1) * 100.0 / "
                    "(SELECT MAX(1,COUNT(*)) FROM basic_blocks)",
                    -1, &sc, NULL);
                if (sc) {
                    sqlite3_bind_int(sc, 1, sid);
                    if (sqlite3_step(sc) == SQLITE_ROW) cov = sqlite3_column_double(sc, 0);
                    sqlite3_finalize(sc);
                }

                snprintf(buf, sizeof(buf), "[#%d] PID %-6d  %-12s  %5d BBs  %4d unique  %.1f%% cov",
                         sid, pid, be ? be : "?", bb_c, u_bb, cov);
                fields_add(pd, buf, 1, 1, DETAIL_NONE, sid);
                n++;
            }
            sqlite3_finalize(st);
            if (n == 0)
                fields_add(pd, "(no trace sessions — run PT Trace first)", 1, 0, DETAIL_NONE, -1);
        }

        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        fields_add(pd, "[Enter]=open session  [v]=coverage  [t]=timeline  [h]=back",
                   1, 0, DETAIL_NONE, -1);
        return 0;
    }

    /* ── 单个 session 的详细视图 ── */
    snprintf(buf, sizeof(buf), "=== Trace Session #%d ===", session_id);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* Coverage 报告 */
    trace_coverage_report(adb, session_id, pd);

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[t]=timeline  [p]=hotspots  [c]=coverage  [h]=back",
               1, 0, DETAIL_NONE, -1);

    return 0;
}

/* 子命令: 按键处理 (由 tui_input.c 或按钮调用) */
int trace_view_handle_key(AnalysisDB *adb, int session_id,
                          int key, PanelData *pd)
{
    if (!adb || !pd || session_id <= 0) return 0;

    if (pd->fields) { /* 清空面板 */
        extern void fields_free(Elf64_Field*, int);
        fields_free(pd->fields, pd->count);
        pd->fields = NULL; pd->count = 0; pd->capacity = 0;
        pd->cursor = 0; pd->scroll = 0;
    }

    switch (key) {
        case 't': case 'T': trace_timeline(adb, session_id, pd);    return 1;
        case 'p': case 'P': trace_hotspots(adb, session_id, pd);    return 1;
        case 'c': case 'C': trace_coverage_report(adb, session_id, pd); return 1;
        default: return 0;
    }
}
