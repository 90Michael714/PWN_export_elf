/*
 * btn_dbview.c — AnalysisDB 可视化: 统计/指令/XREF/寄存器快照
 *
 * 中面板: DB 总览 → 节指令列表 → 选中地址按 Enter 看 XREF
 * 右面板: XREF 交叉引用 + 寄存器快照 (按 'x' 键或 Enter)
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"
#include "core/debug_worker.h"
#include "disasm.h"
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>

int btn_dbview_action(TuiApp *app)
{
    if(!app->adb){
        tui_show_popup(app, "AnalysisDB", "Database not initialized.\nOpen an ELF file first.");
        app->need_render = 1; return 0;
    }

    /* 清空中面板 */
    if(app->middle_data.fields){
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0; app->middle_data.capacity = 0;
        app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    /* ── DB 总览 ── */
    char buf[256];
    int insn_total = db_insn_count(app->adb);
    int snap_total = db_snapshot_count(app->adb);

    fields_add(&app->middle_data,
        "=== Analysis Database ===  [Enter]=XREF  [x]=RegSnap  [h]=back",
        0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Instructions: %d   Snapshots: %d   (in-memory SQLite3)",
             insn_total, snap_total);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);

    /* ── 按节统计指令 ── */
    fields_add(&app->middle_data, "--- Instruction Count by Section ---",
               1, 0, DETAIL_NONE, -1);

    if(insn_total <= 0){
        fields_add(&app->middle_data, "(no instructions imported)", 1, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1; return 0;
    }

    /* 查询: 每节多少条指令 */
    sqlite3 *conn = (sqlite3 *)db_conn(app->adb);
    const char *sec_sql =
        "SELECT section, COUNT(*) as cnt FROM instructions"
        " GROUP BY section ORDER BY cnt DESC LIMIT 30";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(conn, sec_sql, -1, &stmt, NULL);
    if(!stmt){
        fields_add(&app->middle_data, "(query failed)", 1, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1; return 0;
    }

    int sec_idx = 0;
    while(sqlite3_step(stmt) == SQLITE_ROW && sec_idx < 30){
        const char *sec = (const char *)sqlite3_column_text(stmt, 0);
        int cnt = sqlite3_column_int(stmt, 1);
        snprintf(buf, sizeof(buf), "%6d insns  —  %s",
                 cnt, sec && sec[0] ? sec : "(unnamed)");
        fields_add(&app->middle_data, buf, 1, 1, DETAIL_NONE, sec_idx);
        sec_idx++;
    }
    sqlite3_finalize(stmt);

    if(sec_idx == 0)
        fields_add(&app->middle_data, "(no sections)", 1, 0, DETAIL_NONE, -1);

    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);

    /* ── Top 10 被调用函数 ── */
    fields_add(&app->middle_data, "--- Top 10 Most Called (by CALL xref) ---",
               1, 0, DETAIL_NONE, -1);

    const char *call_sql =
        "SELECT to_addr, COUNT(*) as cnt FROM xrefs"
        " WHERE ref_type='call' GROUP BY to_addr ORDER BY cnt DESC LIMIT 10";
    sqlite3_prepare_v2(conn, call_sql, -1, &stmt, NULL);
    if(stmt){
        int rank = 0;
        while(sqlite3_step(stmt) == SQLITE_ROW && rank < 10){
            uint64_t addr = (uint64_t)sqlite3_column_int64(stmt, 0);
            int cnt = sqlite3_column_int(stmt, 1);
            snprintf(buf, sizeof(buf), "%d× CALL →  0x%lx  %s",
                     cnt, (unsigned long)addr,
                     rank == 0 ? "(most called)" : "");
            fields_add(&app->middle_data, buf, 1, 1, DETAIL_NONE, 100 + rank);
            rank++;
        }
        sqlite3_finalize(stmt);
    }

    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data,
        "Select any address and press [Enter] for XREFs, or [x] for Reg Snapshots",
        1, 0, DETAIL_NONE, -1);

    if(app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/*
 * dbview_show_xrefs: 中面板选中地址 → 右面板显示交叉引用
 * 被 tui_input.c 的 PANEL_MIDDLE Enter 或 'x' 处理调用
 */
int dbview_show_xrefs(TuiApp *app, const char *line)
{
    if(!app || !app->adb || !line) return -1;

    /* 提取地址: "0x..." 或 "  ...  0xADDR" */
    uint64_t addr = 0;
    const char *p = strstr(line, "0x");
    if(p) addr = strtoull(p, NULL, 16);
    if(!addr){
        /* 尝试从 "N× CALL → 0xADDR" 格式提取 */
        p = strchr(line, 'x');
        if(p) addr = strtoull(p + 1, NULL, 16);
    }
    if(!addr) return -1;

    /* 清空右面板 */
    if(app->right_data.fields){
        fields_free(app->right_data.fields, app->right_data.count);
        app->right_data.fields = NULL;
        app->right_data.count = 0; app->right_data.capacity = 0;
        app->right_data.cursor = 0; app->right_data.scroll = 0;
        app->right_data.scroll_x = 0;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "=== XREFs for 0x%lx ===", (unsigned long)addr);
    fields_add(&app->right_data, buf, 0, 0, DETAIL_NONE, -1);

    /* ── 谁引用了这个地址 ── */
    DbXref xrefs[256];
    int nx = db_query_xref_to(app->adb, addr, xrefs, 256);
    snprintf(buf, sizeof(buf), "--- Referenced by (%d) ---", nx);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
    if(nx == 0){
        fields_add(&app->right_data, "(none)", 2, 0, DETAIL_NONE, -1);
    }else{
        for(int i = 0; i < nx && i < 50; i++){
            snprintf(buf, sizeof(buf), "0x%lx  %-6s  %s",
                     (unsigned long)xrefs[i].from_addr,
                     xrefs[i].ref_type,
                     xrefs[i].detail);
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
        if(nx > 50){
            snprintf(buf, sizeof(buf), "... and %d more", nx - 50);
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
    }
    fields_add(&app->right_data, "", 0, 0, DETAIL_NONE, -1);

    /* ── 这个地址引用了谁 ── */
    nx = db_query_xref_from(app->adb, addr, xrefs, 256);
    snprintf(buf, sizeof(buf), "--- References to (%d) ---", nx);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
    if(nx == 0){
        fields_add(&app->right_data, "(none)", 2, 0, DETAIL_NONE, -1);
    }else{
        for(int i = 0; i < nx && i < 50; i++){
            snprintf(buf, sizeof(buf), "0x%lx  %-6s  %s",
                     (unsigned long)xrefs[i].to_addr,
                     xrefs[i].ref_type,
                     xrefs[i].detail);
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
        if(nx > 50){
            snprintf(buf, sizeof(buf), "... and %d more", nx - 50);
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
    }
    fields_add(&app->right_data, "", 0, 0, DETAIL_NONE, -1);

    /* ── 寄存器快照 ── */
    DbRegSnap snaps[32];
    int ns = db_query_reg_at_insn(app->adb, addr, snaps, 32);
    snprintf(buf, sizeof(buf), "--- Register Snapshots at this RIP (%d) ---", ns);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
    if(ns == 0){
        fields_add(&app->right_data, "(no snapshots — attach + step first)", 2, 0, DETAIL_NONE, -1);
    }else{
        for(int i = 0; i < ns && i < 10; i++){
            snprintf(buf, sizeof(buf),
                "step %d  RAX=0x%lx RBX=0x%lx RCX=0x%lx RDX=0x%lx",
                snaps[i].step_num,
                (unsigned long)snaps[i].regs[0], /* RAX */
                (unsigned long)snaps[i].regs[1], /* RBX */
                (unsigned long)snaps[i].regs[2], /* RCX */
                (unsigned long)snaps[i].regs[3]  /* RDX */
            );
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);

            /* 第二行: RSI RDI RBP RSP RIP */
            snprintf(buf, sizeof(buf),
                "       RSI=0x%lx RDI=0x%lx RBP=0x%lx RSP=0x%lx RIP=0x%lx",
                (unsigned long)snaps[i].regs[4], /* RSI */
                (unsigned long)snaps[i].regs[5], /* RDI */
                (unsigned long)snaps[i].regs[6], /* RBP */
                (unsigned long)snaps[i].regs[7], /* RSP */
                (unsigned long)snaps[i].rip
            );
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
        if(ns > 10){
            snprintf(buf, sizeof(buf), "... and %d more snapshots", ns - 10);
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
    }
    fields_add(&app->right_data, "", 0, 0, DETAIL_NONE, -1);

    /* ── 汇编指令本身 ── */
    sqlite3 *conn = (sqlite3 *)db_conn(app->adb);
    const char *dis_sql =
        "SELECT mnemonic, op_str, bytes, section FROM instructions WHERE address=?";
    sqlite3_stmt *dst = NULL;
    sqlite3_prepare_v2(conn, dis_sql, -1, &dst, NULL);
    if(dst){
        sqlite3_bind_int64(dst, 1, (sqlite3_int64)addr);
        if(sqlite3_step(dst) == SQLITE_ROW){
            const char *mn = (const char *)sqlite3_column_text(dst, 0);
            const char *op = (const char *)sqlite3_column_text(dst, 1);
            const char *sec = (const char *)sqlite3_column_text(dst, 3);
            snprintf(buf, sizeof(buf), "--- Disassembly ---");
            fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
            snprintf(buf, sizeof(buf), "%s %s  [%s]",
                     mn ? mn : "?", op ? op : "",
                     sec ? sec : "?");
            fields_add(&app->right_data, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(dst);
    }

    snprintf(buf, sizeof(buf), "\n[q] back to DB view  [h] back to middle");
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}
