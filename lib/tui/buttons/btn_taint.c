/* btn_taint.c — Taint: 直接从 symbols+xrefs+instructions JOIN 查污点源 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"

int btn_taint_action(TuiApp *app) {
    if (!app->adb) { tui_show_popup(app,"Taint","DB not ready."); app->need_render=1; return 0; }
    if (app->db_importing) { tui_show_popup(app,"Taint","Import in progress..."); app->need_render=1; return 0; }

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;
    }

    fields_add(&app->middle_data,"=== Taint Source Analysis ===",0,0,DETAIL_NONE,-1);

    sqlite3 *c = (sqlite3 *)db_conn(app->adb);
    char buf[400];
    int total = 0;

    /* 实际污点查询 */
    fields_add(&app->middle_data,"── Taint Sources ──",1,0,DETAIL_NONE,-1);
    static const char *taint_funcs[] = {
        "recv","recvfrom","read","fread","fgets","gets","getenv",
        "scanf","accept","accept4","write","send","sendto",
        "connect","socket","bind","listen", NULL
    };

    for (const char **tf = taint_funcs; *tf; tf++) {
        char sql[600];
        snprintf(sql,sizeof(sql),
            "SELECT i.address, s.name, f.name"
            " FROM instructions i"
            " JOIN xrefs x ON i.address=x.from_addr"
            " JOIN symbols s ON x.to_addr=s.address AND s.table_name='.plt'"
            " LEFT JOIN functions f ON f.start_addr<=i.address AND f.end_addr>i.address"
            " WHERE i.mnemonic='call' AND x.ref_type='call' AND s.name='%s'"
            " LIMIT 50", *tf);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c, sql, -1, &st, NULL) != SQLITE_OK) continue;
        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *sn  = (const char *)sqlite3_column_text(st, 1);
            const char *fn  = (const char *)sqlite3_column_text(st, 2);
            if (!found) {
                snprintf(buf,sizeof(buf),"\xe2\x86\x93 %s:", *tf);
                fields_add(&app->middle_data,buf,1,0,DETAIL_NONE,-1);
            }
            snprintf(buf,sizeof(buf),"0x%lx  %s  [%s]",(unsigned long)addr,sn?sn:"?",fn?fn:"?");
            fields_add(&app->middle_data,buf,2,1,DETAIL_NONE,(int)addr);
            found++; total++;
        }
        sqlite3_finalize(st);
    }

    if (total == 0) {
        fields_add(&app->middle_data,"(no taint sources found — binary may use syscalls directly)",1,0,DETAIL_NONE,-1);
        fields_add(&app->middle_data,"Try VulnScan for sink-based vulnerability detection.",1,0,DETAIL_NONE,-1);
    } else {
        snprintf(buf,sizeof(buf),"%d taint source call sites found",total);
        fields_add(&app->middle_data,buf,1,0,DETAIL_NONE,-1);
    }
    fields_add(&app->middle_data,"",0,0,DETAIL_NONE,-1);
    fields_add(&app->middle_data,"\xe2\x86\x93 = external input  [Enter]=follow to detail",1,0,DETAIL_NONE,-1);

    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}
