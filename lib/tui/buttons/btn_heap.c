/* btn_heap.c — Heap: attach → 采集 → 分析 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/heap_analyzer.h"
#include "core/debug_worker.h"
#include "core/db.h"

static int g_sid = -1;  /* 当前会话 ID */

int btn_heap_action(TuiApp *app) {
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app,"Heap","Not attached.\n\nAttach to a process first (Debug → Attach).");
        app->need_render = 1; return 0;
    }
    if (!app->adb) { tui_show_popup(app,"Heap","DB not ready."); app->need_render=1; return 0; }

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;
    }

    /* 采集堆快照 */
    memory_region_t regions[16];
    int nr = heap_get_regions(app->debug, regions, 16);
    if (nr <= 0) {
        fields_add(&app->middle_data,"(no heap region found)",0,0,DETAIL_NONE,-1);
        app->active_panel=PANEL_MIDDLE; app->need_render=1; return 0;
    }

    allocator_parser_t *parser = heap_detect_allocator(app->debug);
    g_sid = heap_session_begin(app->adb, app->debug->pid, parser->name);
    parser->parse_chunks(app->debug, regions, nr, app->adb, g_sid);
    parser->consistency(app->debug, app->adb, g_sid);

    /* 显示概览 */
    heap_query_overview(app->adb, g_sid, &app->middle_data);
    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* 按键切换视图 (从 tui_input.c 调用) */
int btn_heap_handle_key(TuiApp *app, int key) {
    if (g_sid < 0 || !app->adb) return 0;
    PanelData *pd = &app->middle_data;
    if (pd->fields) { fields_free(pd->fields,pd->count);
        pd->fields=NULL;pd->count=0;pd->capacity=0;pd->cursor=0;pd->scroll=0; }

    switch (key) {
        case 'o': case 'O': heap_query_overview(app->adb,g_sid,pd); break;
        case 'c': case 'C': heap_query_chunks(app->adb,g_sid,pd); break;
        case 'l': case 'L': heap_query_links(app->adb,g_sid,pd); break;
        case 'd': case 'D': heap_query_anomalies(app->adb,g_sid,pd); break;
        case 'v': case 'V': heap_query_visual(app->adb,g_sid,pd); break;
        default: return 0;
    }
    app->need_render = 1; return 1;
}
