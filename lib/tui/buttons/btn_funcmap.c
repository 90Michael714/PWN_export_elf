/* btn_funcmap.c — FuncMap: 函数调用图 */

#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"

/* 全局 DB 句柄 (由 dataflow.c 定义, callgraph.c 消费) */
extern AnalysisDB *g_active_db;

int btn_funcmap_action(TuiApp *app)
{
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }
    /* 设置全局 DB 句柄, 让 callgraph 走快速 SQL 路径 */
    g_active_db = app->adb;
    parse_callgraph(app->elf, &app->middle_data);
    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}
