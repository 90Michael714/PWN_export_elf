/* btn_vulnscan.c — VulnScan: 漏洞模式匹配 → 中面板 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"

int btn_vulnscan_action(TuiApp *app) {
    if (!app->adb) {
        tui_show_popup(app, "VulnScan", "Database not ready.");
        app->need_render = 1; return 0;
    }
    if (app->db_importing) {
        tui_show_popup(app, "VulnScan", "Import in progress...");
        app->need_render = 1; return 0;
    }

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0; app->middle_data.capacity = 0;
        app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    db_vuln_query(app->adb, &app->middle_data);
    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}
