/*
 * btn_hardening.c — Hardening button: 安全加固检查
 *
 * 将 parse_security() 的输出显示在中间面板 (middle_data) 中。
 */

#include "tui.h"
#include "tui_buttons.h"

int btn_hardening_action(TuiApp *app)
{
    /* 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 调用 security.c 的解析函数, 输出到中面板 */
    parse_security(app->elf, &app->middle_data);

    /* 自动切换到中面板查看结果 */
    if (app->middle_data.count > 0)
        app->active_panel = PANEL_MIDDLE;

    app->need_render = 1;
    return 0;
}
