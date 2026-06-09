/*
 * btn_stack.c — Stack View 按钮: 栈视图面板
 *
 * 依赖: stack_view.c (render_stack_view)
 * 触发条件: DebugState 必须有效 (已 attach 到目标进程)
 *
 * 符合 btn_*.c 标准模式: 清空中面板 → 调用渲染函数 → 显示
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"

/* 声明 stack_view.c 的接口 */
extern int render_stack_view(void *ds, Elf64_Ctx *ctx, PanelData *pd);

int btn_stack_action(TuiApp *app)
{
    if (!app->debug) {
        tui_show_popup(app, "Stack View",
                       "No debug session active.\n\n"
                       "Attach to a running process first:\n"
                       "  1. Open the target ELF file\n"
                       "  2. Press F5 to start debugging\n"
                       "  (or use the debug attach from menu)\n\n"
                       "Then the stack view will show live memory.");
        app->need_render = 1;
        return 0;
    }

    /* 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 渲染栈视图 */
    render_stack_view(app->debug, app->elf, &app->middle_data);

    if (app->middle_data.count > 0)
        app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}
