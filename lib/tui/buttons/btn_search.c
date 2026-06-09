/* btn_search.c — Search: 弹出搜索输入框, 支持5种模式 */
#include "tui.h"
#include "tui_buttons.h"
int btn_search_action(TuiApp *app){
    app->search_input_active = 1;
    app->search_input_pos = 0;
    memset(app->search_input_buf, 0, sizeof(app->search_input_buf));
    tui_show_popup(app, "Search",
        "Search Query:\n\n"
        "  _\n\n"
        "Prefix: sym:/addr:/str:/byte: or none for disasm\n"
        "[Enter]Search  [Esc]Cancel");
    app->need_render=1; return 0;
}
