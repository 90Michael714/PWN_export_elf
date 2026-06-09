/* btn_export.c — Export button stub */

#include "tui.h"
#include "tui_buttons.h"

int btn_export_action(TuiApp *app)
{
    tui_show_popup(app,
        "Export",
        "This feature is under development.\n\n"
        "Export panel data as TXT or JSON file.\n\n"
        "Full implementation coming soon."
    );
    app->need_render = 1;
    return 0;
}
