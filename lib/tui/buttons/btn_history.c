/* btn_history.c — History button stub */

#include "tui.h"
#include "tui_buttons.h"

int btn_history_action(TuiApp *app)
{
    tui_show_popup(app,
        "History",
        "This feature is under development.\n\n"
        "Recently opened ELF files list.\n\n"
        "Full implementation coming soon."
    );
    app->need_render = 1;
    return 0;
}
