/* btn_keyhelp.c — KeyHelp button stub */

#include "tui.h"
#include "tui_buttons.h"

int btn_keyhelp_action(TuiApp *app)
{
    tui_show_popup(app,
        "KeyHelp",
        "This feature is under development.\n\n"
        "Keyboard shortcut reference.\n\n"
        "Full implementation coming soon."
    );
    app->need_render = 1;
    return 0;
}
