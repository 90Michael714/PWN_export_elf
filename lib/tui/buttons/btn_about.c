/* btn_about.c — About button stub */

#include "tui.h"
#include "tui_buttons.h"

int btn_about_action(TuiApp *app)
{
    tui_show_popup(app,
        "About",
        "This feature is under development.\n\n"
        "About elf-tui — version, authors, dependencies.\n\n"
        "Full implementation coming soon."
    );
    app->need_render = 1;
    return 0;
}
