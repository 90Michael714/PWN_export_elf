#include "tui.h"
#include "tui_buttons.h"
int btn_ropchain_action(TuiApp *app){
    tui_show_popup(app,"ROPchain","ROP chain compiler loaded.\n\nFunctions: rop_compile_execve()\n          rop_compile_system()\n\nPanelData wrapper pending.\nUse CLI for gadget compilation.");
    app->need_render=1;return 0;
}
