/* btn_bpcond.c — BpCond: conditional breakpoint */
#include "tui.h"
#include "tui_buttons.h"
int btn_bpcond_action(TuiApp *app){
    tui_show_popup(app,"BpCond","Conditional breakpoints activate when:\n  $rax == 0x1234\n  [$rdi] == 0\n  $rip > 0x401000\n\nNeeds live process.\nStart with: elf-tui -p <pid>");
    app->need_render=1;return 0;
}
