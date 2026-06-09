/* btn_expreval.c — ExprEval: expression evaluator */
#include "tui.h"
#include "tui_buttons.h"
int btn_expreval_action(TuiApp *app){
    tui_show_popup(app,"ExprEval","ExprEval evaluates expressions like:\n  $rax + 8\n  [$rsp+0x10]\n  $rip - 0x400000\n\nNeeds live process (registers) or core dump.\nStart with: elf-tui -p <pid>");
    app->need_render=1;return 0;
}
