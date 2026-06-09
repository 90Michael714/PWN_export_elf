/* btn_onegadget.c — OneGadget: execve("/bin/sh") searcher */
#include "tui.h"
#include "tui_buttons.h"
int btn_onegadget_action(TuiApp *app){
    tui_show_popup(app,"OneGadget",
        "One-gadget searcher for execve(\"/bin/sh\").\n\n"
        "Searches executable sections for gadget chains:\n"
        "  mov rdi, <\"/bin/sh\" addr>\n"
        "  xor esi, esi / xor edx, edx\n"
        "  call execve (or syscall)\n\n"
        "PanelData wrapper pending — use CLI: one_gadget <binary>");
    app->need_render=1;return 0;
}
