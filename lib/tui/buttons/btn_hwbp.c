#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
int btn_hwbp_action(TuiApp *app){
    if(!app->debug){app->pid_target=5;app->pid_input_active=1;app->pid_input_pos=0;memset(app->pid_input_buf,0,16);
        tui_show_popup(app,"Debug","Enter target PID:\n\n  _\n\n[Enter]confirm [Esc]cancel");app->need_render=1;return 0;}
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    fields_add(&app->middle_data,"=== HW Breakpoints (DR0-DR7) ===",0,0,DETAIL_NONE,-1);
    /* DR0-DR7 are in debug registers, not in user_regs_struct.
       Use ptrace PTRACE_PEEKUSER to read them (offset in user area) */
    fields_add(&app->middle_data,"DR0-DR3: breakpoint addresses",1,0,DETAIL_NONE,-1);
    fields_add(&app->middle_data,"DR6: status register",1,0,DETAIL_NONE,-1);
    fields_add(&app->middle_data,"DR7: control register",1,0,DETAIL_NONE,-1);
    fields_add(&app->middle_data,"(Use PTRACE_PEEKUSER offset 848-880 for DR0-DR7)",1,0,DETAIL_NONE,-1);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
