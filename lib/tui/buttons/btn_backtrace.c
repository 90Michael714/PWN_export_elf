/* btn_backtrace.c — Backtrace: RBP链回溯 → 中面板 */
#include "tui.h"
#include "tui_buttons.h"

typedef struct { int index; uint64_t rip; uint64_t rbp; uint64_t rsp; } bt_frame_t;

int btn_backtrace_action(TuiApp *app){
    if(!app->debug){app->pid_target=3;app->pid_input_active=1;app->pid_input_pos=0;memset(app->pid_input_buf,0,16);
        tui_show_popup(app,"Debug","Enter target PID:\n\n  _\n\n[Enter]confirm [Esc]cancel");app->need_render=1;return 0;}

    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}

    bt_frame_t frames[64];
    /* 直接调用 backtrace.c 的实现 (含 debug_worker.h → DebugState typedef) */
    extern int backtrace_unwind(void *ds, void *frames, int max);
    int n = backtrace_unwind(app->debug, frames, 64);

    fields_add(&app->middle_data,"=== Stack Backtrace ===",0,0,DETAIL_NONE,-1);
    char buf[256];
    for(int i=0;i<n;i++){
        char sym[64]=""; int64_t off=0;
        if(app->qdb) query_symbol(app->qdb, frames[i].rip, sym, sizeof(sym), &off);
        if(sym[0] && off)
            snprintf(buf,sizeof(buf),"#%d  0x%llx  <%s+0x%lx>",
                     i,(unsigned long long)frames[i].rip,sym,(long)off);
        else if(sym[0])
            snprintf(buf,sizeof(buf),"#%d  0x%llx  <%s>",
                     i,(unsigned long long)frames[i].rip,sym);
        else
            snprintf(buf,sizeof(buf),"#%d  0x%llx  rbp=0x%llx",
                     i,(unsigned long long)frames[i].rip,(unsigned long long)frames[i].rbp);
        fields_add(&app->middle_data,buf,1,i==0?1:0,DETAIL_NONE,i);
    }
    snprintf(buf,sizeof(buf),"%d frames",n);
    fields_add(&app->middle_data,buf,1,0,DETAIL_NONE,-1);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
