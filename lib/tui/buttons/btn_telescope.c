#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
int btn_telescope_action(TuiApp *app){
    if(!app->debug){app->pid_target=4;app->pid_input_active=1;app->pid_input_pos=0;memset(app->pid_input_buf,0,16);
        tui_show_popup(app,"Debug","Enter target PID:\n\n  _\n\n[Enter]confirm [Esc]cancel");app->need_render=1;return 0;}
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    fields_add(&app->middle_data,"=== Telescope @ RSP ===",0,0,DETAIL_NONE,-1);
    uint64_t rsp=app->debug->regs.rsp;
    char buf[256]; uint64_t vals[8];
    for(int i=0;i<8;i++){
        if(debug_readmem(app->debug,rsp+i*8,vals+i,8)!=8)break;
        char sym[64]="";int64_t off=0;
        if(app->qdb)query_symbol(app->qdb,vals[i],sym,sizeof(sym),&off);
        if(sym[0]&&off)snprintf(buf,sizeof(buf),"RSP+0x%02x: 0x%llx  <%s+0x%lx>",i*8,(unsigned long long)vals[i],sym,(long)off);
        else if(sym[0])snprintf(buf,sizeof(buf),"RSP+0x%02x: 0x%llx  <%s>",i*8,(unsigned long long)vals[i],sym);
        else snprintf(buf,sizeof(buf),"RSP+0x%02x: 0x%llx",i*8,(unsigned long long)vals[i]);
        fields_add(&app->middle_data,buf,1,1,DETAIL_NONE,i);
    }
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
