/* btn_syscall.c — SysCall: x86-64 系统调用表 */
#include "tui.h"
#include "tui_buttons.h"

extern int syscall_count(void);
extern const void *syscall_at(int idx);
extern int syscall_format(const void *sc, char *buf, size_t sz);

int btn_syscall_action(TuiApp *app){
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    int total = syscall_count();
    char buf[256];
    snprintf(buf,sizeof(buf),"=== x86-64 Syscall Table (%d entries) ===", total);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
    for(int i = 0; i < total; i++){
        const void *sc = syscall_at(i);
        if(!sc) continue;
        char line[128];
        syscall_format(sc, line, sizeof(line));
        fields_add(&app->middle_data, line, 1, 0, DETAIL_NONE, -1);
    }
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
