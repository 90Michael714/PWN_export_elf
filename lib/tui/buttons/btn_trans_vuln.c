#include "tui.h"
#include "tui_buttons.h"
int btn_trans_vuln_action(TuiApp *app){
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    translate_vuln_scan(app->elf,&app->middle_data);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
