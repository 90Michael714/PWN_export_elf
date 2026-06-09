/* btn_gotplt.c — GOT/PLT: 解析全局偏移表和过程链接表 */
#include "tui.h"
#include "tui_buttons.h"
int btn_gotplt_action(TuiApp *app){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr*)app->elf->map;
    int idx=-1;
    for(int i=0;i<ehdr->e_shnum;i++){
        const char *n=elf_section_name(app->elf,i);
        if(n&&strstr(n,".got.plt")){idx=i;break;}
    }
    if(idx<0){
        for(int i=0;i<ehdr->e_shnum;i++){
            const char *n=elf_section_name(app->elf,i);
            if(n&&!strcmp(n,".got")){idx=i;break;}
        }
    }
    if(idx<0){tui_show_popup(app,"GOT/PLT","No GOT section found.");app->need_render=1;return 0;}
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    parse_got_plt(app->elf,idx,&app->middle_data);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
