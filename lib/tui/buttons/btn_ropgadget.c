/* btn_ropgadget.c — ROPgadget: ROP构件搜索 */
#include "tui.h"
#include "tui_buttons.h"
int btn_ropgadget_action(TuiApp *app){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr*)app->elf->map;
    int idx=-1;
    for(int i=0;i<ehdr->e_shnum;i++){
        Elf64_Shdr *sh=elf_get_shdr(app->elf,i);
        if((sh->sh_flags&SHF_EXECINSTR)&&sh->sh_size>0){idx=i;break;}
    }
    if(idx<0){tui_show_popup(app,"ROPgadget","No executable section found.");app->need_render=1;return 0;}
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    parse_gadget(app->elf,idx,&app->middle_data);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
