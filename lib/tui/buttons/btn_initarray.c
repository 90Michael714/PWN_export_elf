/* btn_initarray.c — InitArray: 构造/析构函数数组 (全部) */
#include "tui.h"
#include "tui_buttons.h"
int btn_initarray_action(TuiApp *app){
    Elf64_Ehdr *ehdr=(Elf64_Ehdr*)app->elf->map;
    int has_any=0;
    for(int i=0;i<ehdr->e_shnum;i++){
        Elf64_Shdr *sh=elf_get_shdr(app->elf,i);
        if(sh && (sh->sh_type==SHT_INIT_ARRAY||sh->sh_type==SHT_FINI_ARRAY||sh->sh_type==SHT_PREINIT_ARRAY))
            {has_any=1;break;}
    }
    if(!has_any){tui_show_popup(app,"InitArray","No init/fini array section found.");app->need_render=1;return 0;}
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    /* -1 = 扫描全部 preinit/init/fini */
    parse_init_array(app->elf,-1,&app->middle_data);
    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
