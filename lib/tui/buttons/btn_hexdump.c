/* btn_hexdump.c — HexDump: 节列表→中面板, hex→右面板 */
#include "tui.h"
#include "tui_buttons.h"
int btn_hexdump_action(TuiApp *app){
    /* 清空中/右面板 */
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    if(app->right_data.fields){fields_free(app->right_data.fields,app->right_data.count);
        app->right_data.fields=NULL;app->right_data.count=0;app->right_data.capacity=0;
        app->right_data.cursor=0;app->right_data.scroll=0;app->right_data.scroll_x=0;}

    Elf64_Ehdr *ehdr=(Elf64_Ehdr*)app->elf->map;
    char buf[192];
    int count=0;

    /* 中面板: PROGBITS 节列表 */
    fields_add(&app->middle_data,"=== HexDump Sections ===",0,0,DETAIL_NONE,-1);
    for(int i=0;i<ehdr->e_shnum;i++){
        Elf64_Shdr *sh=elf_get_shdr(app->elf,i);
        if(sh->sh_type!=SHT_PROGBITS||sh->sh_size==0)continue;
        const char *n=elf_section_name(app->elf,i);
        const char *stype="";
        if(sh->sh_flags&SHF_EXECINSTR) stype="[CODE]";
        else if(sh->sh_flags&SHF_WRITE) stype="[DATA]";
        else if(!(sh->sh_flags&SHF_WRITE)) stype="[RO]";
        snprintf(buf,sizeof(buf),"[%02d] %-24s %-6s %7lu B  %s%s%s",
                 i,n?n:"?",stype,(unsigned long)sh->sh_size,
                 (sh->sh_flags&SHF_WRITE)?"W":"-",
                 (sh->sh_flags&SHF_ALLOC)?"A":"-",
                 (sh->sh_flags&SHF_EXECINSTR)?"X":"-");
        fields_add(&app->middle_data,buf,0,1,DETAIL_SHDR,i);
        count++;
    }
    if(count==0){tui_show_popup(app,"HexDump","No PROGBITS sections found.");app->need_render=1;return 0;}
    snprintf(buf,sizeof(buf),"Total: %d sections — select one to view hexdump",count);
    fields_add(&app->middle_data,buf,0,0,DETAIL_NONE,-1);
    app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}
