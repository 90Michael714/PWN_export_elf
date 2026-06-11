/*
 * tui.c — TUI 主控 (渲染/输入分离架构)
 *
 * 渲染: notcurses 单标准平面 + 坐标区域
 * 输入: select()+read() 读 stdin, 仅处理 'q' 退出
 *
 * 不用 notcurses_get 的原因:
 *   WSL2 上 notcurses_get 不阻塞 → CPU 死循环;
 *   notcurses 内部缓冲区 + select() 门控 → 事件堆积卡死。
 *   select()+read() 是经过 50 年验证的可靠方案。
 */

#include "tui.h"
#include "tui_panels.h"
#include "tui_colors.h"
#include "core/cache.h"
#include "core/debug_worker.h"
#include "core/reg_view.h"
#include "disasm.h"
#include <sqlite3.h>
#include <stdio.h>
#include <sys/select.h>

/* ── vmmap 内存区域标注 (调试模式寄存器视图) ──────────────────────── */
typedef struct { uint64_t start,end;char perms[5];uint64_t offset;
    unsigned int dev_major,dev_minor;unsigned long inode;char path[256];} vmmap_entry_t;
extern int vmmap_read(const struct DebugState *ds, vmmap_entry_t *e, int *c);
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

/* ================================================================
 * 反汇编彩色语法 + CFG 箭头
 * ================================================================ */

/* 指令分类 → 颜色映射 */
typedef struct { const char *mnemonic; uint8_t r,g,b; } MnemColor;
static const MnemColor MNEM_COLORS[] = {
    {"call", 0,255,0}, {"jmp",255,200,0},{"je",255,200,0},{"jne",255,200,0},
    {"jg",255,200,0},{"jge",255,200,0},{"jl",255,200,0},{"jle",255,200,0},
    {"ja",255,200,0},{"jb",255,200,0},{"jz",255,200,0},{"jnz",255,200,0},
    {"jo",255,200,0},{"jno",255,200,0},{"js",255,200,0},{"jns",255,200,0},
    {"loop",255,200,0},{"ret",255,60,60},{"syscall",255,0,255},
    {"sysenter",255,0,255},{"int",255,0,255},
    {"push",100,180,255},{"pop",100,180,255},
    {"lea",100,200,255},
    {"cmp",255,180,100},{"test",255,180,100},
    {"nop",100,100,100},
    {NULL,0,0,0}
};

static void disasm_color_for(const char *text, uint8_t *r, uint8_t *g, uint8_t *b){
    if(!text)return;
    const char *colon=strchr(text,':');
    if(!colon)return;
    /* 格式: "  0xADDR: XX XX XX ...    MNEMONIC  OPERANDS"       */
    /* 关键: hex byte 是 2 个 hex 字符+空格, mnemonic 是字母长串  */
    const char *p=colon+1;
    while(*p==' ')p++;
    while(*p){
        /* 计算连续非空白字符数 */
        const char *tok=p;int toklen=0;
        while(tok[toklen]&&!isspace((unsigned char)tok[toklen]))toklen++;
        if(toklen==0)break;
        /* 2字符+都是hex → hex byte, 跳过. 否则 → mnemonic */
        int both_hex=(toklen==2&&isxdigit((unsigned char)tok[0])&&isxdigit((unsigned char)tok[1]));
        if(!both_hex&&isalpha((unsigned char)*p))break; /* mnemonic! */
        p=tok+toklen;
        while(*p==' ')p++;
    }
    if(!isalpha((unsigned char)*p))return;
    const char *mn_start=p;
    while(isalpha((unsigned char)*p))p++;
    size_t mlen=(size_t)(p-mn_start);if(mlen>15)mlen=15;
    char mn[16];memcpy(mn,mn_start,mlen);mn[mlen]=0;
    for(const MnemColor *mc=MNEM_COLORS;mc->mnemonic;mc++)
        if(!strcmp(mn,mc->mnemonic)){*r=mc->r;*g=mc->g;*b=mc->b;return;}
}

/* 从操作数字符串提取跳转目标地址 */
static uint64_t extract_jump_target(const char *text){
    if(!text)return 0;
    const char *p=strrchr(text,' ');
    if(!p)return 0;
    while(*p==' ')p++;
    if(strncmp(p,"0x",2)==0)return strtoull(p+2,NULL,16);
    return 0;
}

/* ================================================================
 * 布局区域 + 渲染
 * ================================================================ */

typedef struct { int y,x,h,w; } Region;
static Region R_status,R_left,R_mid,R_right;
static struct ncplane *P; /* 标准平面快捷引用 */

static void layout_recalc(void){
    unsigned ty,tx;
    ncplane_dim_yx(P,&ty,&tx);
    if(ty<8||tx<50) return;

    R_status.y=0;R_status.x=0;R_status.h=1;R_status.w=(int)tx;

    int lw=(int)tx*20/100, mw=(int)tx*30/100, rw=(int)tx-lw-mw;  /* 20/30/50 */
    if(lw<10){lw=(int)tx*20/100;mw=(int)tx*30/100;rw=(int)tx-lw-mw;}

    R_left .y=1;R_left .x=0;      R_left .h=(int)ty-1;R_left .w=lw;
    R_mid  .y=1;R_mid  .x=lw;     R_mid  .h=(int)ty-1;R_mid  .w=mw;
    R_right.y=1;R_right.x=lw+mw;  R_right.h=(int)ty-1;R_right.w=rw;
}

static void region_clear(Region *r){
    if(r->w<1||r->h<1) return;
    ncplane_set_bg_rgb8(P,0,0,0);
    char *sp=malloc(r->w+1);
    memset(sp,' ',r->w);sp[r->w]=0;
    for(int y=0;y<r->h;y++) ncplane_putstr_yx(P,r->y+y,r->x,sp);
    free(sp);
}

static void region_border(Region *r, const char *title, int active){
    int w=r->w,h=r->h,x0=r->x,y0=r->y;
    if(w<3||h<2) return;
    int cr=active?0x00:0x50,cg=active?0xDD:0x50,cb=active?0xDD:0x50;
    ncplane_set_fg_rgb8(P,cr,cg,cb);
    ncplane_set_bg_rgb8(P,0,0,0);

    /* top */
    char *top=malloc(w*3+4);int tp=0;
    top[tp++]=0xE2;top[tp++]=0x94;top[tp++]=0x8C;
    for(int i=1;i<w-1;i++){top[tp++]=0xE2;top[tp++]=0x94;top[tp++]=0x80;}
    top[tp++]=0xE2;top[tp++]=0x94;top[tp++]=0x90;top[tp]=0;
    ncplane_putstr_yx(P,y0,x0,top);
    if(title&&w>6){ncplane_set_fg_rgb8(P,255,255,255);ncplane_putstr_yx(P,y0,x0+2,title);}

    /* bottom */
    ncplane_set_fg_rgb8(P,cr,cg,cb);
    char *bot=malloc(w*3+4);int bp=0;
    bot[bp++]=0xE2;bot[bp++]=0x94;bot[bp++]=0x94;
    for(int i=1;i<w-1;i++){bot[bp++]=0xE2;bot[bp++]=0x94;bot[bp++]=0x80;}
    bot[bp++]=0xE2;bot[bp++]=0x94;bot[bp++]=0x98;bot[bp]=0;
    ncplane_putstr_yx(P,y0+h-1,x0,bot);

    /* sides */
    char sd[]={(char)0xE2,(char)0x94,(char)0x82,0};
    for(int y=1;y<h-1;y++){ncplane_putstr_yx(P,y0+y,x0,sd);ncplane_putstr_yx(P,y0+y,x0+w-1,sd);}
    free(top);free(bot);
}

static void region_lines(Region *r, PanelData *pd, int active){
    if(!pd||pd->count==0){
        if(r->w>12&&r->h>2) ncplane_putstr_yx(P,r->y+r->h/2,r->x+(r->w-9)/2,"(no data)");
        return;
    }
    int vis=r->h-2;if(vis<1) return;
    if(pd->cursor<pd->scroll)pd->scroll=pd->cursor;
    if(pd->cursor>=pd->scroll+vis)pd->scroll=pd->cursor-vis+1;
    if(pd->scroll<0)pd->scroll=0;
    int ms=pd->count-vis;if(ms<0)ms=0;if(pd->scroll>ms)pd->scroll=ms;
    int end=pd->scroll+vis;if(end>pd->count)end=pd->count;
    int iw=r->w-2;if(iw<2)return;

    char fill[1024],line[512];
    for(int i=pd->scroll;i<end;i++){
        int sy=r->y+1+(i-pd->scroll);
        Elf64_Field *f=&pd->fields[i];
        if(!f->text)continue;
        int ix=r->x+1+f->indent*2, mw=iw-f->indent*2;
        if(mw<2)mw=2;
        int cur=(i==pd->cursor)&&active;

        /* 构建显示文本 (可能附加 CFG 箭头) */
        char display[640];
        size_t tl=strlen(f->text);
        strncpy(display, f->text, sizeof(display)-1);display[sizeof(display)-1]=0;

        /* CFG 箭头: 对跳转/调用指令附加目标地址 */
        if(f->indent==1&&strchr(f->text,':')){
            const char *colon=strchr(f->text,':');
            if(colon){const char *p=colon+1;while(*p==' ')p++;
                while(*p&&*p!=' '&&!isalpha((unsigned char)*p))p++;
                while(*p==' ')p++;
                if(isalpha((unsigned char)*p)){const char *mn=p;
                    while(isalpha((unsigned char)*p))p++;
                    size_t ml=(size_t)(p-mn);if(ml>8)ml=8;
                    int is_jmp=(!strncmp(mn,"jmp",3)||!strncmp(mn,"je",2)||!strncmp(mn,"jg",2)||!strncmp(mn,"jl",2)||!strncmp(mn,"ja",2)||!strncmp(mn,"jb",2)||!strncmp(mn,"jz",2)||!strncmp(mn,"jn",2)||!strncmp(mn,"js",2)||!strncmp(mn,"jo",2)||!strncmp(mn,"jp",2));
                    int is_call=(!strncmp(mn,"call",4));
                    uint64_t jt=0;
                    if(is_jmp||is_call){
                        jt=extract_jump_target(f->text);
                        if(jt>0){
                            char arrow[64];
                            if(is_call)snprintf(arrow,sizeof(arrow),"  → %s 0x%lx",mn,(unsigned long)jt);
                            else snprintf(arrow,sizeof(arrow),"  → 0x%lx",(unsigned long)jt);
                            size_t dl=strlen(display);size_t al=strlen(arrow);
                            if(dl+al<sizeof(display)-1)memcpy(display+dl,arrow,al+1);
                        }
                    }
                }
            }
        }
        /* 反汇编彩色语法: indent=1 + 开头是 hex地址: → 真实反汇编行 */
        uint8_t cr=255,cg=255,cb=0;
        { const char *tx=f->text;while(*tx==' '||(unsigned char)*tx==0xe2)tx++;
          int is_d=(f->indent==1&&isxdigit((unsigned char)tx[0])&&strchr(tx,':'));
          if(!cur&&is_d)disasm_color_for(f->text,&cr,&cg,&cb);

          int is_rip = (f->text && !strncmp(f->text, "RIP ", 4));
          if(cur){
            int fw=iw;if(fw>1023)fw=1023;
            memset(fill,' ',fw);fill[fw]=0;
            ncplane_set_bg_rgb8(P,0,210,210);ncplane_set_fg_rgb8(P,0,0,0);
            ncplane_putstr_yx(P,sy,r->x+1,fill);
          }else{
            ncplane_set_bg_rgb8(P,0,0,0);
            if(is_rip)          ncplane_set_fg_rgb8(P,255,50,50);
            else if(is_d)       ncplane_set_fg_rgb8(P,cr,cg,cb);
            else if(f->indent==0) ncplane_set_fg_rgb8(P,0,255,255);
            else if(f->selectable)ncplane_set_fg_rgb8(P,255,255,0);
            else                ncplane_set_fg_rgb8(P,200,200,200);
          }
        }

        /* 水平滚动: 字节偏移 → 对齐 UTF-8 字符边界 */
        { int dlen=(int)strlen(display);
          if(pd->scroll_x>dlen-mw/2&&dlen>mw)pd->scroll_x=dlen-mw/2;
          if(pd->scroll_x<0)pd->scroll_x=0; }
        const char *src = display;
        if(pd->scroll_x > 0 && (int)strlen(display) > pd->scroll_x){
            src += pd->scroll_x;
            /* 跳过 UTF-8 续字节 (0x80-0xBF), 确保从完整字符开始 */
            while (*src && ((unsigned char)*src & 0xC0) == 0x80) src++;
            ncplane_set_fg_rgb8(P,100,100,100);ncplane_set_bg_rgb8(P,0,0,0);
            ncplane_putstr_yx(P,sy,r->x+1,"\xe2\x97\x80");ix+=3;mw-=3;
        }
        size_t remain = strlen(src);
        if((int)remain > mw){
            int n = mw - 2; if(n < 0) n = 0;
            /* 回退到完整 UTF-8 字符边界, 避免截断多字节字符 */
            while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80) n--;
            memcpy(line, src, n);
            line[n++]=0xE2;line[n++]=0x96;line[n++]=0xB6;line[n]=0;
        }else{strncpy(line,src,sizeof(line)-1);line[sizeof(line)-1]=0;}
        ncplane_putstr_yx(P, sy, ix, line);
    }
    ncplane_set_bg_rgb8(P,0,0,0);
    if(pd->scroll>0)ncplane_putstr_yx(P,r->y,r->x+r->w-3,"\xE2\x96\xB2");
    if(end<pd->count&&r->h>=2)ncplane_putstr_yx(P,r->y+r->h-2,r->x+r->w-3,"\xE2\x96\xBC");
    /* 水平滚动指示器 */
    if(pd->scroll_x > 0 && r->w > 6)
        ncplane_putstr_yx(P, r->y + r->h - 2, r->x + 2, "\xe2\x97\x80 H-scroll");
}

/* ================================================================
 * 状态栏
 * ================================================================ */

static void render_status(TuiApp *app){
    unsigned tx;ncplane_dim_yx(P,NULL,&tx);
    ncplane_set_fg_rgb8(P,255,255,255);
    ncplane_set_bg_rgb8(P,0,0,140);
    char hints[]=" [PgUp/Dn]Nav [←→]Panel [M-N/M-P]HScroll [q]Quit";
    int hl=(int)strlen(hints),w=(int)tx;
    char ln[600];int sl=(int)strlen(app->status_text);
    int ms=w-hl-2;if(ms<8)ms=w-2;
    int p=0;
    if(sl>ms&&ms>3){memcpy(ln,app->status_text,ms-3);p=ms-3;ln[p++]='.';ln[p++]='.';ln[p++]='.';}
    else{memcpy(ln,app->status_text,sl);p=sl;}
    int pad=w-p-hl;if(pad<1)pad=1;if(pad>200)pad=200;
    memset(ln+p,' ',pad);p+=pad;
    memcpy(ln+p,hints,hl);p+=hl;ln[p]=0;
    ncplane_putstr_yx(P,0,0,ln);
}

/* ================================================================
 * 弹窗
 * ================================================================ */

void tui_show_popup(TuiApp *app, const char *title, const char *content){
    strncpy(app->popup_title, title, 63);
    app->popup_title[63] = '\0';
    strncpy(app->popup_content, content, 4095);
    app->popup_content[4095] = '\0';
    app->popup_active = 1;
    app->popup_dirty  = 1;
    app->need_render = 1;
}

static void render_popup(TuiApp *app){
    unsigned ty, tx;
    struct ncplane *std = notcurses_stdplane(app->nc);
    ncplane_dim_yx(std, &ty, &tx);
    if(ty<12||tx<40) return;

    /* 弹窗尺寸: 70%宽 × 60%高, 居中 */
    int pw = (int)tx * 70 / 100;
    int ph = (int)ty * 60 / 100;
    int px = ((int)tx - pw) / 2;
    int py = ((int)ty - ph) / 2;

    /* 半透明暗背景 */
    ncplane_set_fg_rgb8(std, 255, 255, 255);
    ncplane_set_bg_rgb8(std, 30, 30, 60);

    /* 填充弹窗背景 */
    char *sp = malloc(pw + 1);
    memset(sp, ' ', pw); sp[pw] = 0;
    for(int y = 0; y < ph; y++)
        ncplane_putstr_yx(std, py + y, px, sp);
    free(sp);

    /* 弹窗边框 */
    ncplane_set_fg_rgb8(std, 0, 220, 220);
    ncplane_set_bg_rgb8(std, 30, 30, 60);

    char *top = malloc(pw * 3 + 4);
    int tp = 0;
    top[tp++] = 0xE2; top[tp++] = 0x94; top[tp++] = 0x8C;
    for(int i = 1; i < pw - 1; i++){ top[tp++] = 0xE2; top[tp++] = 0x94; top[tp++] = 0x80; }
    top[tp++] = 0xE2; top[tp++] = 0x94; top[tp++] = 0x90; top[tp] = 0;
    ncplane_putstr_yx(std, py, px, top);

    char *bot = malloc(pw * 3 + 4);
    int bp = 0;
    bot[bp++] = 0xE2; bot[bp++] = 0x94; bot[bp++] = 0x94;
    for(int i = 1; i < pw - 1; i++){ bot[bp++] = 0xE2; bot[bp++] = 0x94; bot[bp++] = 0x80; }
    bot[bp++] = 0xE2; bot[bp++] = 0x94; bot[bp++] = 0x98; bot[bp] = 0;
    ncplane_putstr_yx(std, py + ph - 1, px, bot);

    char sd[] = {(char)0xE2, (char)0x94, (char)0x82, 0};
    for(int y = 1; y < ph - 1; y++){
        ncplane_putstr_yx(std, py + y, px, sd);
        ncplane_putstr_yx(std, py + y, px + pw - 1, sd);
    }
    free(top); free(bot);

    /* 弹窗标题 */
    ncplane_set_fg_rgb8(std, 255, 255, 0);
    ncplane_set_bg_rgb8(std, 30, 30, 60);
    ncplane_putstr_yx(std, py, px + 2, app->popup_title);

    /* 弹窗内容 */
    ncplane_set_fg_rgb8(std, 220, 220, 220);
    int max_lines = ph - 3;
    const char *s = app->popup_content;
    for(int i = 0; i < max_lines && *s; i++){
        char line[256];
        int len = 0;
        while(*s && *s != '\n' && len < pw - 4 && len < 250){
            line[len++] = *s++;
        }
        line[len] = 0;
        if(*s == '\n') s++;
        ncplane_putstr_yx(std, py + 1 + i, px + 2, line);
    }

    /* 关闭提示 */
    ncplane_set_fg_rgb8(std, 128, 128, 128);
    ncplane_putstr_yx(std, py + ph - 2, px + pw - 18, "[q/Esc] Close");
}

/* ================================================================
 * 数据库缓存路径
 * ================================================================ */

/* 数据库文件路径:
 *   优先: <ELF文件路径>.db (与 ELF 同目录)
 *   不可写时回退: ~/.cache/elf-tui/db/<djb2_hash>.db */
#include <sys/stat.h>
static void db_cache_path(const char *filename, char *out, size_t sz)
{
    char real[PATH_MAX];
    if (!realpath(filename, real))
        snprintf(real, sizeof(real), "%s", filename);

    /* 检测同目录是否可写 */
    char test[PATH_MAX + 8];
    snprintf(test, sizeof(test), "%s.db", real);
    FILE *fp = fopen(test, "a");
    if (fp) { fclose(fp); strncpy(out, test, sz); if (sz > 0) out[sz-1] = '\0'; return; }

    /* 回退: ~/.cache/elf-tui/db/<hash>.db */
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/.cache/elf-tui/db", home);
    mkdir(dir, 0755);
    /* 递归创建 ~/.cache/elf-tui/db/ */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s/.cache/elf-tui", home); mkdir(tmp,0755);
    mkdir(dir, 0755);

    unsigned long hash = 5381;
    for (const char *p = real; *p; p++)
        hash = ((hash << 5) + hash) + (unsigned char)*p;
    snprintf(out, sz, "%.*s/%lx.db", (int)(sizeof(dir)-1), dir, hash);
}

/* ================================================================
 * TUI 生命周期
 * ================================================================ */

TuiApp* tui_create(Elf64_Ctx *elf){
    TuiApp *app=calloc(1,sizeof(TuiApp));
    if(!app) return NULL;
    app->elf=elf;app->active_panel=PANEL_LEFT;app->running=1;app->need_render=1;

    /* 初始化异步分析基础设施 */
    cache_init();
    worker_pool_init(2);
    app->qdb = query_open(elf);  /* 数据总线: 符号索引 + 节索引 */

    /* 分析数据库: 持久化缓存, 首次导入后不再重复解析 */
    char db_path[PATH_MAX];
    db_cache_path(elf->filename, db_path, sizeof(db_path));
    int need_import = (access(db_path, F_OK) != 0);  /* 文件不存在 → 需要导入 */
    app->adb = db_open(db_path);
    if (app->adb) {
        sqlite3 *c = (sqlite3 *)db_conn(app->adb);
        sqlite3_stmt *st = NULL; int has_data = 0;
        if (sqlite3_prepare_v2(c, "SELECT COUNT(*) FROM sections", -1, &st, NULL) == 0
            && sqlite3_step(st) == SQLITE_ROW)
            has_data = sqlite3_column_int(st, 0) > 0;
        if (st) sqlite3_finalize(st);
        if (need_import || !has_data) {
            /* 后台线程异步导入, 不阻塞 TUI 启动 */
            app->db_importing = 1;
        } else {
            /* 已有DB但可能缺vuln数据 — 同步补扫 (毫秒级) */
            db_scan_vulns(app->adb);
        }
    }

    struct notcurses_options opts={
        .flags=NCOPTION_SUPPRESS_BANNERS,
    };
    app->nc=notcurses_init(&opts,NULL);
    if(!app->nc){worker_pool_shutdown();cache_destroy();free(app);return NULL;}

    P=notcurses_stdplane(app->nc);
    left_panel_init(&app->left_data,elf);
    middle_panel_init(&app->middle_data);
    right_panel_init(&app->right_data);

    Elf64_Ehdr *ehdr=(Elf64_Ehdr*)elf->map;
    tui_set_status(app,"%s | ELF64 | %s | entry=0x%lX",
                   elf->filename,elf_e_machine_str(ehdr->e_machine),(unsigned long)ehdr->e_entry);

    /* 首次导入时弹出 ELF 摘要窗口 (左右双栏) */
    if (app->db_importing) {
        char hdr[4096];
        int pos = 0;
        pos += snprintf(hdr + pos, sizeof(hdr) - (size_t)pos, "\n\n\n");

        /* ── 左栏: ELF Header 信息 ── */
        char left[16][80];
        int nl = 0;
        snprintf(left[nl++], sizeof(left[0]), "File:  %s", elf->filename);
        left[nl][0] = '\0'; nl++;
        snprintf(left[nl++], sizeof(left[0]), "  Magic:    %02X %02X %02X %02X",
                 ehdr->e_ident[0], ehdr->e_ident[1],
                 ehdr->e_ident[2], ehdr->e_ident[3]);
        snprintf(left[nl++], sizeof(left[0]), "  Class:    ELF%d (%s)",
                 ehdr->e_ident[EI_CLASS]==ELFCLASS64?64:32,
                 ehdr->e_ident[EI_CLASS]==ELFCLASS64?"64-bit":"32-bit");
        snprintf(left[nl++], sizeof(left[0]), "  Data:     %s",
                 ehdr->e_ident[EI_DATA]==ELFDATA2LSB?"Little-endian":"Big-endian");
        snprintf(left[nl++], sizeof(left[0]), "  OS/ABI:   %s",
                 elf_e_osabi_str(ehdr->e_ident[EI_OSABI]));
        snprintf(left[nl++], sizeof(left[0]), "  Type:     %s", elf_e_type_str(ehdr->e_type));
        snprintf(left[nl++], sizeof(left[0]), "  Machine:  %s",
                 elf_e_machine_str(ehdr->e_machine));
        snprintf(left[nl++], sizeof(left[0]), "  Entry:    0x%016lX",
                 (unsigned long)ehdr->e_entry);
        snprintf(left[nl++], sizeof(left[0]), "  PH offset: 0x%lX  (%lu bytes)",
                 (unsigned long)ehdr->e_phoff, (unsigned long)ehdr->e_phoff);
        snprintf(left[nl++], sizeof(left[0]), "  PH count:  %u  (entry %u B)",
                 ehdr->e_phnum, ehdr->e_phentsize);
        snprintf(left[nl++], sizeof(left[0]), "  SH offset: 0x%lX  (%lu bytes)",
                 (unsigned long)ehdr->e_shoff, (unsigned long)ehdr->e_shoff);
        snprintf(left[nl++], sizeof(left[0]), "  SH count:  %u  (entry %u B)",
                 ehdr->e_shnum, ehdr->e_shentsize);

        /* ── 右栏: 安全加固 + 语言检测 ── */
        char right[16][80];
        int nr = 0;
        right[nr][0] = '\0'; nr++;
        snprintf(right[nr++], sizeof(right[0]), "Security Checks");
        right[nr][0] = '\0'; nr++;

        /* NX */
        int nx = 1;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            Elf64_Phdr *ph = elf_get_phdr(elf, i);
            if (ph && ph->p_type == PT_GNU_STACK) {
                nx = !(ph->p_flags & PF_X); break;
            }
        }
        /* PIE */
        int pie = (ehdr->e_type == ET_DYN);
        /* RELRO */
        int relro = 0, full_relro = 0;
        for (int i = 0; i < ehdr->e_phnum; i++) {
            Elf64_Phdr *ph = elf_get_phdr(elf, i);
            if (ph && ph->p_type == PT_GNU_RELRO) { relro = 1; break; }
        }
        if (relro) {
            uint64_t val = 0;
            Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf->map + ehdr->e_phoff);
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdrs[i].p_type == PT_DYNAMIC && phdrs[i].p_filesz > 0) {
                    Elf64_Dyn *dyn = (Elf64_Dyn *)(elf->map + phdrs[i].p_offset);
                    int ndyn = (int)(phdrs[i].p_filesz / sizeof(Elf64_Dyn));
                    for (int j = 0; j < ndyn; j++) {
                        if (dyn[j].d_tag == DT_BIND_NOW) full_relro = 1;
                        if (dyn[j].d_tag == DT_FLAGS && (dyn[j].d_un.d_val & DF_BIND_NOW))
                            full_relro = 1;
                        if (dyn[j].d_tag == DT_FLAGS_1 && (dyn[j].d_un.d_val & DF_1_NOW))
                            full_relro = 1;
                    }
                    break;
                }
            }
        }
        /* Canary — scan dynsym for __stack_chk */
        int canary = 0;
        for (int i = 0; i < ehdr->e_shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(elf, i);
            if (!sh || sh->sh_type != SHT_DYNSYM) continue;
            Elf64_Shdr *strsh = elf_get_shdr(elf, sh->sh_link);
            if (!strsh) continue;
            Elf64_Sym *syms = (Elf64_Sym *)(elf->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym && !canary; j++) {
                const char *n = elf_strtab_get(elf, strsh->sh_offset, syms[j].st_name);
                if (n && strstr(n, "__stack_chk")) canary = 1;
            }
        }
        /* CET — scan for endbr64 */
        int cet = 0;
        const uint8_t ENDBR64[4] = {0xf3, 0x0f, 0x1e, 0xfa};
        for (int i = 0; i < ehdr->e_shnum && !cet; i++) {
            Elf64_Shdr *sh = elf_get_shdr(elf, i);
            if (!sh || !(sh->sh_flags & SHF_EXECINSTR) || sh->sh_size < 4) continue;
            const uint8_t *d = elf->map + sh->sh_offset;
            for (size_t off = 0; off + 4 <= sh->sh_size; off++)
                if (memcmp(d + off, ENDBR64, 4) == 0) { cet = 1; break; }
        }
        /* RPATH / RUNPATH */
        int rp = 0, rnp = 0;
        {
            Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf->map + ehdr->e_phoff);
            for (int i = 0; i < ehdr->e_phnum; i++) {
                if (phdrs[i].p_type == PT_DYNAMIC && phdrs[i].p_filesz > 0) {
                    Elf64_Dyn *dyn = (Elf64_Dyn *)(elf->map + phdrs[i].p_offset);
                    int ndyn = (int)(phdrs[i].p_filesz / sizeof(Elf64_Dyn));
                    for (int j = 0; j < ndyn; j++) {
                        if (dyn[j].d_tag == DT_RPATH) rp = 1;
                        if (dyn[j].d_tag == DT_RUNPATH) rnp = 1;
                    }
                    break;
                }
            }
        }
        /* Symbols stripped? */
        int stripped = 1;
        for (int i = 0; i < ehdr->e_shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(elf, i);
            if (sh && sh->sh_type == SHT_SYMTAB && sh->sh_size > 0) { stripped = 0; break; }
        }
        snprintf(right[nr++], sizeof(right[0]), "  PIE:      %s", pie?"Enabled":"Disabled");
        snprintf(right[nr++], sizeof(right[0]), "  RELRO:    %s",
                 full_relro?"Full":relro?"Partial":"None");
        snprintf(right[nr++], sizeof(right[0]), "  NX:       %s", nx?"Enabled":"EXECUTABLE (!)");
        snprintf(right[nr++], sizeof(right[0]), "  Canary:   %s", canary?"Found":"Missing");
        snprintf(right[nr++], sizeof(right[0]), "  CET:      %s", cet?"IBT present":"None");
        snprintf(right[nr++], sizeof(right[0]), "  RPATH:    %s", rp?"Set":"None");
        snprintf(right[nr++], sizeof(right[0]), "  RUNPATH:  %s", rnp?"Set":"None");
        snprintf(right[nr++], sizeof(right[0]), "  Symbols:  %s", stripped?"Stripped":"Not stripped");

        /* ── 合并左右栏 (各 50%, 竖线分隔) ── */
        int max = nl > nr ? nl : nr;
        for (int i = 0; i < max; i++) {
            const char *lt = i < nl ? left[i] : "";
            const char *rt = i < nr ? right[i] : "";
            pos += snprintf(hdr + pos, sizeof(hdr) - (size_t)pos,
                "%-48s │ %s\n", lt, rt);
        }
        pos += snprintf(hdr + pos, sizeof(hdr) - (size_t)pos,
            "\n── DB importing in background — press q/Esc to close ──\n");
        tui_show_popup(app, "ELF Analysis", hdr);
    }

    return app;
}

/* ── 后台导入线程 ───────────────────────────────────────────────── */
typedef struct { AnalysisDB *adb; Elf64_Ctx *ctx; volatile int *flag; } ImportJob;
static void *import_thread(void *arg) {
    ImportJob *j = (ImportJob *)arg;
    db_import_all(j->adb, j->ctx);
    db_build_indexes(j->adb);
    *(j->flag) = 0;
    free(j);
    return NULL;
}

void tui_destroy(TuiApp *app){
    if(!app)return;
    /* 取消正在执行的 Job */
    if(app->pending_job){worker_cancel(app->pending_job);job_free(app->pending_job);}
    /* 安全分离被调试进程 (必须在 notcurses_stop 之前, tracee 崩溃) */
    if(app->debug){
        debug_detach(app->debug);
        debug_free(app->debug);
        app->debug = NULL;
    }
    if(app->left_data.fields)fields_free(app->left_data.fields,app->left_data.count);
    if(app->middle_data.fields)fields_free(app->middle_data.fields,app->middle_data.count);
    if(app->right_data.fields)fields_free(app->right_data.fields,app->right_data.count);
    if(app->nc)notcurses_stop(app->nc);
    query_close(app->qdb);
    if (app->adb) db_close(app->adb);
    worker_pool_shutdown();
    cache_destroy();
    free(app);
}

/*
 * 提交异步分析 Job。
 * 如果有正在运行的 Job, 先取消它。
 * target_panel: PANEL_MIDDLE 或 PANEL_RIGHT
 */
int tui_submit_analysis(TuiApp *app, WorkerFn fn, int arg_int,
                        const char *status_msg, int target_panel)
{
    /* 取消前一个 Job */
    if(app->pending_job){
        worker_cancel(app->pending_job);
        job_free(app->pending_job);
        app->pending_job = NULL;
    }

    Job *job = NULL;
    int id = worker_submit(fn, app->elf, arg_int, NULL, &job);
    if(id < 0 || !job){
        tui_show_popup(app, "Error", "Failed to submit analysis job (queue full)");
        return -1;
    }

    app->pending_job  = job;
    app->job_running  = 1;
    app->job_panel    = target_panel;
    app->need_render  = 1;

    if(status_msg)
        tui_set_status(app, "%s", status_msg);
    return job->job_id;
}

void tui_render_all(TuiApp *app){
    /* ── 后台导入状态管理 (始终检查, 与渲染解耦) ── */
    static int import_launched = 0;
    if (app->db_importing && !import_launched) {
        import_launched = 1;
        ImportJob *j = malloc(sizeof(ImportJob));
        j->adb = app->adb; j->ctx = app->elf; j->flag = &app->db_importing;
        pthread_t tid;
        pthread_create(&tid, NULL, import_thread, j);
        pthread_detach(tid);
        tui_set_status(app, "Importing ELF data to DB...");
    }
    if (app->db_importing == 0 && import_launched) {
        import_launched = 0;
        tui_set_status(app, "%s | ELF64 | Ready", app->elf->filename);
        app->need_render = 1;  /* 状态栏变化需要重绘 */
    }

    /* 只在需要时渲染, 避免空转刷屏吃 CPU.
     * 弹窗激活但 need_render=0 时也不渲染 — 弹窗由事件循环独立维护. */
    if(!app->need_render) return;

    /* ── 异步 Job 完成检测 ── */
    if(app->pending_job && app->job_running){
        int st = worker_poll(app->pending_job);
        if(st == JOB_DONE){
            PanelData *target = (app->job_panel == PANEL_RIGHT)
                                ? &app->right_data : &app->middle_data;
            if(target->fields) fields_free(target->fields, target->count);
            *target = *app->pending_job->result;
            app->pending_job->result->fields = NULL;
            job_free(app->pending_job);
            app->pending_job = NULL;
            app->job_running = 0;
            app->need_render = 1;
        }else if(st == JOB_ERROR){
            tui_show_popup(app, "Analysis Error",
                           app->pending_job->error[0] ?
                           app->pending_job->error : "Unknown error");
            job_free(app->pending_job);
            app->pending_job = NULL;
            app->job_running = 0;
        }
    }

    P=notcurses_stdplane(app->nc);
    layout_recalc();

    /* 调试模式: 只有当中间面板正在显示寄存器时才自动刷新,
     * 其他视图 (Memory Map / AnalysisDB / Stack View 等) 保留不变 */
    int mid_is_regs = 0;
    if(app->middle_data.count > 0 && app->middle_data.fields &&
       app->middle_data.fields[0].text){
        const char *h = app->middle_data.fields[0].text;
        if(strstr(h, "x86-64 Registers") || strstr(h, "Regs"))
            mid_is_regs = 1;
    }
    if(app->debug && app->debug->attached &&
       (mid_is_regs || app->middle_data.count == 0)){
        /* 寄存器: 保存光标, 刷新数据, 恢复光标 */
        int saved_mid_cur = app->middle_data.cursor;
        int saved_mid_scroll = app->middle_data.scroll;
        if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
            app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;}
        render_reg_single_col(app->debug, &app->middle_data);
        /* Phase 4: 寄存器值标注符号名 */
        if(app->qdb){
            char *regs_to_annotate[] = {"RIP","RDI","RSI","RDX","RAX","RSP","RBP",NULL};
            for(int ri=0;ri<app->middle_data.count;ri++){
                char rn[8]; uint64_t rv=0;
                if(sscanf(app->middle_data.fields[ri].text,"%4s 0x%lx",rn,&rv)==2||
                   sscanf(app->middle_data.fields[ri].text,"%3s 0x%lx",rn,&rv)==2){
                    for(char **ra=regs_to_annotate;*ra;ra++){
                        if(!strcmp(rn,*ra)&&rv>0x1000){
                            char sn[64]="";int64_t off=0;
                            if(query_symbol(app->qdb,rv,sn,sizeof(sn),&off)==0&&sn[0]){
                                char annot[96];
                                if(off)snprintf(annot,sizeof(annot),"%-4s 0x%lx  <%s+0x%lx>",rn,rv,sn,(long)off);
                                else snprintf(annot,sizeof(annot),"%-4s 0x%lx  <%s>",rn,rv,sn);
                                free(app->middle_data.fields[ri].text);
                                app->middle_data.fields[ri].text=strdup(annot);
                            }
                            break;
                        }
                    }
                }
            }
        }
        /* ── 内存区域标注: 每个寄存器值所属的内存区间 ──────────── */
        {
            vmmap_entry_t entries[256];
            int nents = 256;
            if (vmmap_read(app->debug, entries, &nents) == 0 && nents > 0) {
                fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
                fields_add(&app->middle_data,
                    "── Memory Regions (Enter=hexdump) ──", 0, 0, DETAIL_NONE, -1);

                /* 关键寄存器: 值 → 所在内存区域 */
                struct user_regs_struct *r = &app->debug->regs;
                uint64_t reg_vals[] = {r->rip, r->rsp, r->rbp, r->rax,
                    r->rdi, r->rsi, r->rdx, r->rcx, r->r8, r->r9};
                const char *reg_names[] = {"RIP","RSP","RBP","RAX",
                    "RDI","RSI","RDX","RCX","R8","R9"};
                int nregs = 10;

                char rbuf[384];
                for (int ri = 0; ri < nregs; ri++) {
                    uint64_t rv = reg_vals[ri];
                    if (rv < 0x1000) continue;  /* 非地址, 跳过 */

                    /* 查找包含 rv 的内存段 */
                    int found = 0;
                    for (int ei = 0; ei < nents; ei++) {
                        if (rv >= entries[ei].start && rv < entries[ei].end) {
                            const char *seg = "anon";
                            if (entries[ei].path[0]) {
                                char *slash = strrchr(entries[ei].path, '/');
                                seg = slash ? slash + 1 : entries[ei].path;
                            } else {
                                if (entries[ei].perms[1]=='w' &&
                                    entries[ei].start>0x600000000000ULL) seg="[stack]";
                                else if (entries[ei].perms[1]=='w') seg="[heap]";
                                else if (entries[ei].perms[2]=='x') seg="[code]";
                                else if (entries[ei].perms[1]=='-') seg="[ro]";
                            }
                            const char *tag = "";
                            if (strstr(entries[ei].path, "[stack]")) tag=" [STACK]";
                            else if (strstr(entries[ei].path, "[heap]")) tag=" [HEAP]";
                            else if (strstr(entries[ei].path, "libc")) tag=" [LIBC]";
                            else if (strstr(entries[ei].path, "ld-")) tag=" [LD]";
                            snprintf(rbuf, sizeof(rbuf),
                                "  %-4s=0x%lx -> %s%s 0x%lx-0x%lx",
                                reg_names[ri], rv, seg, tag,
                                (unsigned long)entries[ei].start,
                                (unsigned long)entries[ei].end);
                            fields_add(&app->middle_data, rbuf, 1, 1,
                                DETAIL_NONE, (int)(rv & 0xFFFF));
                            found = 1;
                            break;
                        }
                    }
                    if (!found && rv > 0x1000) {
                        snprintf(rbuf, sizeof(rbuf),
                            "  %-4s -> (unmapped)", reg_names[ri]);
                        fields_add(&app->middle_data, rbuf, 1, 0, DETAIL_NONE, -1);
                    }
                }
            }
        }

        app->middle_data.cursor = saved_mid_cur;
        app->middle_data.scroll = saved_mid_scroll;
        if(app->middle_data.cursor >= app->middle_data.count) app->middle_data.cursor = app->middle_data.count-1;
        if(app->middle_data.cursor < 0) app->middle_data.cursor = 0;

        /* 反汇编: 仅在 RIP 变化时刷新, 避免假死 */
        int rip_changed = (app->debug->regs.rip != app->last_rip);
        if(rip_changed||app->right_data.count==0){
            if(app->right_data.fields){fields_free(app->right_data.fields,app->right_data.count);
                app->right_data.fields=NULL;app->right_data.count=0;app->right_data.capacity=0;
                app->right_data.cursor=0;app->right_data.scroll=0;app->right_data.scroll_x=0;}
            fields_add(&app->right_data,"=== Disassembly @ RIP ===",0,0,DETAIL_NONE,-1);
            char dbuf[128];
            snprintf(dbuf,sizeof(dbuf),"RIP: 0x%llx",(unsigned long long)app->debug->regs.rip);
            fields_add(&app->right_data,dbuf,1,0,DETAIL_NONE,-1);
            uint8_t code[64];
            int nr = debug_readmem(app->debug, app->debug->regs.rip, code, sizeof(code));
            if(nr > 0){
                disasm_ctx *dd = disasm_open();
                if(dd){
                    const uint8_t *cp = code; size_t cs = (size_t)nr;
                    uint64_t ca = app->debug->regs.rip; int lines = 0;
                    char lbuf[256];
                    while(cs > 0 && lines < 30 && disasm_next(dd, &cp, &cs, &ca)){
                        cs_insn *in = disasm_insn(dd);
                        char hx[48]=""; int hp=0;
                        for(size_t b=0;b<in->size&&hp<40;b++) hp+=snprintf(hx+hp,sizeof(hx)-(size_t)hp,"%02x ",in->bytes[b]);
                        /* 符号标注 */
                        char sym[64]=""; int64_t off=0;
                        if(app->qdb) query_symbol(app->qdb, in->address, sym, sizeof(sym), &off);
                        char symtag[96]="";
                        if(sym[0]){if(off)snprintf(symtag,sizeof(symtag),"  <%s+0x%lx>",sym,(long)off);
                                   else snprintf(symtag,sizeof(symtag),"  <%s>",sym);}
                        /* 寄存器值叠加: 检测 op_str 中的寄存器名 → 附加值 */
                        struct user_regs_struct *rr = &app->debug->regs;
                        char reg_overlay[128] = "";
                        static const char *reg_names[] = {
                            "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                            "r8","r9","r10","r11","r12","r13","r14","r15",
                            "eax","ebx","ecx","edx","esi","edi","ebp","esp",
                            "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",NULL};
                        uint64_t reg_vals[] = {
                            rr->rax,rr->rbx,rr->rcx,rr->rdx,rr->rsi,rr->rdi,rr->rbp,rr->rsp,
                            rr->r8,rr->r9,rr->r10,rr->r11,rr->r12,rr->r13,rr->r14,rr->r15,
                            rr->rax&0xFFFFFFFF,rr->rbx&0xFFFFFFFF,rr->rcx&0xFFFFFFFF,rr->rdx&0xFFFFFFFF,
                            rr->rsi&0xFFFFFFFF,rr->rdi&0xFFFFFFFF,rr->rbp&0xFFFFFFFF,rr->rsp&0xFFFFFFFF,
                            rr->r8&0xFFFFFFFF,rr->r9&0xFFFFFFFF,rr->r10&0xFFFFFFFF,
                            rr->r11&0xFFFFFFFF,rr->r12&0xFFFFFFFF,rr->r13&0xFFFFFFFF,
                            rr->r14&0xFFFFFFFF,rr->r15&0xFFFFFFFF};
                        char *ops = in->op_str;
                        for (int ri = 0; reg_names[ri] && strlen(reg_overlay) < 100; ri++) {
                            if (strstr(ops, reg_names[ri])) {
                                char tmp[32];
                                snprintf(tmp,sizeof(tmp)," %s=0x%lx",
                                    reg_names[ri],(unsigned long)reg_vals[ri]);
                                if (strlen(reg_overlay)+strlen(tmp) < 120)
                                    strcat(reg_overlay,tmp);
                            }
                        }
                        snprintf(lbuf,sizeof(lbuf),"%s0x%lx: %-24s %-8s %s%s%s",
                                 (ca-in->size==app->debug->regs.rip)?"▶":" ",
                                 (unsigned long)in->address,hx,in->mnemonic,in->op_str,
                                 symtag,reg_overlay);
                        fields_add(&app->right_data,lbuf,1,1,DETAIL_NONE,(int)(in->address&0xFFFF));
                        lines++;
                    }
                    disasm_close(dd);
                }else fields_add(&app->right_data,"(Capstone init failed)",1,0,DETAIL_NONE,-1);
            }else fields_add(&app->right_data,"(cannot read memory at RIP)",1,0,DETAIL_NONE,-1);
            app->last_rip = app->debug->regs.rip;
        }
        ncplane_erase(P);
        render_status(app);
        region_clear(&R_left);
        region_border(&R_left,"Navigation",app->active_panel==PANEL_LEFT);
        region_lines(&R_left,&app->left_data,app->active_panel==PANEL_LEFT);
        region_clear(&R_mid);
        region_border(&R_mid,"Registers",app->active_panel==PANEL_MIDDLE);
        region_lines(&R_mid,&app->middle_data,app->active_panel==PANEL_MIDDLE);
        region_clear(&R_right);
        region_border(&R_right,"Disassembly",app->active_panel==PANEL_RIGHT);
        region_lines(&R_right,&app->right_data,app->active_panel==PANEL_RIGHT);
        /* 右面板深度面包屑: 滚动后覆盖渲染确保始终可见 */
        if (app->right_data.count>0 && app->right_data.fields
            && app->right_data.fields[0].text
            && strstr(app->right_data.fields[0].text,"Jump Depth")
            && app->right_data.scroll>0) {
            ncplane_set_bg_rgb8(P,0,0,80);
            ncplane_set_fg_rgb8(P,0,255,255);
            ncplane_putstr_yx(P, R_right.y+1, R_right.x+1,
                app->right_data.fields[0].text);
        }
    }else{
        ncplane_erase(P);
        render_status(app);
        region_clear(&R_left);
        region_border(&R_left,"Navigation",app->active_panel==PANEL_LEFT);
        region_lines(&R_left,&app->left_data,app->active_panel==PANEL_LEFT);
        region_clear(&R_mid);
        region_border(&R_mid,"Detail",app->active_panel==PANEL_MIDDLE);
        region_lines(&R_mid,&app->middle_data,app->active_panel==PANEL_MIDDLE);
        region_clear(&R_right);
        region_border(&R_right,"Explanation",app->active_panel==PANEL_RIGHT);
        region_lines(&R_right,&app->right_data,app->active_panel==PANEL_RIGHT);
        /* 右面板深度面包屑: 滚动后覆盖渲染确保始终可见 */
        if (app->right_data.count>0 && app->right_data.fields
            && app->right_data.fields[0].text
            && strstr(app->right_data.fields[0].text,"Jump Depth")
            && app->right_data.scroll>0) {
            ncplane_set_bg_rgb8(P,0,0,80);
            ncplane_set_fg_rgb8(P,0,255,255);
            ncplane_putstr_yx(P, R_right.y+1, R_right.x+1,
                app->right_data.fields[0].text);
        }
    }

    notcurses_render(app->nc);
    P=NULL;
}

void tui_run(TuiApp *app){
    TuiApp *a=app;
    struct ncinput ni;
    int quit_confirm = 0;   /* 退出确认弹窗是否激活 */

    /* 初始渲染 */
    a->need_render = 1;
    tui_render_all(a);
    a->need_render = 0;
    if(a->popup_active){
        render_popup(a);
        a->popup_dirty = 0;
        notcurses_render(a->nc);
    }

    /* 事件循环: 每轮调用 tui_render_all 检查导入状态并按需渲染.
     * 弹窗激活时: 若背景刚被渲染则必须重绘弹窗 (背景渲染会擦除弹窗). */
    while(a->running){
        int need_render_before = a->need_render;
        tui_render_all(a);
        int bg_rendered = (need_render_before || a->need_render);
        a->need_render = 0;

        if(a->popup_active && (a->popup_dirty || bg_rendered)){
            render_popup(a);
            a->popup_dirty = 0;
            notcurses_render(a->nc);
        }

        /* ── 获取输入 ── */
        memset(&ni,0,sizeof(ni));
        uint32_t code = notcurses_get(a->nc, NULL, &ni);

        if(code == (uint32_t)-1 || code == 0 || code == NCKEY_RESIZE){
            /* 无输入 → select() 做速率限制, 然后重试 */
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);
            struct timeval tv = {0, 20000};  /* 20ms */
            select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        }else{
            /* ── 有按键 → 分发处理 ── */

            /* 调试热键 F5-F10: 弹窗和非弹窗模式下都可用 (仅在 attach 后) */
            if(a->debug && a->debug->attached &&
               !quit_confirm &&
               !a->pid_input_active && !a->search_input_active){
                if(code == NCKEY_F05){
                    debug_continue(a->debug);
                    if(a->adb) db_insert_reg_snapshot(a->adb,a->debug,db_snapshot_count(a->adb));
                    a->need_render = 1; continue;
                }
                if(code == NCKEY_F07){
                    debug_step(a->debug);
                    if(a->adb) db_insert_reg_snapshot(a->adb,a->debug,db_snapshot_count(a->adb));
                    a->need_render = 1; continue;
                }
                if(code == NCKEY_F08){
                    debug_step_over(a->debug);
                    if(a->adb) db_insert_reg_snapshot(a->adb,a->debug,db_snapshot_count(a->adb));
                    a->need_render = 1; continue;
                }
                if(code == NCKEY_F09){
                    debug_set_breakpoint(a->debug, a->debug->regs.rip);
                    a->need_render = 1; continue;
                }
                if(code == NCKEY_F10){
                    debug_detach(a->debug); debug_free(a->debug); a->debug = NULL;
                    if(a->middle_data.fields){fields_free(a->middle_data.fields,a->middle_data.count);
                        a->middle_data.fields=NULL;a->middle_data.count=0;a->middle_data.capacity=0;
                        a->middle_data.cursor=0;a->middle_data.scroll=0;}
                    if(a->right_data.fields){fields_free(a->right_data.fields,a->right_data.count);
                        a->right_data.fields=NULL;a->right_data.count=0;a->right_data.capacity=0;
                        a->right_data.cursor=0;a->right_data.scroll=0;a->right_data.scroll_x=0;}
                    a->popup_active = 0; a->active_panel = PANEL_LEFT;
                    a->need_render = 1; continue;
                }
            }

            if(a->popup_active){
                /* 退出确认弹窗: 仅接受 y(确认) / n(取消) */
                if(quit_confirm){
                    if(code == 'y' || code == 'Y'){
                        a->running = 0; continue;
                    }
                    if(code == 'n' || code == 'N' || code == NCKEY_ESC){
                        a->popup_active = 0;
                        quit_confirm = 0;
                        a->need_render = 1; continue;
                    }
                    continue;  /* 忽略其他所有按键 */
                }
                /* 弹窗模式: 限制按键处理 (只有输入模式 + 关闭弹窗) */
                if(a->pid_input_active || a->search_input_active){
                    tui_handle_input(a, &ni);
                }else if(code == 'q' || code == 'Q' || code == NCKEY_ESC){
                    /* 弹窗关闭: q / Esc 仅关弹窗, 不退出程序 */
                    a->popup_active = 0;
                    a->need_render = 1;
                }
                /* 弹窗模式: 忽略其他所有按键 */
            }else{
                /* ── 正常模式 ── */
                if(code == 'q' || code == 'Q'){
                    /* 退出确认弹窗 */
                    quit_confirm = 1;
                    tui_show_popup(a, "Quit",
                        "Are you sure you want to quit elf-tui?\n\n"
                        "  [y]  Yes, quit\n"
                        "  [n]  No, cancel");
                    a->need_render = 1;
                }else if(code == ' ' && !a->search_input_active && !a->pid_input_active){
                    /* Space: 全局搜索 */
                    a->search_input_active = 1; a->search_input_pos = 0;
                    memset(a->search_input_buf, 0, sizeof(a->search_input_buf));
                    tui_show_popup(a, "Global Search (DB)",
                        "Query templates:\n"
                        "  callers:NAME    — who calls this function\n"
                        "  callees:ADDR    — what does this function call\n"
                        "  largest         — largest functions by size\n"
                        "  most called     — most frequently called functions\n"
                        "  dangerous       — list all dangerous API calls\n"
                        "  src->sink       — functions containing both calls\n"
                        "  hex/addr/text   — standard keyword search\n"
                        "\n  _\n\n"
                        "[Enter]Search  [Esc]Cancel");
                    a->need_render = 1;
                }else{
                    /* 所有其他按键 → 统一输入处理 */
                    tui_handle_input(a, &ni);
                }
            }
        }
    }
}
