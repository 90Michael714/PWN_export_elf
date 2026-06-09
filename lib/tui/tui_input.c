/*
 * tui_input.c — 键盘输入处理
 *
 * 按键映射:
 *   PageUp/Down 或 ↑/↓ — 上下导航
 *   ←/→                  — 切换活动面板
 *   Enter                — 展开选中项到下一面板
 *   h 或 Backspace       — 返回上一面板
 *   q                    — 退出
 *   g/G                  — 跳到列表顶/底
 */

#include "tui.h"
#include "tui_buttons.h"
#include "core/reg_view.h"
#include "core/debug_worker.h"
#include "core/mem_search.h"
#include "disasm.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static int clamp_cursor(int cur, int max, int delta){
    if(max<=0)return 0;
    int n=cur+delta;
    if(n<0)return max-1;    /* 上越界 → 循环到底部 */
    if(n>=max)return 0;     /* 下越界 → 循环到顶部 */
    return n;
}

static PanelData* active_pd(TuiApp *app){
    switch(app->active_panel){
        case PANEL_LEFT:   return &app->left_data;
        case PANEL_MIDDLE: return &app->middle_data;
        case PANEL_RIGHT:  return &app->right_data;
        default:           return NULL;
    }
}

/* 匹配 NCKEY 或 ASCII 原始码 */
static int is_key(uint32_t code, uint32_t nckey, char ascii){
    if(code==nckey) return 1;
    if(ascii && code==(uint32_t)(unsigned char)ascii) return 1;
    return 0;
}

/* ── PID input mode state machine (for live register reading) ── */

static void pid_input_update_popup(TuiApp *app)
{
    char msg[256];
    snprintf(msg, sizeof(msg),
        "Enter target PID and press Enter:\n\n"
        "  PID: %s_\n\n"
        "  [Enter to confirm]  [Esc to cancel]",
        app->pid_input_buf);
    tui_show_popup(app, "Live Register Reader", msg);
    app->need_render = 0;  /* 仅弹窗文字变化, 不需重绘背景面板 */
}

static void pid_input_cancel(TuiApp *app)
{
    app->pid_input_active = 0;
    app->pid_input_pos = 0;
    memset(app->pid_input_buf, 0, sizeof(app->pid_input_buf));
    app->popup_active = 0;
    app->need_render = 1;
}

static void pid_input_confirm(TuiApp *app)
{
    app->pid_input_active = 0;
    int pid = atoi(app->pid_input_buf);
    app->pid_input_pos = 0;
    memset(app->pid_input_buf, 0, sizeof(app->pid_input_buf));
    if(pid <= 0){tui_show_popup(app,"Error","Invalid PID.");app->need_render=1;return;}

    /* 所有 PID 入口统一: ATTACH → 设 app->debug → 进入调试模式 */
    if(app->debug){ debug_detach(app->debug); debug_free(app->debug); app->debug=NULL; }
    DebugState *ds = NULL;
    if(debug_attach((pid_t)pid, &ds) != 0){
        tui_show_popup(app,"Attach Failed",debug_error());app->need_render=1;return;
    }
    app->debug = ds;
    /* step 0 快照: 记录初始 attach 时的寄存器状态 */
    if (app->adb) db_insert_reg_snapshot(app->adb, ds, 0);
    app->popup_active = 0;  /* 关闭弹窗, 进入调试视图 */
    if(app->middle_data.fields){fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;}
    if(app->right_data.fields){fields_free(app->right_data.fields,app->right_data.count);
        app->right_data.fields=NULL;app->right_data.count=0;app->right_data.capacity=0;
        app->right_data.cursor=0;app->right_data.scroll=0;app->right_data.scroll_x=0;}
    char buf[128];
    snprintf(buf,sizeof(buf),"PID:%d RIP:0x%llx", ds->pid, (unsigned long long)ds->regs.rip);
    tui_set_status(app, buf);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
}

/* ── Main input handler ──────────────────────────────────────── */

int tui_handle_input(TuiApp *app, const struct ncinput *ni){
    uint32_t c=ni->id;
    PanelData *pd=active_pd(app);

    /* ——— PID input mode: intercept all keys ——— */
    if (app->pid_input_active) {
        if (c == NCKEY_ESC) {
            pid_input_cancel(app);
            return 1;
        }
        if (is_key(c, NCKEY_ENTER, '\r') || is_key(c, NCKEY_ENTER, '\n')) {
            pid_input_confirm(app);
            return 1;
        }
        if (c == NCKEY_BACKSPACE || c == (uint32_t)'\b') {
            if (app->pid_input_pos > 0)
                app->pid_input_buf[--app->pid_input_pos] = '\0';
            pid_input_update_popup(app);
            return 1;
        }
        if (c >= '0' && c <= '9' && app->pid_input_pos < 10) {
            app->pid_input_buf[app->pid_input_pos++] = (char)c;
            app->pid_input_buf[app->pid_input_pos] = '\0';
            pid_input_update_popup(app);
            return 1;
        }
        return 1;  /* consume all other keys in PID mode */
    }

    /* ——— Search input mode: 输入搜索查询 ——— */
    if (app->search_input_active) {
        if (c == NCKEY_ESC) {
            app->search_input_active = 0;
            app->search_input_pos = 0;
            memset(app->search_input_buf, 0, sizeof(app->search_input_buf));
            app->popup_active = 0;
            app->need_render = 1;
            return 1;
        }
        if (is_key(c, NCKEY_ENTER, '\r') || is_key(c, NCKEY_ENTER, '\n')) {
            app->search_input_active = 0;
            app->popup_active = 0;
            /* 清空中面板, 放入搜索结果 */
            if(app->middle_data.fields){
                fields_free(app->middle_data.fields, app->middle_data.count);
                app->middle_data.fields=NULL;app->middle_data.count=0;
                app->middle_data.capacity=0;app->middle_data.cursor=0;app->middle_data.scroll=0;
            }
            const char *q = app->search_input_buf;
            int searched = 0;
            int db_count = 0;   /* DB 搜索结果数, 用于内存搜索序号续接 */

            /* 1. 数据库全局搜索 (静态分析数据: insn/sym/str/vuln/...) */
            if (q[0] && app->adb && !app->db_importing) {
                db_count = db_search(app->adb, q, &app->middle_data);
                searched = 1;
            } else if (q[0] && app->db_importing) {
                fields_add(&app->middle_data,"DB importing — retry in a moment",0,0,DETAIL_NONE,-1);
                searched = 1;
            }

            /* 2. 调试模式: 同时搜索 tracee 进程内存 (独立于DB, 互为补充) */
            if (q[0] && app->debug && app->debug->attached) {
                if (searched) {
                    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
                    fields_add(&app->middle_data,
                        "── Live Memory Search (tracee) ──", 1, 0, DETAIL_NONE, -1);
                }
                MemSearchConfig mcfg;
                if(mem_search_init(&mcfg, q)==0){
                    MemSearchResult mres;
                    if(mem_search_run(app->debug, &mcfg, &mres)==0){
                        /* 把每条 hit 格式化为独立行（替代弹窗格式） */
                        char buf[256];
                        snprintf(buf, sizeof(buf),
                            "%d hit(s) in %d segments (%.1f ms)",
                            mres.hit_count, mres.segments_scanned,
                            mres.elapsed_ms);
                        fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
                        int show = mres.hit_count;
                        if (show > 100) show = 100;
                        for (int i = 0; i < show; i++) {
                            const MemSearchHit *h = &mres.hits[i];
                            snprintf(buf, sizeof(buf),
                                "[%d] 0x%lx  mem  %-6s  %s",
                                db_count + i + 1,
                                (unsigned long)h->addr,
                                h->region_perms,
                                h->region_desc);
                            fields_add(&app->middle_data, buf, 1, 1, DETAIL_NONE,
                                (int)(h->addr & 0xFFFF));
                        }
                        if (mres.hit_count > show) {
                            snprintf(buf, sizeof(buf),
                                "... (%d more hits — narrow search)", mres.hit_count - show);
                            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
                        }
                        searched = 1;
                    } else {
                        fields_add(&app->middle_data,
                            "(memory search: no readable segments or read failed)",
                            1, 0, DETAIL_NONE, -1);
                    }
                } else {
                    fields_add(&app->middle_data,
                        "(memory search: pattern parse failed — use hex bytes, 0xADDR, or \"ASCII\")",
                        1, 0, DETAIL_NONE, -1);
                }
            }

            if (!searched)
                fields_add(&app->middle_data,"(DB not ready — wait for import)",0,0,DETAIL_NONE,-1);
            if(app->middle_data.count>0) app->active_panel=PANEL_MIDDLE;
            app->search_input_pos = 0;
            memset(app->search_input_buf, 0, sizeof(app->search_input_buf));
            app->need_render = 1;
            return 1;
        }
        if (c == NCKEY_BACKSPACE || c == (uint32_t)'\b') {
            if (app->search_input_pos > 0)
                app->search_input_buf[--app->search_input_pos] = '\0';
            char msg[700];
            snprintf(msg,sizeof(msg),
                "Query templates: callers:NAME callees:ADDR largest "
                "most_called dangerous src->sink  —  or type keyword/addr\n"
                "\n  %s_\n\n"
                "[Enter]Search  [Esc]Cancel",app->search_input_buf);
            tui_show_popup(app,"Search",msg);
            app->need_render = 0;
            return 1;
        }
        if (c >= 32 && c < 127 && app->search_input_pos < 60) {
            app->search_input_buf[app->search_input_pos++] = (char)c;
            app->search_input_buf[app->search_input_pos] = '\0';
            char msg[700];
            snprintf(msg,sizeof(msg),
                "Query templates: callers:NAME callees:ADDR largest "
                "most_called dangerous src->sink  —  or type keyword/addr\n"
                "\n  %s_\n\n"
                "[Enter]Search  [Esc]Cancel",app->search_input_buf);
            tui_show_popup(app,"Search",msg);
            app->need_render = 0;
            return 1;
        }
        return 1;
    }

    /* ——— 退出 (仅 q) ——— */
    if(c=='q'||c=='Q'){app->running=0;return 1;}

    /* ——— → : 切换到下一面板 ——— */
    if(is_key(c,NCKEY_RIGHT,0)){
        app->active_panel=(ActivePanel)((app->active_panel+1)%PANEL_COUNT);
        app->need_render=1;return 1;
    }

    /* ——— ← : 切换到上一面板 ——— */
    if(is_key(c,NCKEY_LEFT,0)){
        app->active_panel=(ActivePanel)((app->active_panel+PANEL_COUNT-1)%PANEL_COUNT);
        app->need_render=1;return 1;
    }

    /* ——— PageUp 或 ↑: 上移 ——— */
    if(is_key(c,NCKEY_PGUP,0)||is_key(c,NCKEY_UP,0)){
        if(pd&&pd->count>0){pd->cursor=clamp_cursor(pd->cursor,pd->count,-1);app->need_render=1;}
        return 1;
    }

    /* ——— PageDown 或 ↓: 下移 ——— */
    if(is_key(c,NCKEY_PGDOWN,0)||is_key(c,NCKEY_DOWN,0)){
        if(pd&&pd->count>0){pd->cursor=clamp_cursor(pd->cursor,pd->count,1);app->need_render=1;}
        return 1;
    }

    /* ——— Heap 视图切换键 (o/c/l/d/v) ——— */
    if(app->active_panel==PANEL_MIDDLE&&pd&&pd->count>0&&
       pd->fields[0].text&&strstr(pd->fields[0].text,"Heap Graph")){
        if(c=='o'||c=='c'||c=='l'||c=='d'||c=='v'||
           c=='O'||c=='C'||c=='L'||c=='D'||c=='V'){
            btn_heap_handle_key(app,(int)c);return 1;
        }
    }

    /* ——— SymResolve: 交互模式 ——— */
    if(app->active_panel==PANEL_MIDDLE&&pd&&pd->count>0&&
       pd->fields[0].text&&strstr(pd->fields[0].text,"Runtime Symbol Resolution")){
        if(c=='s'||c=='/'||c=='l'||c=='e'||c=='a'||
           c=='S'||c=='L'||c=='E'||c=='A'){
            btn_symresolve_handle_key(app,(int)c);return 1;
        }
    }

    /* ——— d: IR 数据流 (谁读写了这个寄存器的值) ——— */
    if(c=='d'&&app->active_panel==PANEL_MIDDLE&&pd&&pd->cursor>=0&&pd->cursor<pd->count){
        const char *lt=pd->fields[pd->cursor].text;
        if(lt&&app->adb&&!app->db_importing){
            uint64_t addr=0;const char *p=strstr(lt,"0x");
            if(p){addr=strtoull(p,NULL,16);
                if(addr>0x1000){
                    if(app->right_data.fields){
                        fields_free(app->right_data.fields,app->right_data.count);
                        app->right_data.fields=NULL;app->right_data.count=0;
                        app->right_data.capacity=0;app->right_data.cursor=0;
                        app->right_data.scroll=0;app->right_data.scroll_x=0;
                    }
                    db_dataflow_query(app->adb,addr,&app->right_data);
                    if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                    app->need_render=1;return 1;
                }
            }
        }
    }

    /* ——— V: CFG 图 (当前地址所在函数) ——— */
    if(c=='V'&&app->active_panel==PANEL_MIDDLE&&pd&&pd->cursor>=0&&pd->cursor<pd->count){
        const char *lt=pd->fields[pd->cursor].text;
        if(lt&&app->adb&&!app->db_importing){
            uint64_t addr=0;const char *p=strstr(lt,"0x");
            if(p){addr=strtoull(p,NULL,16);
                if(addr>0x1000){
                    if(app->right_data.fields){
                        fields_free(app->right_data.fields,app->right_data.count);
                        app->right_data.fields=NULL;app->right_data.count=0;
                        app->right_data.capacity=0;app->right_data.cursor=0;
                        app->right_data.scroll=0;app->right_data.scroll_x=0;
                    }
                    db_render_cfg_graph(app->adb,addr,&app->right_data);
                    if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                    app->need_render=1;return 1;
                }
            }
        }
    }

    /* ——— f: 数据流追踪 (call 指令) ——— */
    if(c=='f'&&app->active_panel==PANEL_MIDDLE&&pd&&pd->cursor>=0&&pd->cursor<pd->count){
        const char *lt=pd->fields[pd->cursor].text;
        if(lt&&app->adb&&!app->db_importing){
            uint64_t addr=0;const char *p=strstr(lt,"0x");
            if(p){addr=strtoull(p,NULL,16);
                if(addr>0x1000){
                    if(app->right_data.fields){
                        fields_free(app->right_data.fields,app->right_data.count);
                        app->right_data.fields=NULL;app->right_data.count=0;
                        app->right_data.capacity=0;app->right_data.cursor=0;
                        app->right_data.scroll=0;app->right_data.scroll_x=0;
                    }
                    db_trace_args(app->adb,addr,&app->right_data);
                    if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                    app->need_render=1;return 1;
                }
            }
        }
    }

    /* ——— g: 跳到顶 ——— */
    if(c=='g'){if(pd){pd->cursor=0;pd->scroll=0;app->need_render=1;}return 1;}

    /* ——— G: 跳到底 ——— */
    if(c=='G'){if(pd&&pd->count>0){pd->cursor=pd->count-1;app->need_render=1;}return 1;}

    /* ——— ,  水平左滚 ——— */
    if(c==','){
        if(pd){pd->scroll_x-=8;if(pd->scroll_x<0)pd->scroll_x=0;app->need_render=1;}
        return 1;
    }

    /* ——— .  水平右滚 ——— */
    if(c=='.'){
        if(pd){pd->scroll_x+=8;if(pd->scroll_x>2000)pd->scroll_x=2000;app->need_render=1;}
        return 1;
    }

    /* ——— 0  重置水平滚动 ——— */
    if(c=='0'){if(pd){pd->scroll_x=0;app->need_render=1;}return 1;}

    /* ——— 调试模式寄存器热键 (x/d/t) ——— */
    if(app->debug && app->active_panel==PANEL_MIDDLE && pd && pd->cursor>=0 && pd->cursor<pd->count){
        const char *rt = pd->fields[pd->cursor].text;
        if(rt && strstr(rt,"0x")){
            /* 提取寄存器值 */
            char rn[8]; uint64_t rv=0;
            if(sscanf(rt,"%4s 0x%llx",rn,&rv)==2||sscanf(rt,"%3s 0x%llx",rn,&rv)==2){
                if(rv>0x1000){  /* 看起来像地址 */
                    if(c=='x'){ /* hexdump */
                        if(app->right_data.fields){fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;app->right_data.capacity=0;
                            app->right_data.cursor=0;app->right_data.scroll=0;app->right_data.scroll_x=0;}
                        char dbuf[128]; snprintf(dbuf,sizeof(dbuf),"=== Hexdump @ %s ===",rn);
                        fields_add(&app->right_data,dbuf,0,0,DETAIL_NONE,-1);
                        uint8_t mem[128]; int nr=debug_readmem(app->debug,rv,mem,sizeof(mem));
                        if(nr>0){char hx[80];
                            for(int o=0;o<nr;o+=16){int hp=0;hp+=snprintf(hx+hp,sizeof(hx)-hp,"0x%lx ",rv+o);
                                for(int b=0;b<16&&o+b<nr;b++)hp+=snprintf(hx+hp,sizeof(hx)-hp,"%02x ",mem[o+b]);
                                snprintf(dbuf,sizeof(dbuf),"%-60s",hx);fields_add(&app->right_data,dbuf,1,0,DETAIL_NONE,-1);}
                        }else fields_add(&app->right_data,"(cannot read memory)",1,0,DETAIL_NONE,-1);
                        if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                        app->need_render=1;return 1;
                    }
                    if(c=='d'){ /* disasm */
                        if(app->right_data.fields){fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;app->right_data.capacity=0;
                            app->right_data.cursor=0;app->right_data.scroll=0;app->right_data.scroll_x=0;}
                        char dbuf[128]; snprintf(dbuf,sizeof(dbuf),"=== Disasm @ %s (0x%llx) ===",rn,rv);
                        fields_add(&app->right_data,dbuf,0,0,DETAIL_NONE,-1);
                        uint8_t code[64]; int nr=debug_readmem(app->debug,rv,code,sizeof(code));
                        if(nr>0){disasm_ctx *dd=disasm_open();if(dd){const uint8_t *cp=code;size_t cs=nr;uint64_t ca=rv;int ln=0;
                            while(cs>0&&ln<20&&disasm_next(dd,&cp,&cs,&ca)){cs_insn *in=disasm_insn(dd);
                                char hx[48]="";int hp=0;for(size_t b=0;b<in->size&&hp<40;b++)hp+=snprintf(hx+hp,sizeof(hx)-hp,"%02x ",in->bytes[b]);
                                snprintf(dbuf,sizeof(dbuf),"0x%lx: %-24s %-8s %s",(unsigned long)in->address,hx,in->mnemonic,in->op_str);
                                fields_add(&app->right_data,dbuf,1,1,DETAIL_NONE,(int)(in->address&0xFFFF));ln++;}
                            disasm_close(dd);}else fields_add(&app->right_data,"(Capstone init failed)",1,0,DETAIL_NONE,-1);}
                        else fields_add(&app->right_data,"(cannot read memory)",1,0,DETAIL_NONE,-1);
                        if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                        app->need_render=1;return 1;
                    }
                }
            }
        }
    }

    /* ——— Enter: 展开 ——— */
    if(is_key(c,NCKEY_ENTER,'\r')||is_key(c,NCKEY_ENTER,'\n')){
        switch(app->active_panel){
            case PANEL_LEFT: {
                /* 检查是否选中了弹窗按钮 (detail_index == -4) */
                Elf64_Field *sel = NULL;
                if(app->left_data.cursor >= 0 &&
                   app->left_data.cursor < app->left_data.count)
                    sel = &app->left_data.fields[app->left_data.cursor];
                /* Debug → Attach: 已 attach 则显示寄存器, 否则弹窗/PID输入 */
                if(sel && sel->detail_kind == DETAIL_NONE && sel->detail_index == -34){
                    if(app->debug && app->debug->attached){
                        /* 已 attach: 中面板显示实时寄存器 */
                        if(app->middle_data.fields){
                            fields_free(app->middle_data.fields,app->middle_data.count);
                            app->middle_data.fields=NULL;app->middle_data.count=0;
                            app->middle_data.capacity=0;app->middle_data.cursor=0;app->middle_data.scroll=0;
                        }
                        char title[64];
                        snprintf(title,sizeof(title),"=== Regs PID=%d ===",app->debug->pid);
                        fields_add(&app->middle_data,title,0,0,DETAIL_NONE,-1);
                        render_reg_single_col(app->debug, &app->middle_data);
                        /* 不跳转焦点 — 用户用 → 手动切到中面板 */
                    }else{
                        const char *text = registers_popup_text(app->elf);
                        if (text && text[0]) {
                            /* Core dump: show register popup directly */
                            tui_show_popup(app,
                                "x86-64 Registers (Core Dump)", text);
                        } else {
                            /* 未 attach: 进入 PID 输入模式 */
                            app->pid_target = 0;
                            app->pid_input_active = 1;
                            app->pid_input_pos = 0;
                            memset(app->pid_input_buf, 0, sizeof(app->pid_input_buf));
                            pid_input_update_popup(app);
                        }
                    }
                    app->need_render=1; return 1;
                }
                if(sel && sel->detail_kind == DETAIL_NONE && sel->detail_index == -4){
                    tui_show_popup(app, "Test Popup Window",
                        "This is a test popup dialog.\n\n"
                        "It overlays the main TUI panels.\n"
                        "Press 'q' or 'Esc' to close.");
                    app->need_render=1;
                    return 1;
                }
                /* 功能按钮: Code/Security/Data/Tools 分组中的按钮 */
                { int di = sel->detail_index;
                  if(sel && sel->detail_kind == DETAIL_NONE &&
                   (di == BTN_FUZZER || di == BTN_STACK ||
                    di == BTN_DBVIEW || di == BTN_VULNSCAN ||
                    di == BTN_HEAP || di == BTN_GOTPLT_DYN ||
                    di == BTN_TAINT || di == BTN_ROPCHAIN ||
                    (di <= BTN_DISASM && di >= BTN_HISTORY) ||
                    (di <= BTN_VMMAP && di >= BTN_BPCOND) ||
                    (di <= BTN_TRANS_INSN && di >= BTN_TRANS_VULN) ||
                    /* Phase 2+ new buttons */
                    di == BTN_DATAFLOW || di == BTN_DATAFLOW_INTER ||
                    di == BTN_PTTRACE || di == BTN_HEAPTRACE ||
                    di == BTN_HEAPREPLAY ||
                    di == BTN_BINDIFF || di == BTN_SYMBOLIC ||
                    di == BTN_DECOMPILE)){
                    /* 保存当前活动面板, 按钮 action 不应跳转焦点 */
                    ActivePanel saved = app->active_panel;
                    btn_dispatch(app, sel->detail_index);
                    app->active_panel = saved;
                    app->need_render=1;
                    return 1;
                }}
                /* 左面板所有操作均不跳转焦点 — 用户用 → 手动切到中面板 */
                left_panel_handle_enter(&app->left_data,&app->middle_data,app->elf);
                break;
            }
            case PANEL_MIDDLE: {
                /* 反汇编摘要: 选中节 → 右面板只显示该节反汇编 */
                Elf64_Field *msel = NULL;
                if(app->middle_data.cursor >= 0 &&
                   app->middle_data.cursor < app->middle_data.count)
                    msel = &app->middle_data.fields[app->middle_data.cursor];
                if(msel && msel->detail_kind == DETAIL_SHDR &&
                   app->middle_data.count > 0){
                    const char *hdr = app->middle_data.fields[0].text;
                    if(strstr(hdr, "Disassembly Summary") ||
                       strstr(hdr, "HexDump Sections")){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields, app->right_data.count);
                            app->right_data.fields = NULL;
                            app->right_data.count = 0; app->right_data.capacity = 0;
                            app->right_data.cursor = 0; app->right_data.scroll = 0;
                            app->right_data.scroll_x = 0;
                        }
                        if(strstr(hdr, "Disassembly Summary"))
                            parse_disasm(app->elf, msel->detail_index, &app->right_data);
                        else
                            parse_hexdump(app->elf, msel->detail_index, &app->right_data);
                    }else{
                        middle_panel_handle_enter(&app->middle_data,&app->right_data,app->elf);
                    }
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Search") &&
                   msel->text && strstr(msel->text, "  mem  ")){
                    /* 内存搜索结果: Enter → 右面板 raw memory hexdump */
                    uint64_t addr = 0;
                    const char *p = strstr(msel->text, "0x");
                    if(p)addr=strtoull(p,NULL,16);
                    if(addr>0x1000 && app->debug && app->debug->attached){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        /* 读目标地址周围 4KB */
                        uint8_t *mem = malloc(4096);
                        int nr = mem ? debug_readmem(app->debug, addr, mem, 4096) : 0;
                        if(nr > 0){
                            char buf[256];
                            snprintf(buf,sizeof(buf),"▸ 0x%lx  (%d bytes)", (unsigned long)addr, nr);
                            fields_add(&app->right_data,buf,0,0,DETAIL_NONE,-1);
                            /* maps 归属 */
                            char mpath[64]; snprintf(mpath,sizeof(mpath),"/proc/%d/maps",app->debug->pid);
                            FILE *mf = fopen(mpath,"r");
                            if(mf){char ml[512];
                                while(fgets(ml,sizeof(ml),mf)){uint64_t s,e;char mp[5],mf2[256]="";
                                    if(sscanf(ml,"%lx-%lx %4s %*s %*s %*s %255s",&s,&e,mp,mf2)<2)continue;
                                    if(addr>=s&&addr<e){char ann[128]="";
                                        if(mf2[0]){const char *sl=strrchr(mf2,'/');snprintf(ann,sizeof(ann),"%s",sl?sl+1:mf2);}
                                        else if(mp[2]=='x')snprintf(ann,sizeof(ann),"code(%s)",mp);
                                        else snprintf(ann,sizeof(ann),"%s",mp);
                                        snprintf(buf,sizeof(buf),"Region: %s  0x%lx-0x%lx  %s",ann,(unsigned long)s,(unsigned long)e,mp);
                                        fields_add(&app->right_data,buf,1,0,DETAIL_NONE,-1);break;}}
                                fclose(mf);}
                            fields_add(&app->right_data,"",0,0,DETAIL_NONE,-1);
                            char hx[100];
                            for(int off=0;off<nr;off+=16){
                                int hp=0;
                                hp+=snprintf(hx+hp,sizeof(hx)-hp,"0x%lx  ",(unsigned long)(addr+off));
                                for(int b=0;b<16;b++){
                                    if(off+b<nr)hp+=snprintf(hx+hp,sizeof(hx)-hp,"%02x ",mem[off+b]);
                                    else hp+=snprintf(hx+hp,sizeof(hx)-hp,"   ");
                                }
                                hp+=snprintf(hx+hp,sizeof(hx)-hp," ");
                                for(int b=0;b<16&&off+b<nr;b++){
                                    uint8_t c=mem[off+b];
                                    hp+=snprintf(hx+hp,sizeof(hx)-hp,"%c",(c>=32&&c<127)?(char)c:'.');
                                }
                                fields_add(&app->right_data,hx,1,0,DETAIL_NONE,-1);
                            }
                        }else{
                            fields_add(&app->right_data,"(cannot read memory)",1,0,DETAIL_NONE,-1);
                        }
                        free(mem);
                    }
                    app->need_render=1;return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Search")){
                    /* 搜索结果: 地址 → 右面板 DB 全查 (指令+函数+CFG+XREF) */
                    uint64_t addr = 0;
                    if(msel->text){
                        const char *p = strstr(msel->text, "0x");
                        if(p)addr=strtoull(p,NULL,16);
                    }
                    if(addr>0x1000 && app->adb && !app->db_importing){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        db_query_addr_all(app->adb,addr,app->debug,&app->right_data,0);
                        if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                    }else if(addr>0x1000 && app->db_importing){
                        tui_show_popup(app,"DB Importing","Wait for import to complete.");
                    }
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Dynamic GOT/PLT")){
                    /* 动态 GOT/PLT: 选中条目 → 右面板详情 (解析地址+hexdump) */
                    dyn_gotplt_show_detail(app, msel->text);
                    app->need_render = 1; return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Analysis Database")){
                    /* 分析数据库: 选中地址 → 右面板 XREF+寄存器快照 */
                    if(dbview_show_xrefs(app, msel->text) == 0 &&
                       app->right_data.count > 0)
                        app->active_panel = PANEL_RIGHT;
                    app->need_render = 1; return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Heap")){
                    /* 堆视图: chunk行→chunk详情, link行→link详情 */
                    uint64_t a1=0,a2=0;
                    if(msel->text){
                        const char *p=strstr(msel->text,"0x");
                        if(p){a1=strtoull(p,NULL,16);
                            const char *q=strstr(p+2,"0x");
                            if(q)a2=strtoull(q,NULL,16);}
                    }
                    if(a1>0x1000&&app->adb){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        if(a2>0x1000)
                            heap_query_link_detail(app->adb,a1,a2,&app->right_data);
                        else
                            heap_query_chunk_detail(app->adb,a1,&app->right_data);
                    }
                    app->need_render=1;return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Vulnerability Scan")){
                    uint64_t addr = 0;
                    if(msel->text){const char *p=strstr(msel->text,"0x");
                        if(p)addr=strtoull(p,NULL,16);}
                    if(addr>0x1000&&app->adb&&!app->db_importing){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        db_vuln_detail(app->adb,addr,&app->right_data);
                        if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                    }
                    app->need_render=1;return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   (strstr(app->middle_data.fields[0].text, "Memory Map") ||
                    (strstr(app->middle_data.fields[0].text, "Regs") &&
                     msel->text && strstr(msel->text, "-> ")))){
                    /* 寄存器区域标注 → 读整个段, 高亮寄存器值所在行 */
                    uint64_t rv=0, seg_start=0, seg_end=0;
                    const char *p_rv = strstr(msel->text, "0x");
                    if(p_rv) rv = strtoull(p_rv, NULL, 16);
                    const char *p_seg = p_rv ? strstr(p_rv+2, "0x") : NULL;
                    if(p_seg) sscanf(p_seg, "0x%lx-0x%lx", &seg_start, &seg_end);
                    if(rv>0x1000 && app->debug && app->debug->attached){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        /* 读段内容, 以 rv 为中心, 最多 4096 字节 */
                        uint64_t seg_size = (seg_end > seg_start) ? (seg_end - seg_start) : 0;
                        uint64_t dump_start, dump_size;
                        if (seg_size > 0 && seg_size <= 4096) {
                            dump_start = seg_start; dump_size = seg_size;
                        } else {
                            dump_size = 4096;
                            dump_start = (rv > dump_size/2) ? (rv - dump_size/2) : seg_start;
                            if (dump_start < seg_start) dump_start = seg_start;
                        }
                        uint8_t *mem = malloc((size_t)dump_size);
                        int nr = mem ? debug_readmem(app->debug, dump_start, mem, (size_t)dump_size) : -1;
                        if(nr > 0){
                            char buf[256];
                            snprintf(buf,sizeof(buf),"=== Hexdump 0x%lx-0x%lx (%d bytes) ===",
                                     (unsigned long)dump_start,(unsigned long)(dump_start+nr),nr);
                            fields_add(&app->right_data,buf,0,0,DETAIL_NONE,-1);
                            snprintf(buf,sizeof(buf),"RIP=0x%lx  seg:0x%lx-0x%lx  ▶=cursor",
                                     (unsigned long)rv,(unsigned long)seg_start,(unsigned long)seg_end);
                            fields_add(&app->right_data,buf,1,0,DETAIL_NONE,-1);
                            char hx[128];
                            int hl_line = -1;  /* 高亮行索引 (寄存器值所在行) */
                            int line_idx = app->right_data.count; /* 首行索引 */
                            for(int off=0;off<nr;off+=16){
                                uint64_t line_addr = dump_start + off;
                                /* 此行是否包含寄存器值? */
                                int hl = (rv >= line_addr && rv < line_addr + 16);
                                if (hl) hl_line = line_idx;
                                int hp=0;
                                hp+=snprintf(hx+hp,sizeof(hx)-hp,"%s0x%lx  ",
                                    hl?"▶ ":"  ", (unsigned long)line_addr);
                                for(int b=0;b<16;b++){
                                    if(off+b<nr)hp+=snprintf(hx+hp,sizeof(hx)-hp,"%02x ",mem[off+b]);
                                    else hp+=snprintf(hx+hp,sizeof(hx)-hp,"   ");
                                }
                                hp+=snprintf(hx+hp,sizeof(hx)-hp," ");
                                for(int b=0;b<16&&off+b<nr;b++){
                                    uint8_t c=mem[off+b];
                                    hp+=snprintf(hx+hp,sizeof(hx)-hp,"%c",(c>=32&&c<127)?(char)c:'.');
                                }
                                /* 高亮行: selectable=1 → region_lines 黄色前景 */
                                fields_add(&app->right_data,hx,1,hl?1:0,DETAIL_NONE,-1);
                                line_idx++;
                            }
                            /* 自动滚动: 高亮行居中于右面板视口 */
                            if (hl_line >= 0) {
                                app->right_data.cursor = hl_line;
                                /* 计算可视行数: 面板高度 - 2 (边框) */
                                unsigned ty; ncplane_dim_yx(
                                    notcurses_stdplane(app->nc), &ty, NULL);
                                int vis = (int)(ty * 50 / 100) - 2; /* 右面板=50% */
                                if (vis < 4) vis = 4;
                                app->right_data.scroll = hl_line - vis/2;
                                if (app->right_data.scroll < 0) app->right_data.scroll = 0;
                            }
                        }else fields_add(&app->right_data,"(cannot read memory)",1,0,DETAIL_NONE,-1);
                        free(mem);
                    }
                    app->need_render = 1; return 1;
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   strstr(app->middle_data.fields[0].text, "Decompile")){
                    /* Decompile: 函数列表 → Enter → 反编译到右面板 */
                    uint64_t addr = 0;
                    if (msel->text) {
                        const char *p = strstr(msel->text, "0x");
                        if (p) addr = strtoull(p, NULL, 16);
                    }
                    if (addr > 0x1000 && app->adb && !app->db_importing) {
                        if (app->right_data.fields) {
                            fields_free(app->right_data.fields, app->right_data.count);
                            app->right_data.fields = NULL; app->right_data.count = 0;
                            app->right_data.capacity = 0; app->right_data.cursor = 0;
                            app->right_data.scroll = 0; app->right_data.scroll_x = 0;
                        }
                        decompile_function_at(addr, &app->right_data);
                        if (app->right_data.count > 0)
                            app->active_panel = PANEL_RIGHT;
                        app->need_render = 1; return 1;
                    }
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   app->middle_data.fields[0].text &&
                   strstr(app->middle_data.fields[0].text, "Runtime Symbol")){
                    /* SymResolve: 运行时地址 → 右面板详细 (maps+DB XREF+4KB hexdump) */
                    uint64_t addr = 0;
                    if(msel->text){const char *p=strstr(msel->text,"0x");
                        if(p)addr=strtoull(p,NULL,16);}
                    if(addr>0x1000 && app->debug && app->debug->attached){
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        char buf[512];
                        snprintf(buf,sizeof(buf),"▸ SymResolve Detail @ 0x%lx",(unsigned long)addr);
                        fields_add(&app->right_data,buf,0,0,DETAIL_NONE,-1);
                        /* proc maps 归属 */
                        char mpath[64];snprintf(mpath,sizeof(mpath),"/proc/%d/maps",app->debug->pid);
                        FILE *mf=fopen(mpath,"r");
                        if(mf){char ml[512];
                            while(fgets(ml,sizeof(ml),mf)){uint64_t s,e;char mp[5],mf2[256]="";
                                if(sscanf(ml,"%lx-%lx %4s %*s %*s %*s %255s",&s,&e,mp,mf2)<2)continue;
                                if(addr>=s&&addr<e){
                                    snprintf(buf,sizeof(buf),"Segment: 0x%lx-0x%lx  %s  %s",(unsigned long)s,(unsigned long)e,mp,mf2[0]?mf2:"[anon]");
                                    fields_add(&app->right_data,buf,1,0,DETAIL_NONE,-1);
                                    snprintf(buf,sizeof(buf),"Offset: +0x%lx into segment",(unsigned long)(addr-s));
                                    fields_add(&app->right_data,buf,1,0,DETAIL_NONE,-1);break;}}
                            fclose(mf);}
                        /* DB 符号匹配 */
                        if(app->adb){sqlite3 *c2=(sqlite3*)db_conn(app->adb);
                            if(c2){sqlite3_stmt *st2=NULL;
                                sqlite3_prepare_v2(c2,"SELECT name,type,bind FROM symbols WHERE address=?1 LIMIT 1",-1,&st2,NULL);
                                if(st2){sqlite3_bind_int64(st2,1,(sqlite3_int64)addr);
                                    if(sqlite3_step(st2)==SQLITE_ROW){
                                        snprintf(buf,sizeof(buf),"Static DB: %s [%s/%s]",sqlite3_column_text(st2,0),sqlite3_column_text(st2,1),sqlite3_column_text(st2,2));
                                        fields_add(&app->right_data,buf,1,0,DETAIL_NONE,-1);}
                                    else fields_add(&app->right_data,"Static DB: (runtime only, not in analysis DB)",1,0,DETAIL_NONE,-1);
                                    sqlite3_finalize(st2);}}}
                        /* DB XREF */
                        if(app->adb){sqlite3 *c2=(sqlite3*)db_conn(app->adb);
                            if(c2){sqlite3_stmt *st2=NULL;
                                sqlite3_prepare_v2(c2,"SELECT from_addr,ref_type FROM xrefs WHERE to_addr=?1 LIMIT 16",-1,&st2,NULL);
                                if(st2){sqlite3_bind_int64(st2,1,(sqlite3_int64)addr);int nx=0;
                                    while(sqlite3_step(st2)==SQLITE_ROW&&nx<16){
                                        if(nx==0)fields_add(&app->right_data,"── DB XREFs (static) ──",1,0,DETAIL_NONE,-1);
                                        snprintf(buf,sizeof(buf),"← 0x%lx  %s",(unsigned long)sqlite3_column_int64(st2,0),sqlite3_column_text(st2,1));
                                        fields_add(&app->right_data,buf,2,0,DETAIL_NONE,-1);nx++;}
                                    sqlite3_finalize(st2);}}}
                        /* 4KB hexdump */
                        fields_add(&app->right_data,"── Memory Hexdump (4KB) ──",1,0,DETAIL_NONE,-1);
                        uint8_t *mem=malloc(4096);
                        int nr=mem?debug_readmem(app->debug,addr,mem,4096):0;
                        if(nr>0){char hx[100];
                            for(int off=0;off<nr&&off<4096;off+=16){int hp=0;
                                hp+=snprintf(hx+hp,sizeof(hx)-hp,"+0x%03x  ",off);
                                for(int b=0;b<16;b++){
                                    if(off+b<nr)hp+=snprintf(hx+hp,sizeof(hx)-hp,"%02x ",mem[off+b]);
                                    else hp+=snprintf(hx+hp,sizeof(hx)-hp,"   ");}
                                hp+=snprintf(hx+hp,sizeof(hx)-hp," ");
                                for(int b=0;b<16&&off+b<nr;b++){uint8_t c=mem[off+b];
                                    hp+=snprintf(hx+hp,sizeof(hx)-hp,"%c",(c>=32&&c<127)?(char)c:'.');}
                                fields_add(&app->right_data,hx,1,0,DETAIL_NONE,-1);}}
                        else fields_add(&app->right_data,"(cannot read memory)",1,0,DETAIL_NONE,-1);
                        free(mem);
                        if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                        app->need_render=1;return 1;
                    }
                }else if(msel && msel->selectable && app->middle_data.count > 0 &&
                   app->middle_data.fields[0].text){
                    /* 安全审计/代码分析 等视图: 选中行 → 右面板详情 */
                    const char *hdr = app->middle_data.fields[0].text;
                    if(strstr(hdr, "Security") || strstr(hdr, "Attack Surface") ||
                       strstr(hdr, "Segment Permission") || strstr(hdr, "Function Boundary") ||
                       strstr(hdr, "ROP Gadget") || strstr(hdr, "Danger") ||
                       strstr(hdr, "Taint") ||
                       strstr(hdr, "Call Graph") || strstr(hdr, "Data Flow") ||
                       strstr(hdr, "String Cross") || strstr(hdr, "Vulnerability Risk") ||
                       strstr(hdr, "Runtime Symbol")){
                        uint64_t addr=0;const char *p=strstr(msel->text?msel->text:"","0x");
                        if(p)addr=strtoull(p,NULL,16);
                        if(addr>0x1000&&app->adb&&!app->db_importing){
                            if(app->right_data.fields){
                                fields_free(app->right_data.fields,app->right_data.count);
                                app->right_data.fields=NULL;app->right_data.count=0;
                                app->right_data.capacity=0;app->right_data.cursor=0;
                                app->right_data.scroll=0;app->right_data.scroll_x=0;
                            }
                            db_query_addr_all(app->adb,addr,app->debug,&app->right_data,0);
                            if(app->right_data.count>0)app->active_panel=PANEL_RIGHT;
                        }else if(addr>0x1000&&app->db_importing){
                            tui_show_popup(app,"DB Importing","Wait...");
                        }
                        app->need_render=1;return 1;
                    }else{
                        middle_panel_handle_enter(&app->middle_data,&app->right_data,app->elf);
                        if(app->right_data.count>0) app->active_panel=PANEL_RIGHT;
                    }
                }else{
                    /* Catch-All: 反汇编行 或 含独立代码地址 → 右面板上下文跳转 */
                    uint64_t addr = 0;
                    int is_disasm_line = 0;
                    int is_code_addr   = 0;
                    if (msel && msel->text) {
                        const char *p = msel->text;
                        while (*p == ' ') p++;
                        /* 规则1: 反汇编行 "0xADDR: hexbytes mnemonic" */
                        if (strncmp(p, "0x", 2) == 0) {
                            const char *colon = strchr(p, ':');
                            if (colon && colon > p + 4) {
                                const char *after = colon + 1;
                                while (*after == ' ') after++;
                                if (isxdigit((unsigned char)after[0]) &&
                                    isxdigit((unsigned char)after[1]) &&
                                    after[2] == ' ') {
                                    is_disasm_line = 1;
                                    addr = strtoull(p, NULL, 16);
                                }
                            }
                        }
                        /* 规则2: 行中含独立代码地址 0xADDR (不是 0xADDR-0xADDR 范围) */
                        if (!is_disasm_line) {
                            const char *xp = strstr(p, "0x");
                            while (xp) {
                                const char *ap = xp + 2;
                                while (isxdigit((unsigned char)*ap)) ap++;
                                /* 排除地址范围 (后面紧跟 '-') 和非代码地址 (如 0x0, 0x1) */
                                if (*ap != '-' && *ap != 'x' && ap > xp + 4) {
                                    uint64_t candidate = strtoull(xp, NULL, 16);
                                    if (candidate > 0x1000) {
                                        is_code_addr = 1;
                                        addr = candidate;
                                        break;
                                    }
                                }
                                xp = strstr(xp + 2, "0x");
                            }
                        }
                    }
                    if ((is_disasm_line || is_code_addr) && addr > 0x1000
                        && app->adb && !app->db_importing) {
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields, app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        db_query_addr_all(app->adb, addr, app->debug, &app->right_data, 0);
                        if(app->right_data.count>0) app->active_panel=PANEL_RIGHT;
                    } else {
                        middle_panel_handle_enter(&app->middle_data,&app->right_data,app->elf);
                        if(app->right_data.count>0) app->active_panel=PANEL_RIGHT;
                    }
                }
                break;
            }
            case PANEL_RIGHT: {
                /* 右面板地址跳转: 选中任何含 0x... 的行 → Enter → 递归查询新地址 */
                Elf64_Field *rsel = NULL;
                if(app->right_data.cursor>=0 && app->right_data.cursor<app->right_data.count)
                    rsel = &app->right_data.fields[app->right_data.cursor];
                if(rsel && rsel->text && app->adb && !app->db_importing){
                    uint64_t addr=0;const char *p=rsel->text;
                    while(*p==' ')p++;
                    if(strncmp(p,"0x",2)==0)addr=strtoull(p,NULL,16);
                    else{p=strstr(p,"0x");if(p)addr=strtoull(p,NULL,16);}
                    if(addr>0x1000){
                        /* 推入导航历史 (标题在 fields[1], fields[0]是深度行) */
                        if(app->right_data.count>1&&app->nav_depth<32){
                            const char *th=app->right_data.fields[1].text;
                            if(th&&strstr(th,"0x")){
                                const char *tp=strstr(th,"0x");
                                uint64_t prev= tp?strtoull(tp,NULL,16):0;
                                if(prev>0)app->nav_history[app->nav_depth++]=prev;
                            }
                        }
                        /* 清空后写入新查询结果 */
                        if(app->right_data.fields){
                            fields_free(app->right_data.fields,app->right_data.count);
                            app->right_data.fields=NULL;app->right_data.count=0;
                            app->right_data.capacity=0;app->right_data.cursor=0;
                            app->right_data.scroll=0;app->right_data.scroll_x=0;
                        }
                        db_query_addr_all(app->adb,addr,app->debug,&app->right_data,app->nav_depth);
                    }
                }
                break;
            }
            case PANEL_COUNT: break;
        }
        app->need_render=1;return 1;
    }

    /* ——— h 或 Backspace: 返回 (优先导航历史) ——— */
    if(c=='h'||c=='H'||is_key(c,NCKEY_BACKSPACE,'\b')){
        if(app->active_panel==PANEL_RIGHT && app->nav_depth>0){
            /* 有导航历史: 回退到上一次跳转的地址 */
            uint64_t prev=app->nav_history[--app->nav_depth];
            if(app->right_data.fields){
                fields_free(app->right_data.fields,app->right_data.count);
                app->right_data.fields=NULL;app->right_data.count=0;
                app->right_data.capacity=0;app->right_data.cursor=0;
                app->right_data.scroll=0;app->right_data.scroll_x=0;
            }
            if(app->adb&&!app->db_importing)
                db_query_addr_all(app->adb,prev,app->debug,&app->right_data,app->nav_depth);
            app->need_render=1;return 1;
        }
        if(app->active_panel==PANEL_RIGHT) app->active_panel=PANEL_MIDDLE;
        else if(app->active_panel==PANEL_MIDDLE) app->active_panel=PANEL_LEFT;
        app->need_render=1;
        return 1;
    }

    return 0;
}
