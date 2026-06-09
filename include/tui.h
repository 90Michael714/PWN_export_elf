/*
 * tui.h — TUI 主控头文件
 */

#ifndef TUI_H
#define TUI_H

#include <notcurses/notcurses.h>
#include "elf_parser.h"
#include "tui_panels.h"
#include "core/worker.h"
#include "core/query.h"
#include "core/db.h"

typedef struct {
    struct notcurses *nc;
    Elf64_Ctx        *elf;

    PanelData  left_data;
    PanelData  middle_data;
    PanelData  right_data;

    ActivePanel active_panel;
    int         running;
    int         need_render;

    /* 异步 Job 跟踪 */
    Job        *pending_job;     /* 当前后台分析 Job (NULL=无) */
    int         job_panel;       /* 完成后填充到哪个面板 (PANEL_MIDDLE/PANEL_RIGHT) */
    int         job_running;     /* 1=Job 执行中, 0=空闲 */

    /* 弹窗状态 */
    int         popup_active;
    int         popup_dirty;   /* 1=弹窗内容变化需要重绘 */
    /* PID 输入模式 (共享, 多种功能复用) */
    int         pid_input_active;
    char        pid_input_buf[16];
    int         pid_input_pos;
    int         pid_target;
    /* Ptrace 调试状态 (NULL=静态, 非NULL=attach后持续调试模式) */
    struct DebugState *debug;
    uint64_t            last_rip;
    /* 数据总线 (Phase 2): 所有模块通过此查询符号/反汇编/节信息 */
    QueryDB            *qdb;
    /* 分析数据库 (SQLite3): 反汇编指令 + 寄存器快照 + 交叉引用 + CFG */
    AnalysisDB         *adb;
    int                 db_importing;   /* 1=后台导入中 */
    /* 导航历史: 右面板地址跳转的 breadcrumb */
    uint64_t            nav_history[32];
    int                 nav_depth;
    /* Search 输入模式 (Search 按钮触发, 接受任意字符) */
    int         search_input_active;
    char        search_input_buf[64];
    int         search_input_pos;
    char        popup_title[64];
    char        popup_content[4096];

    char        status_text[256];
} TuiApp;

/* 主控 API */
TuiApp* tui_create(Elf64_Ctx *elf);
void    tui_destroy(TuiApp *app);
void    tui_run(TuiApp *app);
void    tui_set_status(TuiApp *app, const char *fmt, ...);
void    tui_render_all(TuiApp *app);
void    tui_show_popup(TuiApp *app, const char *title, const char *content);

/* 异步分析提交 (按钮调用) */
int     tui_submit_analysis(TuiApp *app, WorkerFn fn, int arg_int,
                            const char *status_msg, int target_panel);

/* 子模块 */
void    tui_status_render(TuiApp *app);
int     tui_handle_input(TuiApp *app, const struct ncinput *ni);

#endif
