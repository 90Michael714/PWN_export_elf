/*
 * tui_buttons.h — 左面板功能按钮声明
 *
 * 每个功能按钮一个 action 函数，接收 TuiApp*，通过弹窗或中间面板展示结果。
 * 当前全部为占位桩 (stub)，后期逐步填入实现代码。
 */

#ifndef TUI_BUTTONS_H
#define TUI_BUTTONS_H

#include "tui.h"

/* 按钮 detail_index 常量 — 用于 tui_left.c 和 tui_handle_input 中匹配 */
enum {
    BTN_DISASM      = -10,
    BTN_GOTPLT      = -11,
    BTN_HEXDUMP     = -12,
    BTN_FUNCMAP     = -13,
    BTN_HARDENING   = -14,
    BTN_DANGERFUNC  = -15,
    BTN_ROPGADGET   = -16,
    BTN_ATKSURFACE  = -17,
    BTN_SEGPERM     = -18,
    BTN_MEMLAYOUT   = -19,
    BTN_INITARRAY   = -20,
    BTN_STRXREF     = -21,
    BTN_EHFRAME     = -22,
    BTN_SEARCH      = -23,
    BTN_EXPORT      = -24,
    BTN_KEYHELP     = -25,
    BTN_ABOUT       = -26,
    BTN_HISTORY     = -27,
    /* Debug & Runtime */
    BTN_VMMAP       = -40,
    BTN_SYMRESOLVE  = -41,
    BTN_BACKTRACE   = -42,
    BTN_TELESCOPE   = -43,
    BTN_HWBP        = -44,
    /* Exploit Tools */
    BTN_ONEGADGET   = -45,
    BTN_SYSCALL     = -46,
    BTN_EXPREVAL    = -47,
    BTN_BPCOND      = -48,
    BTN_TAINT       = -49,
    BTN_ROPCHAIN    = -50,
    BTN_TRANS_INSN  = -60,
    BTN_TRANS_VULN  = -62,
    BTN_MEMSEARCH   = -39,
    BTN_FUZZER      = -29,
    BTN_STACK       = -28,
    BTN_DBVIEW      = -37,
    BTN_VULNSCAN    = -57,
    BTN_HEAP        = -56,
    BTN_GOTPLT_DYN  = -82,
    /* Phase 2+ IR + Trace */
    BTN_DATAFLOW     = -70,
    BTN_DATAFLOW_INTER = -71,
    BTN_PTTRACE      = -72,
    BTN_HEAPTRACE    = -73,
    BTN_HEAPREPLAY   = -74,
    BTN_BINDIFF      = -75,
    BTN_SYMBOLIC     = -76,
    BTN_DECOMPILE    = -77,
    BTN_RT_DECOMP    = -78,   /* 运行时感知反编译 */
};

/* 按钮 action 函数 — 每个返回 0=成功, -1=失败 */
int btn_disasm_action     (TuiApp *app);
int btn_gotplt_action     (TuiApp *app);
int btn_hexdump_action    (TuiApp *app);
int btn_funcmap_action    (TuiApp *app);
int btn_hardening_action  (TuiApp *app);
int btn_dangerfunc_action (TuiApp *app);
int btn_ropgadget_action  (TuiApp *app);
int btn_atksurface_action (TuiApp *app);
int btn_segperm_action    (TuiApp *app);
int btn_memlayout_action  (TuiApp *app);
int btn_initarray_action  (TuiApp *app);
int btn_strxref_action    (TuiApp *app);
int btn_ehframe_action    (TuiApp *app);
int btn_search_action     (TuiApp *app);
int btn_export_action     (TuiApp *app);
int btn_keyhelp_action    (TuiApp *app);
int btn_about_action      (TuiApp *app);
int btn_history_action    (TuiApp *app);
int btn_vmmap_action      (TuiApp *app);
int btn_symresolve_action (TuiApp *app);
int btn_symresolve_handle_key(TuiApp *app, int key);
int btn_backtrace_action  (TuiApp *app);
int btn_telescope_action  (TuiApp *app);
int btn_hwbp_action       (TuiApp *app);
int btn_onegadget_action  (TuiApp *app);
int btn_syscall_action    (TuiApp *app);
int btn_expreval_action   (TuiApp *app);
int btn_bpcond_action     (TuiApp *app);
int btn_taint_action      (TuiApp *app);
int btn_ropchain_action   (TuiApp *app);
int btn_trans_insn_action (TuiApp *app);
int btn_trans_vuln_action (TuiApp *app);
int btn_fuzzer_action    (TuiApp *app);
int btn_memsearch_action (TuiApp *app);
int btn_stack_action     (TuiApp *app);
int btn_dbview_action    (TuiApp *app);
int btn_vulnscan_action  (TuiApp *app);
int btn_heap_action      (TuiApp *app);
int btn_heap_handle_key  (TuiApp *app, int key);
int btn_gotplt_dyn_action (TuiApp *app);
int dyn_gotplt_show_detail(TuiApp *app, const char *line);

/* Phase 2+ new buttons */
int btn_dataflow_action     (TuiApp *app);
int btn_dataflow_inter_action (TuiApp *app);
int btn_pttrace_action      (TuiApp *app);
int btn_heaptrace_action    (TuiApp *app);
int btn_heapreplay_action   (TuiApp *app);
int btn_bindiff_action      (TuiApp *app);
int btn_symbolic_action     (TuiApp *app);
int btn_decompile_action    (TuiApp *app);
int btn_rtdecomp_action     (TuiApp *app);   /* 运行时感知反编译 */

/* 按钮分发器: 根据 detail_index 调用对应 action */
int btn_dispatch(TuiApp *app, int detail_index);

/* memsearch: 中面板内存段列表 → Enter → 右面板hexdump (tui_input.c调用) */
int memsearch_show_hexdump(TuiApp *app, const char *seg_line);
int vmmap_show_hexdump(TuiApp *app, const char *seg_line);

/* dbview: 中面板地址 → Enter → 右面板 XREF+寄存器快照 */
int dbview_show_xrefs(TuiApp *app, const char *line);

#endif
