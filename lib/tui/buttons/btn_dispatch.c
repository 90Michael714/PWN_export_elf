/*
 * btn_dispatch.c — 按钮分发器
 *
 * Phase 5: 纯转发按钮由 BUTTON_REGISTRY[] 表驱动 (btn_common.c),
 * 有自定义逻辑的保留独立文件和 switch case。
 */

#include "tui_buttons.h"

/* 声明注册表回退函数 */
extern int btn_registry_dispatch(TuiApp *app, int btn_id);

int btn_dispatch(TuiApp *app, int detail_index)
{
    switch (detail_index) {
        /* ── 自定义逻辑按钮 (保留独立文件) ── */
        case BTN_DISASM:      return btn_disasm_action(app);
        case BTN_GOTPLT:      return btn_gotplt_action(app);
        case BTN_HEXDUMP:     return btn_hexdump_action(app);
        case BTN_FUNCMAP:     return btn_funcmap_action(app);
        case BTN_HARDENING:   return btn_hardening_action(app);
        case BTN_DANGERFUNC:  return btn_dangerfunc_action(app);
        case BTN_ROPGADGET:   return btn_ropgadget_action(app);
        case BTN_INITARRAY:   return btn_initarray_action(app);
        case BTN_SEARCH:      return btn_search_action(app);
        case BTN_EXPORT:      return btn_export_action(app);
        case BTN_KEYHELP:     return btn_keyhelp_action(app);
        case BTN_ABOUT:       return btn_about_action(app);
        case BTN_HISTORY:     return btn_history_action(app);
        case BTN_VMMAP:       return btn_vmmap_action(app);
        case BTN_SYMRESOLVE:  return btn_symresolve_action(app);
        case BTN_BACKTRACE:   return btn_backtrace_action(app);
        case BTN_TELESCOPE:   return btn_telescope_action(app);
        case BTN_HWBP:        return btn_hwbp_action(app);
        case BTN_ONEGADGET:   return btn_onegadget_action(app);
        case BTN_SYSCALL:     return btn_syscall_action(app);
        case BTN_EXPREVAL:    return btn_expreval_action(app);
        case BTN_BPCOND:      return btn_bpcond_action(app);
        case BTN_TAINT:       return btn_taint_action(app);
        case BTN_ROPCHAIN:    return btn_ropchain_action(app);
        case BTN_TRANS_INSN:  return btn_trans_insn_action(app);
        case BTN_FUZZER:      return btn_fuzzer_action(app);
        case BTN_STACK:       return btn_stack_action(app);
        case BTN_DBVIEW:      return btn_dbview_action(app);
        case BTN_VULNSCAN:    return btn_vulnscan_action(app);
        case BTN_HEAP:        return btn_heap_action(app);
        case BTN_GOTPLT_DYN:  return btn_gotplt_dyn_action(app);
        case BTN_DATAFLOW:        return btn_dataflow_action(app);
        case BTN_DATAFLOW_INTER:  return btn_dataflow_inter_action(app);
        case BTN_PTTRACE:         return btn_pttrace_action(app);
        case BTN_HEAPTRACE:       return btn_heaptrace_action(app);
        case BTN_HEAPREPLAY:      return btn_heapreplay_action(app);
        case BTN_BINDIFF:         return btn_bindiff_action(app);
        case BTN_SYMBOLIC:        return btn_symbolic_action(app);
        case BTN_DECOMPILE:       return btn_decompile_action(app);
        case BTN_RT_DECOMP:       return btn_rtdecomp_action(app);

        /* ── 纯转发按钮 → btn_common.c 注册表 ── */
        default: {
            int r = btn_registry_dispatch(app, detail_index);
            if (r == 0) return r;
            return -1;
        }
    }
}
