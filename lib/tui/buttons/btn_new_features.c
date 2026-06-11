/*
 * btn_new_features.c — Phase 2+ 新功能按钮 actions
 *
 * 统一管理新增按钮的实现, 遵循 btn_xxx_action(TuiApp*) 接口约定。
 */

#include "tui.h"
#include "tui_buttons.h"
#include "core/ir.h"
#include "core/pt_trace.h"
#include "core/rt_resolver.h"
#include "core/heap_analyzer.h"
#include "core/db.h"
#include "core/debug_worker.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

/* 外部声明 — 分析引擎入口 */
extern AnalysisDB *g_active_db; /* 由 dataflow.c 等文件使用 */

/* ================================================================== */
/* DataFlow — 函数内 IR 数据流分析                                     */
/* ================================================================== */

int btn_dataflow_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->adb) {
        tui_show_popup(app, "DataFlow", "DB not available.\nImport ELF first.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    /* 获取当前选中的地址 (从中间面板或右面板) */
    uint64_t target = 0;
    PanelData *src = &app->middle_data;
    if (src->count > 0 && src->cursor >= 0 && src->cursor < src->count) {
        target = (uint64_t)src->fields[src->cursor].detail_index;
    }
    if (target == 0) {
        Elf64_Ehdr *ehdr = elf_get_ehdr(app->elf);
        target = ehdr->e_entry;
    }

    /* 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    dataflow_set_target(target);
    parse_dataflow(app->elf, 0, &app->middle_data);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* DataFlow Inter — 跨过程数据流分析                                    */
/* ================================================================== */

int btn_dataflow_inter_action(TuiApp *app)
{
    if (!app || !app->adb) {
        if (app) tui_show_popup(app, "DF-Inter", "DB not available.");
        return 0;
    }
    g_active_db = app->adb;

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    parse_dataflow_inter(app->elf, 0, &app->middle_data);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* PT Trace — Intel PT / BTS 执行 Trace                                */
/*                                                                     */
/* 录制策略:                                                           */
/*   - Intel PT 后端:  PTRACE_CONT + SIGALRM 超时 (3s)                  */
/*   - Software 后端:  PTRACE_SINGLESTEP 有界循环 (1000步 / 2s)         */
/*                                                                     */
/* 两种路径都不会永久阻塞 TUI — 每一步/每次 wait 都有超时保护。          */
/* ================================================================== */

/*
 * intel_pt_continue_timeout — 使用 alarm(2) 给 PTRACE_CONT 加超时
 *
 * PTRACE_CONT 会让 tracee 自由运行, waitpid 会一直阻塞直到 tracee
 * 收到信号。这里用 SIGALRM 作为超时, 到期后通过 PTRACE_INTERRUPT
 * (Linux 3.4+) 强行停止 tracee。
 *
 * 返回: 0 = 正常停止, -1 = 超时中断, -2 = 错误
 */
static int intel_pt_continue_timeout(DebugState *ds, int timeout_sec)
{
    if (!ds || !ds->attached) return -2;

    /* 安装 SIGALRM 处理器 (忽略信号本身, 仅用于中断 waitpid) */
    struct sigaction sa_old, sa_new;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = SIG_IGN;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0;
    sigaction(SIGALRM, &sa_new, &sa_old);

    alarm((unsigned)timeout_sec);

    /* PTRACE_CONT — tracee 开始自由执行 */
    if (ptrace(PTRACE_CONT, ds->pid, NULL, NULL) == -1) {
        alarm(0);
        sigaction(SIGALRM, &sa_old, NULL);
        return -2;
    }

    int result = 0;
    int status = 0;
    while (waitpid(ds->pid, &status, 0) == -1) {
        if (errno == EINTR) {
            /* SIGALRM 触发 → 强行中断 tracee */
            ptrace(PTRACE_INTERRUPT, ds->pid, NULL, NULL);
            /* 等待 tracee 实际停止 (SIGTRAP) */
            if (waitpid(ds->pid, &status, 0) > 0) {
                ds->last_status = status;
                if (WIFSTOPPED(status))
                    ds->last_signal = WSTOPSIG(status);
            }
            result = -1;  /* 超时中断 */
            break;
        }
        /* 其他错误 → 退出 */
        result = -2;
        break;
    }

    /* 正常停止: 保存状态 */
    if (result == 0) {
        ds->last_status = status;
        if (WIFSTOPPED(status))
            ds->last_signal = WSTOPSIG(status);
        if (WIFEXITED(status) || WIFSIGNALED(status))
            ds->attached = 0;
        /* 刷新寄存器 */
        debug_getregs(ds);
    }

    /* 清理 */
    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);

    return result;
}

int btn_pttrace_action(TuiApp *app)
{
    if (!app) return -1;

    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "PT Trace",
            "Not attached.\n\nAttach to a process first (Debug → Attach),\n"
            "then click PT Trace to record execution.");
        app->need_render = 1; return 0;
    }
    if (!app->adb) {
        tui_show_popup(app, "PT Trace", "DB not ready.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    /* 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 探测可用后端 */
    trace_backend_t *tb = trace_detect_backend();
    if (!tb) {
        fields_add(&app->middle_data, "(no trace backend available)", 0, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1;
        return 0;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "=== %s Trace ===", tb->name);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);

    /* 开始录制 */
    void *tctx = NULL;
    if (tb->start(app->debug, &tctx) != 0) {
        fields_add(&app->middle_data, "(trace start failed — maybe Intel PT unavailable)", 1, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1;
        return 0;
    }

    /* 创建 DB session */
    int sid = trace_session_begin(app->adb, app->debug->pid, tb->name);

    fields_add(&app->middle_data, "Trace recording STARTED.", 1, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Session #%d  Backend: %s", sid, tb->name);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

    /* ══════════════════════════════════════════════════════════════════
     * 录制阶段 — 两条路径, 都不会永久阻塞 TUI
     * ══════════════════════════════════════════════════════════════════ */
    int is_hw = (strcmp(tb->name, "Intel PT") == 0);

    if (is_hw) {
        /* ── Intel PT 硬件路径: PTRACE_CONT + alarm 超时 ── */
        fields_add(&app->middle_data,
            "HW PT: PTRACE_CONT w/ 3s alarm timeout...", 1, 0, DETAIL_NONE, -1);

        int rc = intel_pt_continue_timeout(app->debug, 3);
        if (rc == -1) {
            fields_add(&app->middle_data,
                "(timeout — tracee interrupted via PTRACE_INTERRUPT)", 1, 0, DETAIL_NONE, -1);
        } else if (rc == -2) {
            fields_add(&app->middle_data,
                "(PTRACE_CONT failed — tracee may have exited)", 1, 0, DETAIL_NONE, -1);
        } else {
            fields_add(&app->middle_data,
                "(tracee stopped by signal)", 1, 0, DETAIL_NONE, -1);
        }
    } else {
        /* ── Software 路径: 有界单步采样 ──
         * 在无 Intel PT 硬件的环境 (WSL2 / 旧 CPU / VM) 使用。
         * 每个 PTRACE_SINGLESTEP 阻塞 ~μs-ms, 总时间由 max_steps 和
         * timeout_ms 双重约束。正常情况下 1000 步 ≈ 0.5-1 秒。       */
        fields_add(&app->middle_data,
            "SW Step: single-step loop (max 1000 steps / 2000ms)...", 1, 0, DETAIL_NONE, -1);

        int steps = sw_trace_record_steps(tctx, app->debug, 1000, 2000);

        if (steps < 0) {
            fields_add(&app->middle_data,
                "(recording failed — tracee may have exited)", 1, 0, DETAIL_NONE, -1);
        } else if (steps == 0) {
            fields_add(&app->middle_data,
                "(0 steps recorded — tracee may be blocked on syscall)", 1, 0, DETAIL_NONE, -1);
        } else {
            snprintf(buf, sizeof(buf), "Recorded %d instruction samples.", steps);
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        }
    }

    /* ══════════════════════════════════════════════════════════════════
     * 停止 & 解码
     * ══════════════════════════════════════════════════════════════════ */
    int nsamples = tb->stop(tctx);
    snprintf(buf, sizeof(buf), "Trace stopped. %d samples collected.", nsamples);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

    tb->decode(tctx, app->adb, sid, &app->middle_data);
    tb->free_ctx(tctx);

    /* 显示覆盖率报告 */
    trace_coverage_report(app->adb, sid, &app->middle_data);

    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* Heap Trace — 堆事件追踪                                              */
/* ================================================================== */

int btn_heaptrace_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "Heap Trace",
            "Not attached.\n\nAttach to a process first (Debug → Attach).");
        app->need_render = 1; return 0;
    }
    if (!app->adb) {
        tui_show_popup(app, "Heap Trace", "DB not ready.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 开始堆追踪 */
    extern int heap_trace_start(struct DebugState*, AnalysisDB*, Elf64_Ctx*, void**);
    extern int heap_trace_stop(void*, struct DebugState*);
    extern int heap_trace_flush_db(void*, AnalysisDB*, int);
    extern void heap_trace_free(void*);

    void *htx = NULL;
    if (heap_trace_start(app->debug, app->adb, app->elf, &htx) != 0) {
        fields_add(&app->middle_data, "(heap trace start failed)", 0, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1;
        return 0;
    }

    fields_add(&app->middle_data, "=== Heap Trace ===", 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "Trace STARTED.", 1, 0, DETAIL_NONE, -1);

    /* 创建 DB session 并简化为 snapshot 模式: 立即停止, 刷新到 DB */
    int sid = heap_session_begin(app->adb, app->debug->pid, "trace");

    int nevents = heap_trace_stop(htx, app->debug);
    heap_trace_flush_db(htx, app->adb, sid);

    char buf[200];
    snprintf(buf, sizeof(buf), "Recorded %d heap events → session #%d", nevents, sid);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

    /* 显示时间轴 */
    extern int heap_replay_timeline(AnalysisDB*, int, PanelData*);
    heap_replay_timeline(app->adb, sid, &app->middle_data);

    heap_trace_free(htx);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* Heap Replay — 堆事件回放                                             */
/* ================================================================== */

int btn_heapreplay_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->adb) {
        tui_show_popup(app, "Heap Replay", "DB not ready.");
        app->need_render = 1; return 0;
    }

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 获取最近的 heap event session */
    sqlite3 *c = (sqlite3 *)db_conn(app->adb);
    int sid = -1;
    if (c) {
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "SELECT id FROM heap_sessions ORDER BY id DESC LIMIT 1",
            -1, &st, NULL);
        if (st) {
            if (sqlite3_step(st) == SQLITE_ROW)
                sid = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
        }
    }

    extern int heap_replay_timeline(AnalysisDB*, int, PanelData*);
    extern int heap_replay_stats(AnalysisDB*, int, PanelData*);

    fields_add(&app->middle_data, "=== Heap Replay ===", 0, 0, DETAIL_NONE, -1);

    if (sid > 0) {
        heap_replay_timeline(app->adb, sid, &app->middle_data);
        heap_replay_stats(app->adb, sid, &app->middle_data);
    } else {
        fields_add(&app->middle_data, "(no heap trace sessions found)", 1, 0, DETAIL_NONE, -1);
    }

    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* Binary Diff — 二进制差异比对                                         */
/* ================================================================== */

int btn_bindiff_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->adb) {
        tui_show_popup(app, "BinDiff", "DB not available.\nImport ELF first, then load second binary.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    fields_add(&app->middle_data, "=== Binary Diff ===", 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "(Select a function in another DB to compare)", 1, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "Usage:", 1, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "  1. Import ELF #1 → DB", 2, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "  2. Import ELF #2 → another DB", 2, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "  3. Select function → BinDiff with matching", 2, 0, DETAIL_NONE, -1);

    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* Symbolic — angr 符号执行桥接                                         */
/* ================================================================== */

int btn_symbolic_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->adb) {
        tui_show_popup(app, "Symbolic", "DB not available.");
        app->need_render = 1; return 0;
    }

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    extern int symbolic_explore(const char*, uint64_t, uint64_t, PanelData*);
    extern int symbolic_find_input(const char*, uint64_t, int, PanelData*);

    uint64_t target = 0;
    /* 使用中间面板选中的地址 */
    PanelData *src = &app->middle_data;
    if (src->count > 0 && src->cursor >= 0 && src->cursor < src->count) {
        if (src->fields[src->cursor].detail_index > 0)
            target = (uint64_t)src->fields[src->cursor].detail_index;
    }
    if (target == 0) {
        Elf64_Ehdr *ehdr = elf_get_ehdr(app->elf);
        target = ehdr->e_entry;
    }

    symbolic_explore(app->elf->filename, target, 0, &app->middle_data);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* Decompile — 地址为中心的运行时反编译 (需要 attach 进程)              */
/*                                                                     */
/* 核心逻辑: 静态 ELF 地址 + 运行时加载基址 = 真实内存地址             */
/*   load_base = /proc/PID/maps 中可执行段首地址 - 第一个 PT_LOAD vaddr */
/*   真实地址 = load_base + 静态地址 (DB 中的地址)                      */
/* ================================================================== */

int btn_decompile_action(TuiApp *app)
{
    if (!app) return -1;

    /* ── 前提 1: 必须 attach 到进程 ── */
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "Decompile — Not Attached",
            "Decompile requires a live process.\n\n"
            "1. Expand 'Debug' in the left panel\n"
            "2. Click 'Attach' → enter target PID\n"
            "3. Then click 'Decompile'\n\n"
            "Real addresses (after ASLR) can only be\n"
            "resolved when attached to a running process.");
        app->need_render = 1; return 0;
    }

    /* ── 前提 2: DB 必须就绪 ── */
    if (!app->adb) {
        tui_show_popup(app, "Decompile", "DB not ready.\nImport ELF first.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    /* ── 计算运行时加载基址 ── */
    extern uint64_t decompile_load_base;  /* decompile.c 中的全局变量 */
    decompile_load_base = 0;

    {
        /* 获取 ELF 第一个 PT_LOAD 的虚拟地址 */
        Elf64_Ehdr *ehdr = elf_get_ehdr(app->elf);
        uint64_t first_load_vaddr = 0;
        int found = 0;
        for (int i = 0; i < ehdr->e_phnum && !found; i++) {
            Elf64_Phdr *ph = elf_get_phdr(app->elf, i);
            if (ph && ph->p_type == 1 /* PT_LOAD */) {  /* PT_LOAD */
                first_load_vaddr = ph->p_vaddr;
                found = 1;
            }
        }

        /* 从 /proc/PID/maps 获取可执行段的首地址 */
        char mappath[64];
        snprintf(mappath, sizeof(mappath), "/proc/%d/maps", app->debug->pid);
        FILE *mf = fopen(mappath, "r");
        if (mf) {
            char line[512];
            while (fgets(line, sizeof(line), mf)) {
                uint64_t s, e; char perms[8], path[256] = "";
                int nf = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &s, &e, perms, path);
                if (nf >= 3 && perms[2] == 'x') {
                    /* 找到第一个可执行段 → 这就是 text 段在内存中的起始地址 */
                    decompile_load_base = s - first_load_vaddr;
                    break;
                }
            }
            fclose(mf);
        }
    }

    /* 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    parse_decompile(app->elf, 0, &app->middle_data);
    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ================================================================== */
/* RtDecomp — 运行时感知反编译                                          */
/* ================================================================== */

int btn_rtdecomp_action(TuiApp *app)
{
    if (!app) return -1;
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "Runtime Decompile",
            "No debug session active.\n\n"
            "Attach to a running process first (Debug -> Attach),\n"
            "then single-step a few times to capture register state.\n"
            "RtDecomp uses runtime GOT values + register snapshots + /proc/maps\n"
            "to resolve indirect calls and data references.");
        app->need_render = 1; return 0;
    }
    if (!app->adb) {
        tui_show_popup(app, "Runtime Decompile", "DB not available.\nImport ELF first.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0;
        app->middle_data.scroll = 0;
    }

    /* 一键全解析: 节地址映射 + GOT解析 + 间接调用 + 数据引用 */
    rt_resolve_all(app->debug, app->elf, app->adb, &app->middle_data);

    /* 如果有选中地址, 自动反编译该函数 */
    uint64_t target = 0;
    if (app->middle_data.count > 0 && app->middle_data.cursor < app->middle_data.count)
        target = (uint64_t)app->middle_data.fields[app->middle_data.cursor].detail_index;

    if (target > 0x1000) {
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        rt_decompile_function(app->adb, target, &app->middle_data);
    } else {
        /* 使用 entry point */
        Elf64_Ehdr *ehdr = elf_get_ehdr(app->elf);
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        rt_decompile_function(app->adb, ehdr->e_entry, &app->middle_data);
    }

    app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}
