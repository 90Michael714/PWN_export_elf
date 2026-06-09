/*
 * btn_fuzzer.c — Fuzzer 按钮: 配置 → 执行 → 结果展示
 *
 * 流程:
 *   1. 读取当前选中的函数地址 (从符号表/当前节)
 *   2. 弹窗展示配置 (目标地址/参数/策略/迭代次数)
 *   3. 阻塞式执行 fuzz_run(), 每 100 轮更新进度弹窗
 *   4. 完成后展示 crash 列表和统计
 *
 * 依赖: fuzz_engine.h + fuzz_mutate.c + fuzz_engine.c
 *       需要 pthread (Worker 线程, 避免 TUI 假死)
 */
#define _GNU_SOURCE
#include "tui.h"
#include "tui_buttons.h"
#include "core/fuzz_engine.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

/* ── 全局: fuzz 运行状态 (跨线程共享) ── */
static FuzzStats   g_fuzz_stats;
static FuzzCrash   g_fuzz_crashes[128];
static int         g_fuzz_crash_count = 0;
static int         g_fuzz_running = 0;
static int         g_fuzz_paused  = 0;
static pthread_t   g_fuzz_thread;
static FuzzConfig  g_fuzz_cfg;

/* ── 进度回调 (从 fuzz_engine 调用) ── */
static void on_progress(const FuzzStats *s, void *user) {
    TuiApp *app = (TuiApp *)user;
    memcpy(&g_fuzz_stats, s, sizeof(FuzzStats));
    /* 每 200 轮刷新一次 TUI */
    if (s->total_iterations % 200 == 0 && app) {
        char status[512];
        snprintf(status, sizeof(status),
                 "Fuzzer Running\n\n"
                 "Progress:  %d / %d iterations\n"
                 "Crashes:   %d total, %d unique\n"
                 "Speed:     %d exec/s\n\n"
                 "Mutations:\n"
                 "  BitFlip: %d  ByteFlip: %d  Arith: %d\n"
                 "  Havoc:   %d  Interest: %d\n\n"
                 "Press [Enter] to stop",
                 s->total_iterations, g_fuzz_cfg.max_iterations,
                 s->total_crashes, s->unique_crashes,
                 s->execs_per_second,
                 s->mut_bitflip_hits, s->mut_byteflip_hits,
                 s->mut_arith_hits, s->mut_interesting_hits,
                 s->mut_havoc_hits);
        tui_show_popup(app, "Fuzzer", status);
    }
}

/* ── crash 回调 ── */
static void on_crash(const FuzzCrash *c, void *user) {
    (void)user;
    if (g_fuzz_crash_count < 128)
        memcpy(&g_fuzz_crashes[g_fuzz_crash_count++], c, sizeof(FuzzCrash));
}

/* ── Worker 线程入口 ── */
static void *fuzz_thread(void *arg) {
    TuiApp *app = (TuiApp *)arg;
    g_fuzz_running = 1;
    g_fuzz_crash_count = 0;
    memset(&g_fuzz_stats, 0, sizeof(g_fuzz_stats));

    fuzz_run(&g_fuzz_cfg, on_progress, on_crash, app);

    g_fuzz_running = 0;
    return NULL;
}

/* ── 显示 Crash 列表弹窗 ── */
static void show_crash_list(TuiApp *app) {
    if (g_fuzz_crash_count == 0) {
        tui_show_popup(app, "Fuzzer Result",
                       "Fuzzing completed.\n\n"
                       "No crashes found.\n"
                       "Try increasing iterations or enabling more strategies.");
        return;
    }

    char buf[4096];
    int pos = snprintf(buf, sizeof(buf),
                       "Fuzzer Complete!\n\n"
                       "Iterations: %d  Crashes: %d total, %d unique\n"
                       "Speed:      %d exec/s\n\n"
                       "─── Crash List ───\n\n",
                       g_fuzz_stats.total_iterations,
                       g_fuzz_stats.total_crashes, g_fuzz_stats.unique_crashes,
                       g_fuzz_stats.execs_per_second);

    /* 去重显示 (只显示 unique crashes) */
    int shown = 0;
    for (int i = 0; i < g_fuzz_crash_count && pos < 3800; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (fuzz_crash_is_duplicate(&g_fuzz_crashes[i], &g_fuzz_crashes[j]))
            { dup = 1; break; }
        if (dup) continue;

        FuzzCrash *c = &g_fuzz_crashes[i];
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "#%d  %s  RIP=0x%lx\n"
                        "    Input(%zuB): ",
                        shown + 1, c->crash_type,
                        (unsigned long)c->rip_snapshot,
                        c->input_size);

        /* hex dump of first 16 bytes of input */
        for (size_t b = 0; b < c->input_size && b < 16 && pos < 4050; b++)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                           "%02X ", c->input[b]);
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n\n");
        shown++;
    }

    if (g_fuzz_crash_count > shown) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        "... (%d duplicate crashes omitted)\n",
                        g_fuzz_crash_count - shown);
    }

    snprintf(buf + pos, sizeof(buf) - (size_t)pos,
             "\n─── Exploitability ───\n"
             "[*] Review unique crashes above\n"
             "[*] Check register state at crash time\n"
             "[*] Use the debugger to reproduce and inspect");

    tui_show_popup(app, "Fuzzer Result", buf);
}

/* ── 配置弹窗 → 启动 fuzz ── */
static void start_fuzz_config(TuiApp *app)
{
    /* 从当前上下文获取目标地址 */
    uint64_t target = 0;
    if (app->elf) {
        /* 尝试获取当前选中节的入口地址 */
        int shnum = (int)((Elf64_Ehdr*)app->elf->map)->e_shnum;
        for (int i = 0; i < shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(app->elf, i);
            if (sh && (sh->sh_flags & SHF_EXECINSTR) && sh->sh_size > 0) {
                target = sh->sh_addr;
                break;
            }
        }
    }

    if (target == 0) {
        tui_show_popup(app, "Fuzzer Error",
                       "No executable section found.\n"
                       "Open an ELF file with code sections first.");
        return;
    }

    /* 初始化配置 */
    fuzz_config_init(&g_fuzz_cfg);
    g_fuzz_cfg.target_addr   = target;
    g_fuzz_cfg.input_max_size = 256;
    g_fuzz_cfg.max_iterations = 2000;
    g_fuzz_cfg.strategy_mask  = FUZZ_MUTATE_HAVOC | FUZZ_MUTATE_BITFLIP
                               | FUZZ_MUTATE_INTERESTING;
    /* 默认: rdi = input buffer, rsi = input size */
    g_fuzz_cfg.args[0].is_input  = 1;
    g_fuzz_cfg.args[1].is_length = 1;

    /* 配置摘要弹窗 */
    char cfg_msg[1024];
    snprintf(cfg_msg, sizeof(cfg_msg),
             "Fuzzer Configuration\n\n"
             "Target:     0x%lx\n"
             "Input size: %zu bytes\n"
             "Strategies: HAVOC + BITFLIP + INTERESTING\n"
             "Iterations: %d\n"
             "Args:       rdi=input_buf, rsi=input_len\n\n"
             "Press [s] to START\n"
             "Press [q] to Cancel",
             (unsigned long)g_fuzz_cfg.target_addr,
             g_fuzz_cfg.input_max_size,
             g_fuzz_cfg.max_iterations);

    tui_show_popup(app, "Fuzzer Config", cfg_msg);
}

/* ── 停止 fuzz ── */
static void stop_fuzz(void) {
    if (!g_fuzz_running) return;
    fuzz_request_stop();
    if (g_fuzz_thread) {
        pthread_join(g_fuzz_thread, NULL);
        g_fuzz_thread = 0;
    }
}

/* ── 按钮 action ── */
int btn_fuzzer_action(TuiApp *app)
{
    if (g_fuzz_running) {
        /* Fuzzer 正在运行 → 显示状态 */
        char status[512];
        snprintf(status, sizeof(status),
                 "Fuzzer Running\n\n"
                 "Progress:  %d / %d\n"
                 "Crashes:   %d (%d unique)\n"
                 "Speed:     %d exec/s\n\n"
                 "Press [s] to STOP\n"
                 "Press [q] to Cancel",
                 g_fuzz_stats.total_iterations, g_fuzz_cfg.max_iterations,
                 g_fuzz_stats.total_crashes, g_fuzz_stats.unique_crashes,
                 g_fuzz_stats.execs_per_second);
        tui_show_popup(app, "Fuzzer", status);
        app->need_render = 1;
        return 0;
    }

    /* Fuzzer 未运行 → 显示配置 → 等待用户按键启动 */
    start_fuzz_config(app);
    app->need_render = 1;
    return 0;
}

/* ── 按键处理 (从 tui_input.c 的 handle_key 中调用) ── */
int btn_fuzzer_handle_key(TuiApp *app, int key)
{
    if (!g_fuzz_running) {
        if (key == 's' || key == 'S') {
            /* 启动 fuzz 线程 */
            pthread_create(&g_fuzz_thread, NULL, fuzz_thread, app);
            tui_show_popup(app, "Fuzzer", "Starting fuzzer...\n\nPress [Enter] to check progress.");
            app->need_render = 1;
            return 1;
        }
        return 0;
    }

    /* 正在运行 */
    if (key == 's' || key == 'S' || key == NCKEY_ENTER) {
        stop_fuzz();
        /* 等待线程结束 */
        struct timespec ts = {0, 100000000}; /* 100ms */
        nanosleep(&ts, NULL);
        show_crash_list(app);
        app->need_render = 1;
        return 1;
    }

    return 0;
}

/* ── 查询 fuzzer 是否正在运行 (供 tui_status.c 显示状态) ── */
int btn_fuzzer_is_running(void) { return g_fuzz_running; }
int btn_fuzzer_is_paused(void)  { return g_fuzz_paused; }
void btn_fuzzer_get_stats(FuzzStats *out) {
    if (out) memcpy(out, &g_fuzz_stats, sizeof(FuzzStats));
}
