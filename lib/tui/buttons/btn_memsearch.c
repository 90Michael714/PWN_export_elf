/* btn_memsearch.c — MemSearch: 中面板=内存段列表, 右面板=段内容hexdump
 *
 * 数据源: vmmap_read() → /proc/<pid>/maps (复用 vmmap_live.c 统一解析)
 * 合并 VMMap 的库标签 + 汇总行, 保留 MemSearch 的自适应单位和 hexdump 交互
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
#include <stdio.h>
#include <string.h>

/* ── 从 vmmap_live.c 复用解析 ─────────────────────────────────────── */

typedef struct {
    uint64_t    start;
    uint64_t    end;
    char        perms[5];
    uint64_t    offset;
    unsigned int dev_major;
    unsigned int dev_minor;
    unsigned long inode;
    char        path[256];
} vmmap_entry_t;

extern int vmmap_read(const struct DebugState *ds,
                      vmmap_entry_t *entries, int *count);

/* ── MemSearch 按钮 ──────────────────────────────────────────────── */

int btn_memsearch_action(TuiApp *app){
    if(!app->debug || !app->debug->attached){
        tui_show_popup(app, "MemSearch",
            "No debug session active.\n\n"
            "Attach to a running process first:\n"
            "  Left panel → Registers → Enter → type PID");
        app->need_render = 1; return 0;
    }

    /* 清空中面板 */
    if(app->middle_data.fields){
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0; app->middle_data.capacity = 0;
        app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    /* ── 标题标签 (保留 MemSearch 原有格式) ── */
    char hdr[128];
    snprintf(hdr, sizeof(hdr),
             "=== Memory Map (PID %d) ===  [Enter] hexdump  [h] back",
             app->debug->pid);
    fields_add(&app->middle_data, hdr, 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "Start-End              Size     Perms  Region",
               1, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "──────────────         ──────── ────── ────────────",
               1, 0, DETAIL_NONE, -1);

    /* ── 通过 vmmap_read() 统一读取 /proc/<pid>/maps ── */
    vmmap_entry_t entries[256];
    int count = 256;
    if (vmmap_read(app->debug, entries, &count) != 0 || count == 0) {
        fields_add(&app->middle_data, "(cannot read /proc/pid/maps)", 1, 0, DETAIL_NONE, -1);
        app->active_panel = PANEL_MIDDLE;
        app->need_render = 1; return 0;
    }

    int seg_idx = 0;
    unsigned long total_kb = 0;

    for (int i = 0; i < count && seg_idx < 256; i++) {
        vmmap_entry_t *e = &entries[i];

        /* 跳过不可读段和内核地址 (保持 MemSearch 原有过滤) */
        if (e->perms[0] != 'r') continue;
        if (e->start >= 0x7FFFFFFFFFFFULL) continue;

        uint64_t sz = e->end - e->start;
        total_kb += (unsigned long)(sz / 1024);

        /* ── 自适应单位 (保留 MemSearch 原有逻辑) ── */
        const char *unit = "B";
        double dsz = (double)sz;
        if     (dsz >= 1024.0*1024*1024) { dsz /= 1024.0*1024*1024; unit = "GB"; }
        else if(dsz >= 1024.0*1024)      { dsz /= 1024.0*1024;      unit = "MB"; }
        else if(dsz >= 1024.0)           { dsz /= 1024.0;            unit = "KB"; }

        /* ── 段名推测 (保留 MemSearch 原有逻辑) ── */
        const char *seg_name = "anon";
        if(e->path[0]){
            char *slash = strrchr(e->path, '/');
            seg_name = slash ? slash + 1 : e->path;
        } else {
            if     (e->perms[1] == 'w' && e->start > 0x600000000000ULL)
                seg_name = "[stack]";
            else if(e->perms[1] == 'w')
                seg_name = "[heap]";
            else if(e->perms[2] == 'x')
                seg_name = "[code]";
            else if(e->perms[1] == '-')
                seg_name = "[ro]";
        }

        /* ── 库标签 (合并 VMMap 的标签特性) ── */
        const char *tag = "";
        if (e->path[0]) {
            if      (strstr(e->path, "[stack]")) tag = " [STACK]";
            else if (strstr(e->path, "[heap]"))  tag = " [HEAP]";
            else if (strstr(e->path, "libc"))    tag = " [LIBC]";
            else if (strstr(e->path, "ld-"))     tag = " [LD]";
            else if (strstr(e->path, "libpthread")) tag = " [PTHREAD]";
            else if (strstr(e->path, "libm"))    tag = " [LIBM]";
            else if (strstr(e->path, "libdl"))   tag = " [LIBDL]";
        }

        char buf[512];
        snprintf(buf, sizeof(buf),
                 "[%d] 0x%lx-0x%lx  %6.1f%s %-6s %s%s",
                 seg_idx,
                 (unsigned long)e->start, (unsigned long)e->end,
                 dsz, unit, e->perms, seg_name, tag);
        fields_add(&app->middle_data, buf, 0, 1, DETAIL_NONE, seg_idx);
        seg_idx++;
    }

    if(seg_idx == 0)
        fields_add(&app->middle_data, "(no readable segments)", 1, 0, DETAIL_NONE, -1);
    else {
        /* ── 汇总行 (合并 VMMap 的总映射量特性) ── */
        char sum[128];
        snprintf(sum, sizeof(sum), "── %d segments, total mapped: %lu KB (%lu MB)",
                 seg_idx, total_kb, total_kb / 1024);
        fields_add(&app->middle_data, sum, 1, 0, DETAIL_NONE, -1);
    }

    if(app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/*
 * memsearch_show_hexdump: 从段列表选段 → 右面板hexdump
 * 被 tui_input.c 的 PANEL_MIDDLE Enter 处理调用
 * (功能保持不变)
 */
int memsearch_show_hexdump(TuiApp *app, const char *seg_line)
{
    if(!app || !app->debug || !seg_line) return -1;

    /* 解析: "[N] 0xSTART-0xEND  ..."  注意前缀有序号 */
    uint64_t start = 0, end = 0;
    const char *p = strstr(seg_line, "0x");
    if (!p) return -1;
    if(sscanf(p, "0x%lx-0x%lx", &start, &end) < 2) return -1;

    /* 限制最多读 4KB */
    uint64_t read_size = end - start;
    if(read_size > 4096) read_size = 4096;
    if(read_size == 0) return -1;

    uint8_t *mem = malloc(read_size);
    if(!mem) return -1;
    int nr = debug_readmem(app->debug, start, mem, read_size);
    if(nr <= 0){ free(mem); return -1; }

    /* 清空右面板 */
    if(app->right_data.fields){
        fields_free(app->right_data.fields, app->right_data.count);
        app->right_data.fields = NULL;
        app->right_data.count = 0; app->right_data.capacity = 0;
        app->right_data.cursor = 0; app->right_data.scroll = 0;
        app->right_data.scroll_x = 0;
    }

    char title[256];
    snprintf(title, sizeof(title),
             "=== Hexdump: 0x%lx-0x%lx ===",
             (unsigned long)start, (unsigned long)(start + nr));
    fields_add(&app->right_data, title, 0, 0, DETAIL_NONE, -1);

    /* 逐行输出 hex+ASCII (16字节/行) */
    char hx[100];
    for(int off = 0; off < nr; off += 16){
        int pos = 0;
        pos += snprintf(hx + pos, sizeof(hx) - (size_t)pos,
                        "0x%lx  ", (unsigned long)(start + off));

        /* hex 部分 */
        for(int b = 0; b < 16; b++){
            if(off + b < nr)
                pos += snprintf(hx + pos, sizeof(hx) - (size_t)pos,
                                "%02x ", mem[off + b]);
            else
                pos += snprintf(hx + pos, sizeof(hx) - (size_t)pos, "   ");
        }
        pos += snprintf(hx + pos, sizeof(hx) - (size_t)pos, " ");

        /* ASCII 部分 */
        for(int b = 0; b < 16 && off + b < nr; b++){
            uint8_t c = mem[off + b];
            pos += snprintf(hx + pos, sizeof(hx) - (size_t)pos, "%c",
                            (c >= 32 && c < 127) ? (char)c : '.');
        }

        fields_add(&app->right_data, hx, 1, 0, DETAIL_NONE, -1);
    }

    free(mem);
    return 0;
}
