/* btn_vmmap.c — VMMap: 内存映射查看器 (合并原 VMMap + MemSearch 优点)
 *
 * 数据: vmmap_to_panel() → vmmap_read() → /proc/<pid>/maps
 * 显示: MemSearch 风格列标签 + 自适应单位 + VMMap 库标签 + 汇总行
 * 交互: Enter → 右面板 hexdump
 * 分析: 自动检测 RWX段 / libc基址 / ld基址 / 堆范围
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── 孤儿函数: vmmap_live.c 中已实现但未在头文件声明 ──────────────── */
struct DebugState;
typedef struct { uint64_t start, end; char perms[5]; uint64_t offset;
    unsigned int dev_major, dev_minor; unsigned long inode; char path[256]; } vmmap_entry_t;
extern int vmmap_count_rwx(const struct DebugState *ds);
extern int vmmap_find_base(const struct DebugState *ds, const char *lib, uint64_t *base);
extern int vmmap_find_heap(const struct DebugState *ds, uint64_t *start, uint64_t *end);

/* ── VMMap 按钮 ─────────────────────────────────────────────────── */

int btn_vmmap_action(TuiApp *app){
    if(!app->debug){
        app->pid_target=1;app->pid_input_active=1;app->pid_input_pos=0;
        memset(app->pid_input_buf,0,16);
        tui_show_popup(app,"VMMap",
            "Enter target PID:\n\n  _\n\n[Enter]confirm [Esc]cancel");
        app->need_render=1;return 0;
    }
    if(app->middle_data.fields){
        fields_free(app->middle_data.fields,app->middle_data.count);
        app->middle_data.fields=NULL;app->middle_data.count=0;
        app->middle_data.capacity=0;
        app->middle_data.cursor=0;app->middle_data.scroll=0;
    }
    vmmap_to_panel(app->debug, &app->middle_data);

    /* ── 分析摘要: 自动检测关键安全属性 ─────────────────────────── */
    if (app->middle_data.count > 0) {
        char buf[256];

        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data,
            "── Analysis ─────────────────────────────────────────────",
            1, 0, DETAIL_NONE, -1);

        /* 1. RWX 段检测 */
        int rwx = vmmap_count_rwx(app->debug);
        if (rwx > 0) {
            snprintf(buf, sizeof(buf),
                "⚠ WARNING: %d RWX segment(s) — shellcode injection target!",
                rwx);
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        } else {
            fields_add(&app->middle_data,
                "✓ No RWX segments (W^X enforced)", 1, 0, DETAIL_NONE, -1);
        }

        /* 2. 关键库基址 (ASLR 绕过参考) */
        uint64_t base = 0;
        if (vmmap_find_base(app->debug, "libc", &base) == 0) {
            snprintf(buf, sizeof(buf),
                "  libc      base = 0x%lx", (unsigned long)base);
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        }
        if (vmmap_find_base(app->debug, "ld-", &base) == 0) {
            snprintf(buf, sizeof(buf),
                "  ld        base = 0x%lx", (unsigned long)base);
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        }
        if (vmmap_find_base(app->debug, "libpthread", &base) == 0) {
            snprintf(buf, sizeof(buf),
                "  pthread   base = 0x%lx", (unsigned long)base);
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        }

        /* 3. 堆范围 */
        uint64_t heap_start = 0, heap_end = 0;
        if (vmmap_find_heap(app->debug, &heap_start, &heap_end) == 0) {
            snprintf(buf, sizeof(buf),
                "  heap:      0x%lx - 0x%lx  (%lu KB)",
                (unsigned long)heap_start, (unsigned long)heap_end,
                (unsigned long)((heap_end - heap_start) / 1024));
            fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
        }

        /* 4. 提示 */
        fields_add(&app->middle_data,
            "  [Enter]=hexdump  [Space]=new search  →=right panel",
            1, 0, DETAIL_NONE, -1);
    }

    if(app->middle_data.count>0)app->active_panel=PANEL_MIDDLE;
    app->need_render=1;return 0;
}

/* ── VMMap hexdump (合并原 MemSearch hexdump 交互) ────────────────
 * 选中内存段 → Enter → 右面板显示该段前 4KB hexdump
 * 被 tui_input.c 的 PANEL_MIDDLE Enter 处理调用
 */
int vmmap_show_hexdump(TuiApp *app, const char *seg_line)
{
    if(!app || !app->debug || !seg_line) return -1;

    /* 解析: "[N] 0xSTART-0xEND  ..." */
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
