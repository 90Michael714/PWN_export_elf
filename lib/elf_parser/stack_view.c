/*
 * stack_view.c — 栈视图面板 (依赖: debug_worker.h)
 *
 * 显示 RSP 附近的内存内容, 格式:
 *   地址         hex 值 (64-bit)        ASCII     标注
 *   ─────────   ─────────────────────   ────────   ──────────────
 *   0x7fff0020  0x00007f1234567890ab   ........   ← libc+0x12345
 *   0x7fff0028  0x0000000000401234     ...@.4.    ← saved RIP (main+0x10)
 *   0x7fff0030  0x00007fffffffe050     P...____   ← saved RBP
 *
 * 标注规则:
 *   - 值为 0                           → "[zero]"
 *   - 值在已知 libc 范围内             → "libc+0x..."
 *   - 值在主程序代码范围内             → "text+0x..."
 *   - 值等于 RBP                       → "[saved RBP]"
 *   - 值接近 RSP (栈内地址)            → "[stack+0x...]"
 *   - 值在 backtrace 的 RIP 列表中     → "[saved RIP: main+0x10]"
 *   - 值不可读                         → "(unmapped)"
 *
 * 依赖:
 *   #include "core/debug_worker.h" (debug_readmem + ds->regs)
 *   #include "elf_parser.h" (符号表)
 *
 * 符合 COORDINATION.md:
 *   接口: int render_stack_view(DebugState *ds, Elf64_Ctx *ctx, PanelData *pd);
 */
#include "core/debug_worker.h"
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* ================================================================== */
/* 地址空间识别                                                       */
/* ================================================================== */

typedef struct {
    uint64_t text_start, text_end;
    uint64_t libc_start, libc_end;
    uint64_t ld_start,   ld_end;
    uint64_t stack_low,  stack_high;
} mem_layout_t;

/** 从 /proc/pid/maps 读取内存布局 (用于标注) */
static int get_memory_layout(DebugState *ds, mem_layout_t *ml)
{
    memset(ml, 0, sizeof(*ml));
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        uint64_t s, e; char p[5], f[256]="";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &s, &e, p, f) < 3) continue;

        if (p[2] == 'x') {
            if (strstr(f, "libc"))      { ml->libc_start = s; ml->libc_end = e; }
            else if (strstr(f, "ld-"))  { ml->ld_start   = s; ml->ld_end   = e; }
        }
        if (!ml->text_start && s > 0x400000 && strstr(f, "/")) {
            ml->text_start = s; ml->text_end = e; /* 主程序 */
        }
        if (strstr(f, "[stack]")) { ml->stack_low = s; ml->stack_high = e; }
    }
    fclose(fp);
    return 0;
}

/** 标注一个地址值 */
static const char *annotate_value(uint64_t val, const mem_layout_t *ml,
                                   uint64_t rbp, const uint64_t *bt_rips, int bt_count,
                                   char *buf, size_t sz)
{
    if (val == 0) { snprintf(buf, sz, "[zero]"); return buf; }
    if (val == rbp) { snprintf(buf, sz, "[saved RBP]"); return buf; }

    /* 检查是否匹配回溯中的返回地址 */
    for (int i = 0; i < bt_count; i++) {
        if (val == bt_rips[i]) {
            snprintf(buf, sz, "[saved RIP: frame %d]", i);
            return buf;
        }
    }

    /* 代码段范围 */
    if (ml->text_start && val >= ml->text_start && val < ml->text_end)
        { snprintf(buf, sz, "text+0x%lx", (unsigned long)(val - ml->text_start)); return buf; }
    if (ml->libc_start && val >= ml->libc_start && val < ml->libc_end)
        { snprintf(buf, sz, "libc+0x%lx", (unsigned long)(val - ml->libc_start)); return buf; }
    if (ml->ld_start && val >= ml->ld_start && val < ml->ld_end)
        { snprintf(buf, sz, "ld+0x%lx", (unsigned long)(val - ml->ld_start)); return buf; }

    /* 栈内地址 */
    if (ml->stack_low && val >= ml->stack_low && val < ml->stack_high)
        { snprintf(buf, sz, "stack+0x%lx", (unsigned long)(val - ml->stack_low)); return buf; }

    buf[0] = '\0';
    return buf;
}

/* ================================================================== */
/* 回溯提取 (简化 RBP 链, 获取 saved RIP 列表)                        */
/* ================================================================== */

static int extract_backtrace_addrs(DebugState *ds, uint64_t *rips, int max)
{
    int count = 0;
    uint64_t rbp = ds->regs.rbp;

    /* 当前 RIP */
    if (count < max) rips[count++] = ds->regs.rip;

    for (int i = 0; i < 32 && rbp != 0 && count < max; i++) {
        uint64_t pair[2];
        if (debug_readmem(ds, rbp, pair, 16) != 16) break;
        uint64_t saved_rbp = pair[0];
        uint64_t saved_rip = pair[1];
        if (saved_rip == 0 || saved_rip > 0x7fffffffffffULL) break;
        if (saved_rbp != 0 && saved_rbp <= rbp) break;
        rips[count++] = saved_rip;
        rbp = saved_rbp;
    }
    return count;
}

/* RSP 值传递 (render_stack_view 设置, format_stack_row 使用) */
static uint64_t ds_debug_rsp_value = 0;

/* ================================================================== */
/* 行格式化                                                           */
/* ================================================================== */

static void format_stack_row(uint64_t addr, uint64_t val,
                              const mem_layout_t *ml,
                              uint64_t rbp, const uint64_t *rips, int nrips,
                              char *buf, size_t sz)
{
    char anno[64] = "";
    annotate_value(val, ml, rbp, rips, nrips, anno, sizeof(anno));

    /* ASCII 预览 (小端字节序显示) */
    char ascii[9] = "........";
    uint8_t *b = (uint8_t *)&val;
    for (int i = 0; i < 8; i++)
        if (isprint(b[i])) ascii[i] = (char)b[i];

    /* 标注当前 RSP 位置 */
    const char *marker = "";
    if (addr == ds_debug_rsp_value) marker = " ← RSP";

    if (anno[0])
        snprintf(buf, sz, "0x%lx: 0x%lx  %s  %s%s",
                 (unsigned long)addr, (unsigned long)val, ascii, anno, marker);
    else
        snprintf(buf, sz, "0x%lx: 0x%lx  %s%s",
                 (unsigned long)addr, (unsigned long)val, ascii, marker);
}

/* ================================================================== */
/* 公共接口                                                           */
/* ================================================================== */

int render_stack_view(void *ds_vp, Elf64_Ctx *ctx, PanelData *pd)
{
    DebugState *ds = (DebugState *)ds_vp;
    if (!ds || !pd) return -1;
    (void)ctx;

    debug_getregs(ds);

    uint64_t rsp = ds->regs.rsp;
    uint64_t rbp = ds->regs.rbp;
    ds_debug_rsp_value = rsp;

    /* 获取内存布局 */
    mem_layout_t ml;
    get_memory_layout(ds, &ml);

    /* 获取回溯地址 */
    uint64_t bt_rips[32];
    int nrips = extract_backtrace_addrs(ds, bt_rips, 32);

    /* 读取栈内存范围: RSP-64 到 RSP+192 (16 行 × 16 bytes = 256 字节) */
    #define STACK_ROWS 16
    uint64_t start = (rsp > 64) ? rsp - 64 : rsp;
    uint64_t data[STACK_ROWS * 2]; /* 每个 8 字节读取一个 uint64_t */
    size_t total_bytes = STACK_ROWS * 16;

    /* 尝试批量读取 */
    int read_ok = (debug_readmem(ds, start, data, total_bytes) == (int)total_bytes);

    /* 标题 */
    char buf[256];
    snprintf(buf, sizeof(buf),
             "=== Stack View (PID %d) ===  RSP=0x%lx  RBP=0x%lx",
             ds->pid, (unsigned long)rsp, (unsigned long)rbp);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 列头 */
    fields_add(pd, "Address           Value (64-bit)            ASCII     Annotation",
               1, 0, DETAIL_NONE, -1);
    fields_add(pd, "───────────────   ────────────────────────  ────────  ──────────────",
               1, 0, DETAIL_NONE, -1);

    /* 输出内存行 */
    for (int i = 0; i < STACK_ROWS; i++) {
        uint64_t addr = start + (uint64_t)(i * 8);
        uint64_t val  = 0;

        if (read_ok) {
            val = ((const uint64_t *)data)[i];
        } else {
            /* 逐字节读取 fallback */
            debug_readmem(ds, addr, &val, 8);
        }

        format_stack_row(addr, val, &ml, rbp, bt_rips, nrips, buf, sizeof(buf));
        int indent = 1;
        /* 当前 RSP 行高亮 */
        if (addr == rsp) indent = 1;
        fields_add(pd, buf, indent, 1, DETAIL_NONE, (int)(addr & 0xFFFF));
    }

    /* RSP 指示器 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    /* 统计 */
    snprintf(buf, sizeof(buf),
             "Stack range: 0x%lx - 0x%lx  (%lu bytes shown, 16 slots)",
             (unsigned long)start, (unsigned long)(start + total_bytes),
             (unsigned long)total_bytes);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (!read_ok)
        fields_add(pd, "[!] Partial read — some values may be inaccessible", 1, 0, DETAIL_NONE, -1);

    return pd->count;
}
