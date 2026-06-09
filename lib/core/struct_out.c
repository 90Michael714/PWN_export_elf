/*
 * struct_out.c — 结构化输出辅助函数实现
 */

#include "core/struct_out.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* PanelData 扩展: 结构化字段数组 */
typedef struct {
    StructField *sf;
    int          count;
    int          cap;
} PanelStructs;

/* 存储在 PanelData 中 (通过预留指针) — 简化: 全局哈希表 */

#define MAX_PANELS 16
static PanelData  *panel_keys[MAX_PANELS];
static PanelStructs panel_vals[MAX_PANELS];
static int panel_count = 0;

static PanelStructs* find_structs(const PanelData *pd)
{
    for (int i = 0; i < panel_count; i++)
        if (panel_keys[i] == pd) return &panel_vals[i];
    return NULL;
}

static PanelStructs* ensure_structs(PanelData *pd)
{
    PanelStructs *ps = find_structs(pd);
    if (ps) return ps;
    if (panel_count >= MAX_PANELS) return NULL;
    ps = &panel_vals[panel_count];
    panel_keys[panel_count] = (PanelData*)pd;
    panel_count++;
    return ps;
}

int panel_add_struct(PanelData *pd, const StructField *sf)
{
    if (!pd || !sf) return -1;
    PanelStructs *ps = ensure_structs(pd);
    if (!ps) return -1;

    /* 扩展容量 */
    if (ps->count >= ps->cap) {
        ps->cap = ps->cap ? ps->cap * 2 : 64;
        ps->sf = realloc(ps->sf, (size_t)ps->cap * sizeof(StructField));
    }

    /* 复制结构化数据 */
    ps->sf[ps->count] = *sf;

    /* 生成对应的格式化文本行 */
    char text[256];
    switch (sf->kind) {
        case SF_DISASM: {
            char hx[48] = ""; int hp = 0;
            for (int b = 0; b < sf->data.disasm.nb && hp < 42; b++)
                hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp,
                              "%02x ", sf->data.disasm.bytes[b]);
            snprintf(text, sizeof(text), "  0x%lx: %-24s %-8s %s",
                     (unsigned long)sf->data.disasm.addr, hx,
                     sf->data.disasm.mnemonic, sf->data.disasm.ops);
            break;
        }
        case SF_REG:
            snprintf(text, sizeof(text), "%-4s 0x%llx  %s",
                     sf->data.reg.name, (unsigned long long)sf->data.reg.value,
                     sf->data.reg.annotation);
            break;
        case SF_GOT:
            snprintf(text, sizeof(text), "GOT[0x%lx] → %s %s",
                     (unsigned long)sf->data.got.got_addr,
                     sf->data.got.sym_name,
                     sf->data.got.is_lazy ? "(lazy)" : "(resolved)");
            break;
        case SF_SYMREF:
            if (sf->data.sym.offset)
                snprintf(text, sizeof(text), "%s+0x%lx",
                         sf->data.sym.sym, (long)sf->data.sym.offset);
            else
                snprintf(text, sizeof(text), "%s", sf->data.sym.sym);
            break;
        case SF_STACK:
            snprintf(text, sizeof(text), "#%d  0x%lx → %s+0x%lx",
                     sf->data.stack.frame_no,
                     (unsigned long)sf->data.stack.ret_addr,
                     sf->data.stack.sym_name,
                     (long)sf->data.stack.offset);
            break;
        case SF_VMMAP:
            snprintf(text, sizeof(text), "0x%lx-0x%lx %6luK %s %s",
                     (unsigned long)sf->data.vmmap.start,
                     (unsigned long)sf->data.vmmap.end,
                     (unsigned long)sf->data.vmmap.size / 1024,
                     sf->data.vmmap.perms, sf->data.vmmap.path);
            break;
        default:
            text[0] = '\0';
            break;
    }

    /* 追加到 PanelData */
    if (text[0])
        fields_add(pd, text, 1, 1, DETAIL_NONE, ps->count);
    else
        fields_add(pd, "(struct)", 1, 0, DETAIL_NONE, ps->count);

    ps->count++;
    return ps->count - 1;
}

const StructField* panel_get_struct(const PanelData *pd, int index)
{
    PanelStructs *ps = find_structs(pd);
    if (!ps || index < 0 || index >= ps->count) return NULL;
    return &ps->sf[index];
}

void panel_structs_free(PanelData *pd)
{
    for (int i = 0; i < panel_count; i++) {
        if (panel_keys[i] == pd) {
            free(panel_vals[i].sf);
            /* 压缩数组 */
            panel_keys[i] = panel_keys[panel_count - 1];
            panel_vals[i] = panel_vals[panel_count - 1];
            panel_count--;
            return;
        }
    }
}
