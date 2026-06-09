/*
 * btn_common.c — 统一按钮调度器 (Phase 5)
 *
 * 消除纯转发按钮的重复代码: clear→call→show 模式统一为 ButtonDef 表。
 * 有自定义逻辑的按钮 (Search/Disasm/Registers 等) 保留独立文件。
 */

#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"

extern AnalysisDB *g_active_db;

/* ── 按钮行为描述 ──────────────────────────────────────────────── */

typedef void (*ParserFn)(Elf64_Ctx*, int arg, PanelData*);

typedef struct {
    int       btn_id;
    ParserFn  parser;
    int       arg_int;        /* shdr_idx, -1=不需要 */
    int       target_panel;   /* PANEL_MIDDLE 或 PANEL_RIGHT */
    const char *label;        /* 调试用 */
} ButtonDef;

/* ── 通用执行器 ────────────────────────────────────────────────── */

static int btn_exec(TuiApp *app, const ButtonDef *def)
{
    if (!def || !def->parser) return -1;

    PanelData *target = (def->target_panel == PANEL_RIGHT)
                        ? &app->right_data : &app->middle_data;

    if (target->fields) {
        fields_free(target->fields, target->count);
        target->fields = NULL;
        target->count = 0; target->capacity = 0;
        target->cursor = 0; target->scroll = 0;
        target->scroll_x = 0;
    }

    g_active_db = app->adb;
    def->parser(app->elf, def->arg_int, target);

    if (target->count > 0)
        app->active_panel = (ActivePanel)def->target_panel;
    app->need_render = 1;
    return 0;
}

/* ── 注册表: 纯转发按钮 ────────────────────────────────────────── */

static void _parse_seg_perm_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { (void)a; parse_seg_perm(c, p); }
static void _parse_mem_layout_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { (void)a; parse_mem_layout(c, p); }
static void _parse_attack_surface_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { (void)a; parse_attack_surface(c, p); }
static void _parse_strings_xref_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { (void)a; parse_strings_xref(c, p); }
static void _parse_eh_frame_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { parse_eh_frame(c, a, p); }
static void _parse_vuln_report_wrap(Elf64_Ctx *c, int a, PanelData *p)
    { (void)a; translate_vuln_scan(c, p); }
static const ButtonDef BUTTON_REGISTRY[] = {
    { BTN_SEGPERM,    _parse_seg_perm_wrap,        -1, PANEL_MIDDLE, "SegPerm" },
    { BTN_MEMLAYOUT,  _parse_mem_layout_wrap,      -1, PANEL_MIDDLE, "MemLayout" },
    { BTN_ATKSURFACE, _parse_attack_surface_wrap,  -1, PANEL_MIDDLE, "AtkSurface" },
    { BTN_STRXREF,    _parse_strings_xref_wrap,    -1, PANEL_MIDDLE, "StrXRef" },
    { BTN_EHFRAME,    _parse_eh_frame_wrap,        -1, PANEL_MIDDLE, "EHFrame" },
    { BTN_TRANS_VULN, _parse_vuln_report_wrap,     -1, PANEL_MIDDLE, "VulnReport" },
    { 0, NULL, 0, 0, NULL }  /* sentinel */
};

/* ── 注册表查询 ────────────────────────────────────────────────── */

int btn_registry_dispatch(TuiApp *app, int btn_id)
{
    for (const ButtonDef *d = BUTTON_REGISTRY; d->parser; d++)
        if (d->btn_id == btn_id)
            return btn_exec(app, d);
    return -1;  /* 未找到 */
}
