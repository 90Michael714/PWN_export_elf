/*
 * tui_panels.h — 面板数据操作声明
 */

#ifndef TUI_PANELS_H
#define TUI_PANELS_H

#include "elf_parser.h"

typedef enum {
    PANEL_LEFT = 0,
    PANEL_MIDDLE,
    PANEL_RIGHT,
    PANEL_COUNT
} ActivePanel;

void left_panel_init(PanelData *pd, Elf64_Ctx *ctx);
void left_panel_handle_enter(PanelData *left, PanelData *middle, Elf64_Ctx *ctx);

void middle_panel_init(PanelData *pd);
void middle_panel_handle_enter(PanelData *middle, PanelData *right, Elf64_Ctx *ctx);

void right_panel_init(PanelData *pd);

#endif
