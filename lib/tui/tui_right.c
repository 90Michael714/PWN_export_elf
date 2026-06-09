/*
 * tui_right.c — 右面板: 字段详细解释
 *
 * 当中面板的某个字段被选中时，在右面板显示该字段的详细解释、
 * 取值范围、相关概念等信息。
 */

#include "tui.h"
#include "tui_panels.h"
#include "tui_colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void right_panel_init(PanelData *pd)
{
    pd->count = 0;
    pd->capacity = 0;
    pd->fields = NULL;
    pd->cursor = 0;
    pd->scroll = 0;
}

/*
 * Rendering is handled in tui.c via region_lines() / region_border().
 * right_panel_init() provides the data layer.
 */
