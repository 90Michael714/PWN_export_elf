/*
 * tui_status.c — 状态栏
 */

#include "tui.h"
#include "tui_colors.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void tui_set_status(TuiApp *app, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(app->status_text, sizeof(app->status_text), fmt, ap);
    va_end(ap);
    app->need_render = 1;
}

void tui_status_render(TuiApp *app)
{
    struct ncplane *P = notcurses_stdplane(app->nc);
    unsigned tx;
    ncplane_dim_yx(P, NULL, &tx);
    int w = (int)tx;

    ncplane_set_fg_rgb8(P, 255, 255, 255);
    ncplane_set_bg_rgb8(P, 0, 0, 140);

    char hints[] = " [Tab]Switch [j/k]Nav [Enter]Select [h]Back [q]Quit";
    int hl = (int)strlen(hints);
    int avail = w;

    /* 构建完整行: status + 空格填充 + hints */
    char line[600];
    int sl = (int)strlen(app->status_text);

    int max_st = avail - hl - 2;
    if (max_st < 8) max_st = avail - 2;

    int pos = 0;
    if (sl > max_st && max_st > 3) {
        memcpy(line, app->status_text, max_st - 3);
        pos = max_st - 3;
        line[pos++] = '.'; line[pos++] = '.'; line[pos++] = '.';
    } else {
        memcpy(line, app->status_text, sl);
        pos = sl;
    }

    /* 空格填充 */
    int pad = avail - pos - hl;
    if (pad < 1) pad = 1;
    if (pad > 200) pad = 200;
    memset(line + pos, ' ', pad);
    pos += pad;

    /* hints */
    memcpy(line + pos, hints, hl);
    pos += hl;
    line[pos] = '\0';

    ncplane_putstr_yx(P, 0, 0, line);
}
