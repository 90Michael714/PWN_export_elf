/*
 * tui_colors.h — TUI 颜色方案定义
 */

#ifndef TUI_COLORS_H
#define TUI_COLORS_H

/* 通用前景色 RGB */
#define COLOR_WHITE       0xFFFFFF
#define COLOR_BLACK       0x000000
#define COLOR_YELLOW      0xFFFF00
#define COLOR_CYAN        0x00FFFF
#define COLOR_LIGHT_CYAN  0x00CCCC
#define COLOR_MAGENTA     0xFF00FF
#define COLOR_GRAY        0x808080
#define COLOR_DARK_GRAY   0x404040
#define COLOR_BRIGHT_GRAY 0xC0C0C0

/* 专用背景色 */
#define BG_STATUS_BAR    0x000080   /* 状态栏深蓝背景 */
#define BG_HIGHLIGHT     0x00AAAA   /* 选中项青背景 */
#define BG_HIGHLIGHT_DIM 0x005555   /* 选中项暗青背景 */

/* 面板边框颜色 */
#define BORDER_ACTIVE    0x00DDDD   /* 活动面板亮青 */
#define BORDER_INACTIVE  0x666666   /* 非活动面板灰色 */

/* 语义颜色 */
#define FG_FIELD_NAME    COLOR_YELLOW      /* 字段名 */
#define FG_FIELD_VALUE   COLOR_WHITE       /* 字段值 */
#define FG_ADDRESS       COLOR_LIGHT_CYAN  /* 地址值 */
#define FG_HEADING       COLOR_CYAN        /* 标题 */
#define FG_SPECIAL       COLOR_MAGENTA     /* 特殊标记值 */

#endif
