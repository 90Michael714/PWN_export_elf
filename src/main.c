/*
 * main.c — ELF TUI Parser 入口
 *
 * 用法: elf-tui <elf64-file>
 *
 * 启动流程:
 * 1. 加载 ELF64 文件
 * 2. 创建 notcurses TUI
 * 3. 进入交互主循环
 */

#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog)
{
    printf("elf-tui — ELF64 TUI Parser\n\n");
    printf("Usage: %s <elf64-file>\n\n", prog);
    printf("Keyboard controls:\n");
    printf("  Tab          Switch active panel\n");
    printf("  j / Down     Move cursor down\n");
    printf("  k / Up       Move cursor up\n");
    printf("  g            Jump to top\n");
    printf("  G            Jump to bottom\n");
    printf("  Enter        Expand selected item\n");
    printf("  q / Esc      Quit\n\n");
    printf("Panel layout:\n");
    printf("  Left (25%%)   — Navigation tree\n");
    printf("  Middle (35%%) — Expanded item details\n");
    printf("  Right (40%%)  — Field explanations\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    const char *filename = argv[1];

    /* 加载 ELF64 文件 */
    Elf64_Ctx *elf = elf_open(filename);
    if (!elf) {
        fprintf(stderr, "Error: Failed to open '%s' "
                "(not found or not a valid ELF64 file)\n", filename);
        return 1;
    }

    /* 创建并运行 TUI */
    TuiApp *app = tui_create(elf);
    if (!app) {
        fprintf(stderr, "Error: Failed to initialize TUI\n");
        elf_close(elf);
        return 1;
    }

    tui_run(app);

    /* 清理 */
    tui_destroy(app);
    elf_close(elf);

    return 0;
}
