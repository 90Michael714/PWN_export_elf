/*
 * strings.c — 字符串表提取工具
 *
 * 从 ELF 字符串表中提取完整的字符串列表，方便 TUI 展示。
 */

#include "elf_parser.h"
#include <stdlib.h>
#include <string.h>

char* elf_strtable_extract(Elf64_Ctx *ctx, Elf64_Off offset, Elf64_Xword size)
{
    if (size == 0 || offset + size > ctx->size) return strdup("(empty)");

    /* 直接复制整个字符串表区域 */
    char *buf = malloc(size + 1);
    memcpy(buf, (char*)(ctx->map + offset), size);
    buf[size] = '\0';

    /* 将中间的 '\0' 替换为换行符 */
    for (Elf64_Xword i = 0; i < size - 1; i++) {
        if (buf[i] == '\0') buf[i] = '\n';
    }
    return buf;
}
