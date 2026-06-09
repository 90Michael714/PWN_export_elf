/*
 * dynamic.c — 动态节解析 (.dynamic)
 *
 * 解析 .dynamic 节中的动态链接信息，包括依赖库、符号表地址、重定位信息等。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_dynamic(Elf64_Ctx *ctx, PanelData *pd)
{
    /* 查找 .dynamic 节 */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int shnum = ehdr->e_shnum;

    Elf64_Shdr *dyn_shdr = NULL;

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (sh->sh_type == SHT_DYNAMIC) {
            dyn_shdr = sh;
            break;
        }
    }

    if (!dyn_shdr) {
        /* 尝试从 Program Headers 找 */
        int phnum = ehdr->e_phnum;
        for (int i = 0; i < phnum; i++) {
            Elf64_Phdr *ph = elf_get_phdr(ctx, i);
            if (ph->p_type == PT_DYNAMIC) {
                /* 动态节以文件偏移方式存在 */
                dyn_shdr = (Elf64_Shdr*)(ctx->map + ph->p_offset);
                /* 这不是真正的 shdr，只说明找到位置 */
                fields_add(pd, "(Dynamic section found via PT_DYNAMIC)",
                           0, 0, DETAIL_NONE, -1);
                fields_add(pd, "(Could not locate SHT_DYNAMIC section header)",
                           0, 0, DETAIL_NONE, -1);
                return pd->count;
            }
        }
        fields_add(pd, "(No .dynamic section found)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    int entry_count = dyn_shdr->sh_size / sizeof(Elf64_Dyn);
    Elf64_Dyn *dyns = (Elf64_Dyn*)(ctx->map + dyn_shdr->sh_offset);

    /* 找到关联的字符串表 */
    Elf64_Off stroff = 0;
    Elf64_Shdr *str_shdr = elf_get_shdr(ctx, dyn_shdr->sh_link);
    if (str_shdr) stroff = str_shdr->sh_offset;

    char buf[256];
    snprintf(buf, sizeof(buf), "=== .dynamic (%d entries) ===", entry_count);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < entry_count; i++) {
        Elf64_Dyn *dyn = &dyns[i];
        const char *tag_name = elf_d_tag_str(dyn->d_tag);

        if (dyn->d_tag == DT_NULL) {
            snprintf(buf, sizeof(buf), "[%3d] DT_NULL (end of .dynamic)", i);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            break;
        }

        /* 根据 tag 类型决定如何显示值 */
        switch (dyn->d_tag) {
            case DT_NEEDED:
            case DT_SONAME:
            case DT_RPATH:
            case DT_RUNPATH:
                if (stroff) {
                    const char *str = elf_dynstr_get(ctx, stroff, dyn->d_un.d_val);
                    snprintf(buf, sizeof(buf), "[%3d] %-16s = \"%s\"",
                             i, tag_name, str ? str : "(null)");
                } else {
                    snprintf(buf, sizeof(buf), "[%3d] %-16s = 0x%lX",
                             i, tag_name, (unsigned long)dyn->d_un.d_val);
                }
                break;
            default:
                snprintf(buf, sizeof(buf), "[%3d] %-16s = 0x%lX",
                         i, tag_name, (unsigned long)dyn->d_un.d_val);
                break;
        }
        fields_add(pd, buf, 0, 1, DETAIL_DYN, i);
    }

    return pd->count;
}
