/*
 * phdr.c — Program Headers 解析
 *
 * 解析 Program Header Table 中的每个段描述符，显示段类型、权限、内存布局等。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_phdr(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int phnum = ehdr->e_phnum;
    char flags_buf[32];

    if (phnum == 0) {
        fields_add(pd, "(No program headers)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    fields_add(pd, "=== Program Headers ===", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < phnum; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        char buf[256];

        /* 段标题行 */
        snprintf(buf, sizeof(buf), "[%02d] %s  %s",
                 i, elf_p_type_str(ph->p_type),
                 elf_p_flags_str(ph->p_flags, flags_buf, sizeof(flags_buf)));
        fields_add(pd, buf, 0, 1, DETAIL_PHDR, i);

        /* 段详细信息 */
        snprintf(buf, sizeof(buf), "p_offset: 0x%lX",
                 (unsigned long)ph->p_offset);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_vaddr:  0x%lX",
                 (unsigned long)ph->p_vaddr);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_paddr:  0x%lX",
                 (unsigned long)ph->p_paddr);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_filesz: 0x%lX (%lu)",
                 (unsigned long)ph->p_filesz, (unsigned long)ph->p_filesz);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_memsz:  0x%lX (%lu)",
                 (unsigned long)ph->p_memsz, (unsigned long)ph->p_memsz);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_flags:  0x%08X (%s)",
                 ph->p_flags,
                 elf_p_flags_str(ph->p_flags, flags_buf, sizeof(flags_buf)));
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        snprintf(buf, sizeof(buf), "p_align:  0x%lX",
                 (unsigned long)ph->p_align);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        /* 内存映射描述 */
        char map_desc[128] = "";
        if (ph->p_type == PT_LOAD) {
            snprintf(map_desc, sizeof(map_desc),
                     "  -> Memory mapping: 0x%lX-0x%lX (file) / 0x%lX-0x%lX (mem)",
                     (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_filesz),
                     (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_memsz));
            fields_add(pd, map_desc, 1, 0, DETAIL_NONE, -1);
        }
    }

    return pd->count;
}
