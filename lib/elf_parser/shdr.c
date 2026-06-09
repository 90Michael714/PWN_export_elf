/*
 * shdr.c — Section Headers 解析
 *
 * 解析 Section Header Table，列出所有节并提供单个节的详细展开。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_shdr_list(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int shnum = ehdr->e_shnum;
    char flags_buf[32];

    fields_add(pd, "=== Section Headers ===", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        const char *name = elf_section_name(ctx, i);
        char buf[256];

        /* 节名称 + 类型 + 标志 */
        snprintf(buf, sizeof(buf), "[%02d] %-24s  %s  %s  size=0x%lX",
                 i, name,
                 elf_sh_type_str(sh->sh_type),
                 elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf)),
                 (unsigned long)sh->sh_size);
        fields_add(pd, buf, 0, 1, DETAIL_SHDR, i);
    }

    return pd->count;
}

int parse_shdr_detail(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *name = elf_section_name(ctx, shdr_idx);
    char flags_buf[32];
    char buf[256];

    snprintf(buf, sizeof(buf), "=== Section [%02d]: %s ===", shdr_idx, name);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_name:      0x%08X (\"%s\")",
             sh->sh_name, name);
    fields_add(pd, buf, 1, 1, DETAIL_SHDR, shdr_idx);

    snprintf(buf, sizeof(buf), "sh_type:      0x%08X — %s",
             sh->sh_type, elf_sh_type_str(sh->sh_type));
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf));
    snprintf(buf, sizeof(buf), "sh_flags:     0x%lX (%s)",
             (unsigned long)sh->sh_flags, flags_buf);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addr:      0x%lX",
             (unsigned long)sh->sh_addr);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_offset:    0x%lX (%lu bytes)",
             (unsigned long)sh->sh_offset, (unsigned long)sh->sh_offset);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_size:      0x%lX (%lu bytes)",
             (unsigned long)sh->sh_size, (unsigned long)sh->sh_size);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_link:      %d", sh->sh_link);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_info:      %d", sh->sh_info);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addralign: 0x%lX",
             (unsigned long)sh->sh_addralign);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_entsize:   0x%lX (%lu)",
             (unsigned long)sh->sh_entsize, (unsigned long)sh->sh_entsize);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 解释 sh_link / sh_info 含义 */
    fields_add(pd, "--- sh_link/sh_info interpretation ---", 1, 0, DETAIL_NONE, -1);
    switch (sh->sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM:
            snprintf(buf, sizeof(buf), "sh_link=%d -> String table section [%d]",
                     sh->sh_link, sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            snprintf(buf, sizeof(buf), "sh_info=%d -> First non-local symbol index",
                     sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            break;
        case SHT_RELA:
        case SHT_REL:
            snprintf(buf, sizeof(buf), "sh_link=%d -> Symbol table section [%d]",
                     sh->sh_link, sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            snprintf(buf, sizeof(buf), "sh_info=%d -> Target section index [%d]",
                     sh->sh_info, sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            break;
        case SHT_DYNAMIC:
            snprintf(buf, sizeof(buf), "sh_link=%d -> String table used by .dynamic",
                     sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            break;
        case SHT_HASH:
        case SHT_GNU_HASH:
            snprintf(buf, sizeof(buf), "sh_link=%d -> Symbol table for hash",
                     sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            break;
        default:
            fields_add(pd, "(no special interpretation for this type)",
                       2, 0, DETAIL_NONE, -1);
            break;
    }

    return pd->count;
}
