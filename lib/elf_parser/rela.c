/*
 * rela.c — 重定位表解析 (.rela.* / .rel.*)
 *
 * 解析重定位表节中的重定位条目。x86-64 主要使用 RELA (带显式加数)。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_rela(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *sec_name = elf_section_name(ctx, shdr_idx);
    int machine = ehdr->e_machine;

    if (sh->sh_entsize == 0) {
        fields_add(pd, "(Empty relocation table)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    char buf[256];

    if (sh->sh_type == SHT_RELA) {
        int count = sh->sh_size / sizeof(Elf64_Rela);
        Elf64_Rela *relas = (Elf64_Rela*)(ctx->map + sh->sh_offset);

        snprintf(buf, sizeof(buf), "=== %s (%d RELA entries) ===",
                 sec_name, count);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

        Elf64_Off sym_stroff = 0;
        Elf64_Shdr *sym_shdr = elf_get_shdr(ctx, sh->sh_link);
        if (sym_shdr) {
            Elf64_Shdr *str_shdr = elf_get_shdr(ctx, sym_shdr->sh_link);
            if (str_shdr) sym_stroff = str_shdr->sh_offset;
        }

        for (int i = 0; i < count && i < 2000; i++) {
            Elf64_Rela *rela = &relas[i];
            uint32_t sym_idx = rela->r_info >> 32;
            const char *type_name = elf_reloc_type_str(machine, rela->r_info);

            const char *sym_name = "";
            if (sym_stroff && sym_shdr->sh_entsize > 0) {
                Elf64_Sym *syms = (Elf64_Sym*)(ctx->map + sym_shdr->sh_offset);
                Elf64_Sym *sym = &syms[sym_idx];
                if (sym->st_name) {
                    sym_name = elf_strtab_get(ctx, sym_stroff, sym->st_name);
                }
            }

            snprintf(buf, sizeof(buf),
                     "[%4d] off=0x%lX  type=%-22s sym=%-24s addend=%ld",
                     i, (unsigned long)rela->r_offset, type_name,
                     sym_name[0] ? sym_name : "(null)",
                     (long)rela->r_addend);
            fields_add(pd, buf, 0, 1, DETAIL_RELA, i);
        }
    } else if (sh->sh_type == SHT_REL) {
        int count = sh->sh_size / sizeof(Elf64_Rel);
        Elf64_Rel *rels = (Elf64_Rel*)(ctx->map + sh->sh_offset);

        snprintf(buf, sizeof(buf), "=== %s (%d REL entries) ===",
                 sec_name, count);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

        for (int i = 0; i < count && i < 2000; i++) {
            Elf64_Rel *rel = &rels[i];
            const char *type_name = elf_reloc_type_str(machine, rel->r_info);

            snprintf(buf, sizeof(buf),
                     "[%4d] off=0x%lX  type=%s",
                     i, (unsigned long)rel->r_offset, type_name);
            fields_add(pd, buf, 0, 1, DETAIL_RELA, i);
        }
    } else {
        fields_add(pd, "(Not a relocation section)", 0, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}
