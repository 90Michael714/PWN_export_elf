/*
 * version.c — 版本信息解析 (.gnu.version*)
 *
 * 解析 GNU 符号版本信息，包括版本定义 (Verdef)、版本需求 (Verneed)、
 * 和版本符号表 (Versym)。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_version(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int shnum = ehdr->e_shnum;
    char buf[320];

    /* 查找 Verdef / Verneed 节 */
    int verdef_idx = -1, verneed_idx = -1, versym_idx = -1;
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (sh->sh_type == SHT_GNU_verdef)  verdef_idx = i;
        if (sh->sh_type == SHT_GNU_verneed) verneed_idx = i;
        if (sh->sh_type == SHT_GNU_versym)  versym_idx = i;
    }

    /* ===== 版本定义 (Verdef) ===== */
    if (verdef_idx >= 0) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, verdef_idx);
        fields_add(pd, "=== Version Definitions (.gnu.version_d) ===",
                   0, 0, DETAIL_NONE, -1);

        Elf64_Off offset = 0;
        Elf64_Word stroff = 0;
        Elf64_Shdr *str_shdr = elf_get_shdr(ctx, sh->sh_link);
        if (str_shdr) stroff = str_shdr->sh_offset;

        int vd_count = 0;
        while (offset + sizeof(Elf64_Verdef) <= sh->sh_size && vd_count < 100) {
            Elf64_Verdef *vd = (Elf64_Verdef*)(ctx->map + sh->sh_offset + offset);
            if (vd->vd_version == 0) break;

            snprintf(buf, sizeof(buf), "[Verdef %d] version=%d flags=0x%04X ndx=%d cnt=%d",
                     vd_count, vd->vd_version, vd->vd_flags,
                     vd->vd_ndx, vd->vd_cnt);
            fields_add(pd, buf, 0, 1, DETAIL_VERDEF, vd_count);

            /* 遍历辅助条目 */
            Elf64_Off aux_off = offset + vd->vd_aux;
            for (int a = 0; a < vd->vd_cnt && a < 10; a++) {
                Elf64_Verdaux *vda = (Elf64_Verdaux*)(ctx->map + sh->sh_offset + aux_off);
                const char *vname = stroff ? elf_strtab_get(ctx, stroff, vda->vda_name) : "?";
                snprintf(buf, sizeof(buf), "  [Aux %d] name=\"%s\"", a, vname);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                if (vda->vda_next == 0) break;
                aux_off += vda->vda_next;
            }

            if (vd->vd_next == 0) break;
            offset += vd->vd_next;
            vd_count++;
        }
    }

    /* ===== 版本需求 (Verneed) ===== */
    if (verneed_idx >= 0) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, verneed_idx);
        fields_add(pd, "=== Version Requirements (.gnu.version_r) ===",
                   0, 0, DETAIL_NONE, -1);

        Elf64_Off offset = 0;
        Elf64_Word stroff = 0;
        Elf64_Shdr *str_shdr = elf_get_shdr(ctx, sh->sh_link);
        if (str_shdr) stroff = str_shdr->sh_offset;

        int vn_count = 0;
        while (offset + sizeof(Elf64_Verneed) <= sh->sh_size && vn_count < 100) {
            Elf64_Verneed *vn = (Elf64_Verneed*)(ctx->map + sh->sh_offset + offset);
            if (vn->vn_version == 0) break;

            const char *file_name = stroff ? elf_strtab_get(ctx, stroff, vn->vn_file) : "?";
            snprintf(buf, sizeof(buf), "[Verneed %d] file=\"%s\" cnt=%d",
                     vn_count, file_name, vn->vn_cnt);
            fields_add(pd, buf, 0, 1, DETAIL_VERNEED, vn_count);

            /* 遍历辅助条目 */
            Elf64_Off aux_off = offset + vn->vn_aux;
            for (int a = 0; a < vn->vn_cnt && a < 10; a++) {
                Elf64_Vernaux *vna = (Elf64_Vernaux*)(ctx->map + sh->sh_offset + aux_off);
                const char *vname = stroff ? elf_strtab_get(ctx, stroff, vna->vna_name) : "?";
                snprintf(buf, sizeof(buf), "  [Aux %d] name=\"%s\" flags=0x%04X hash=0x%08X",
                         a, vname, vna->vna_flags, vna->vna_hash);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
                if (vna->vna_next == 0) break;
                aux_off += vna->vna_next;
            }

            if (vn->vn_next == 0) break;
            offset += vn->vn_next;
            vn_count++;
        }
    }

    /* ===== 版本符号表 (Versym) ===== */
    if (versym_idx >= 0) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, versym_idx);
        int count = sh->sh_size / sizeof(Elf64_Half);
        Elf64_Half *versyms = (Elf64_Half*)(ctx->map + sh->sh_offset);

        snprintf(buf, sizeof(buf), "=== Version Symbols (.gnu.version) — %d entries ===", count);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

        for (int i = 0; i < count && i < 50000; i++) {
            Elf64_Half vs = versyms[i];
            const char *desc = "";
            if (vs == 0) desc = "local";
            else if (vs == 1) desc = "global";
            else if (vs >= 2) desc = "versioned";

            snprintf(buf, sizeof(buf), "[%5d] versym=0x%04X (%s)", i, vs, desc);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        if (count > 50000) fields_add(pd, "... (truncated)", 1, 0, DETAIL_NONE, -1);
    }

    if (verdef_idx < 0 && verneed_idx < 0 && versym_idx < 0) {
        fields_add(pd, "(No version information sections found)",
                   0, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}
