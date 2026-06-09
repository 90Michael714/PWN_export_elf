/*
 * note.c — 注释节解析 (.note.*)
 *
 * 解析 ELF Note 节，包括 GNU ABI 标签、Build ID、GNU 属性等。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_note(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *sec_name = elf_section_name(ctx, shdr_idx);

    char buf[256];
    snprintf(buf, sizeof(buf), "=== %s (Note section) ===", sec_name);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    uint8_t *data = ctx->map + sh->sh_offset;
    Elf64_Xword remaining = sh->sh_size;
    Elf64_Xword pos = 0;

    int note_idx = 0;
    while (pos + sizeof(Elf64_Nhdr) <= remaining) {
        Elf64_Nhdr *nhdr = (Elf64_Nhdr*)(data + pos);

        if (nhdr->n_namesz == 0 && nhdr->n_descsz == 0) {
            fields_add(pd, "(Zero-length note — end)", 1, 0, DETAIL_NONE, -1);
            break;
        }

        /* 名称对齐到 4 字节 */
        Elf64_Xword name_off = pos + sizeof(Elf64_Nhdr);
        Elf64_Xword name_len_aligned = (nhdr->n_namesz + 3) & ~3;
        Elf64_Xword desc_off = name_off + name_len_aligned;
        Elf64_Xword desc_len_aligned = (nhdr->n_descsz + 3) & ~3;
        Elf64_Xword total = sizeof(Elf64_Nhdr) + name_len_aligned + desc_len_aligned;

        if (pos + total > remaining) break;

        const char *owner = (const char*)(data + name_off);
        char owner_safe[64];
        strncpy(owner_safe, owner[0] ? owner : "(null)", 63);
        owner_safe[63] = '\0';
        snprintf(buf, sizeof(buf), "[Note %d] owner=\"%s\" type=%s(%d) desc_size=%u",
                 note_idx, owner_safe,
                 elf_note_type_str(nhdr->n_type), nhdr->n_type, nhdr->n_descsz);
        fields_add(pd, buf, 1, 1, DETAIL_NOTE, note_idx);

        /* 根据类型显示描述内容 */
        uint8_t *desc = data + desc_off;
        switch (nhdr->n_type) {
            case NT_GNU_BUILD_ID: {
                /* Build ID — 显示为十六进制字符串 */
                char hex_str[256] = "";
                Elf64_Xword len = nhdr->n_descsz;
                if (len > 80) len = 80; /* 截断 */
                for (Elf64_Xword j = 0; j < len; j++) {
                    char byte_hex[4];
                    snprintf(byte_hex, sizeof(byte_hex), "%02X", desc[j]);
                    strncat(hex_str, byte_hex, sizeof(hex_str) - 1);
                }
                snprintf(buf, sizeof(buf), "  Build ID: %.80s%s",
                         hex_str, nhdr->n_descsz > 80 ? "..." : "");
                fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                break;
            }
            case NT_GNU_ABI_TAG: {
                if (nhdr->n_descsz >= 4) {
                    uint32_t os = *(uint32_t*)desc;
                    snprintf(buf, sizeof(buf), "  ABI OS: %u", os);
                    fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                }
                if (nhdr->n_descsz >= 16) {
                    uint32_t *ver = (uint32_t*)(desc + 4);
                    snprintf(buf, sizeof(buf), "  ABI Version: %u.%u.%u",
                             ver[0], ver[1], ver[2]);
                    fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                }
                break;
            }
            case NT_GNU_PROPERTY_TYPE_0: {
                snprintf(buf, sizeof(buf), "  Property data: %u bytes",
                         nhdr->n_descsz);
                fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                break;
            }
        }

        pos += total;
        note_idx++;
    }

    if (note_idx == 0) {
        fields_add(pd, "(No valid note entries found)", 1, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}
