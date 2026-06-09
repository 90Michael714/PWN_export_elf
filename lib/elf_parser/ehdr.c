/*
 * ehdr.c — ELF64 Header 解析
 *
 * 解析 ELF 文件头 (Elf64_Ehdr)，将其各字段格式化为可显示的字段列表。
 */

#include "elf_parser.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void add_field(PanelData *pd, const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fields_add(pd, buf, 1, 1, DETAIL_EHDR, pd->count);
}

static void add_heading(PanelData *pd, const char *title)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "=== %s ===", title);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
}

int parse_ehdr(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    (void)pd; /* used via add_field / add_heading */

    add_heading(pd, "ELF Header");

    /* e_ident */
    add_heading(pd, "e_ident (Magic & Identification)");
    add_field(pd, "EI_MAG0-3:  %02X %02X %02X %02X (\\x7fELF)",
              ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1],
              ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);
    add_field(pd, "EI_CLASS:    %d (ELFCLASS%d)",
              ehdr->e_ident[EI_CLASS],
              ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32);
    add_field(pd, "EI_DATA:     %d (%s)",
              ehdr->e_ident[EI_DATA],
              ehdr->e_ident[EI_DATA] == ELFDATA2LSB ? "Little Endian" :
              ehdr->e_ident[EI_DATA] == ELFDATA2MSB ? "Big Endian" : "Unknown");
    add_field(pd, "EI_VERSION:  %d", ehdr->e_ident[EI_VERSION]);
    add_field(pd, "EI_OSABI:    %d — %s", ehdr->e_ident[EI_OSABI],
              elf_e_osabi_str(ehdr->e_ident[EI_OSABI]));
    add_field(pd, "EI_ABIVERSION: %d", ehdr->e_ident[EI_ABIVERSION]);

    /* 顶层字段 */
    add_heading(pd, "File Header Fields");
    add_field(pd, "e_type:      0x%04X — %s",
              ehdr->e_type, elf_e_type_str(ehdr->e_type));
    add_field(pd, "e_machine:   0x%04X — %s",
              ehdr->e_machine, elf_e_machine_str(ehdr->e_machine));
    add_field(pd, "e_version:   0x%08X", ehdr->e_version);
    add_field(pd, "e_entry:     0x%lX (entry point)",
              (unsigned long)ehdr->e_entry);

    add_field(pd, "e_phoff:     0x%lX (%lu bytes)",
              (unsigned long)ehdr->e_phoff, (unsigned long)ehdr->e_phoff);
    add_field(pd, "e_shoff:     0x%lX (%lu bytes)",
              (unsigned long)ehdr->e_shoff, (unsigned long)ehdr->e_shoff);
    add_field(pd, "e_flags:     0x%08X", ehdr->e_flags);

    add_field(pd, "e_ehsize:    %d bytes (ELF header size)",
              ehdr->e_ehsize);
    add_field(pd, "e_phentsize: %d bytes (Program header entry size)",
              ehdr->e_phentsize);
    add_field(pd, "e_phnum:     %d (Program header entries)",
              ehdr->e_phnum);
    add_field(pd, "e_shentsize: %d bytes (Section header entry size)",
              ehdr->e_shentsize);
    add_field(pd, "e_shnum:     %d (Section header entries)",
              ehdr->e_shnum);
    add_field(pd, "e_shstrndx:  %d (Section name string table index)",
              ehdr->e_shstrndx);

    return pd->count;
}
