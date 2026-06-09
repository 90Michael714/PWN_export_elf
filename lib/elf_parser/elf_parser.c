/*
 * elf_parser.c — ELF64 核心解析模块
 *
 * 提供 ELF 文件的打开/关闭、mmap 映射、字符串表查询、类型名称转换
 * 等基础功能。所有其他解析模块都依赖此模块。
 */

#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* ================================================================
 * 文件打开 / 关闭
 * ================================================================ */

Elf64_Ctx* elf_open(const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    if (st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return NULL; }

    uint8_t *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { close(fd); return NULL; }

    /* 验证 ELF 魔数 */
    if (map[EI_MAG0] != ELFMAG0 || map[EI_MAG1] != ELFMAG1 ||
        map[EI_MAG2] != ELFMAG2 || map[EI_MAG3] != ELFMAG3) {
        munmap(map, st.st_size); close(fd); return NULL;
    }

    /* 验证 64-bit */
    if (map[EI_CLASS] != ELFCLASS64) {
        munmap(map, st.st_size); close(fd); return NULL;
    }

    Elf64_Ctx *ctx = calloc(1, sizeof(Elf64_Ctx));
    ctx->fd = fd;
    ctx->size = st.st_size;
    ctx->map = map;
    ctx->filename = filename;
    return ctx;
}

void elf_close(Elf64_Ctx *ctx)
{
    if (!ctx) return;
    if (ctx->map) munmap(ctx->map, ctx->size);
    if (ctx->fd >= 0) close(ctx->fd);
    free(ctx);
}

/* ================================================================
 * 字符串表查询
 * ================================================================ */

const char* elf_strtab_get(Elf64_Ctx *ctx, Elf64_Off stroff, Elf64_Word idx)
{
    if (stroff + idx >= ctx->size) return "(out of bounds)";
    return (const char*)(ctx->map + stroff + idx);
}

const char* elf_dynstr_get(Elf64_Ctx *ctx, Elf64_Off stroff, Elf64_Word idx)
{
    return elf_strtab_get(ctx, stroff, idx);
}

/* ================================================================
 * 节头查询
 * ================================================================ */

Elf64_Ehdr* elf_get_ehdr(Elf64_Ctx *ctx)
{
    return (Elf64_Ehdr*)ctx->map;
}

Elf64_Shdr* elf_get_shdr(Elf64_Ctx *ctx, int index)
{
    Elf64_Ehdr *ehdr = elf_get_ehdr(ctx);
    return (Elf64_Shdr*)(ctx->map + ehdr->e_shoff + index * sizeof(Elf64_Shdr));
}

const char* elf_section_name(Elf64_Ctx *ctx, int index)
{
    Elf64_Ehdr *ehdr = elf_get_ehdr(ctx);
    Elf64_Shdr *shdr = elf_get_shdr(ctx, index);
    Elf64_Shdr *shstr = elf_get_shdr(ctx, ehdr->e_shstrndx);
    return elf_strtab_get(ctx, shstr->sh_offset, shdr->sh_name);
}

Elf64_Phdr* elf_get_phdr(Elf64_Ctx *ctx, int index)
{
    Elf64_Ehdr *ehdr = elf_get_ehdr(ctx);
    return (Elf64_Phdr*)(ctx->map + ehdr->e_phoff + index * sizeof(Elf64_Phdr));
}

/* ================================================================
 * 类型名称转换 (字符串化)
 * ================================================================ */

const char* elf_e_type_str(Elf64_Half e_type)
{
    switch (e_type) {
        case ET_NONE: return "ET_NONE (No file type)";
        case ET_REL:  return "ET_REL (Relocatable)";
        case ET_EXEC: return "ET_EXEC (Executable)";
        case ET_DYN:  return "ET_DYN (Shared object)";
        case ET_CORE: return "ET_CORE (Core file)";
        default:      return "Unknown";
    }
}

const char* elf_e_machine_str(Elf64_Half e_machine)
{
    switch (e_machine) {
        case EM_X86_64:  return "EM_X86_64 (AMD x86-64)";
        case EM_AARCH64: return "EM_AARCH64 (ARM AArch64)";
        case EM_RISCV:   return "EM_RISCV (RISC-V)";
        case EM_ARM:     return "EM_ARM (ARM)";
        case 3:          return "EM_386 (Intel 80386)";
        default:         return "Unknown";
    }
}

const char* elf_e_osabi_str(unsigned char osabi)
{
    switch (osabi) {
        case ELFOSABI_NONE: return "ELFOSABI_NONE (UNIX System V)";
        case 1:             return "ELFOSABI_HPUX";
        case 2:             return "ELFOSABI_NETBSD";
        case ELFOSABI_GNU:  return "ELFOSABI_GNU/LINUX";
        case 6:             return "ELFOSABI_SOLARIS";
        case 9:             return "ELFOSABI_FREEBSD";
        default:            return "Unknown";
    }
}

const char* elf_sh_type_str(Elf64_Word sh_type)
{
    switch (sh_type) {
        case SHT_NULL:      return "SHT_NULL";
        case SHT_PROGBITS:  return "SHT_PROGBITS";
        case SHT_SYMTAB:    return "SHT_SYMTAB";
        case SHT_STRTAB:    return "SHT_STRTAB";
        case SHT_RELA:      return "SHT_RELA";
        case SHT_HASH:      return "SHT_HASH";
        case SHT_DYNAMIC:   return "SHT_DYNAMIC";
        case SHT_NOTE:      return "SHT_NOTE";
        case SHT_NOBITS:    return "SHT_NOBITS";
        case SHT_REL:       return "SHT_REL";
        case SHT_DYNSYM:    return "SHT_DYNSYM";
        case SHT_INIT_ARRAY:    return "SHT_INIT_ARRAY";
        case SHT_FINI_ARRAY:    return "SHT_FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "SHT_PREINIT_ARRAY";
        case SHT_GROUP:     return "SHT_GROUP";
        case SHT_SYMTAB_SHNDX:  return "SHT_SYMTAB_SHNDX";
        case SHT_RELR:      return "SHT_RELR";
        case SHT_GNU_HASH:  return "SHT_GNU_HASH";
        case SHT_GNU_verdef:    return "SHT_GNU_verdef";
        case SHT_GNU_verneed:   return "SHT_GNU_verneed";
        case SHT_GNU_versym:    return "SHT_GNU_versym";
        default:            return "(other)";
    }
}

const char* elf_sh_flags_str(Elf64_Xword sh_flags, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    if (sh_flags & SHF_WRITE)      strncat(buf, "W", bufsz - 1);
    else                           strncat(buf, "-", bufsz - 1);
    if (sh_flags & SHF_ALLOC)      strncat(buf, "A", bufsz - 1);
    else                           strncat(buf, "-", bufsz - 1);
    if (sh_flags & SHF_EXECINSTR)  strncat(buf, "X", bufsz - 1);
    else                           strncat(buf, "-", bufsz - 1);
    if (sh_flags & SHF_MERGE)      strncat(buf, "M", bufsz - 1);
    if (sh_flags & SHF_STRINGS)    strncat(buf, "S", bufsz - 1);
    if (sh_flags & SHF_TLS)        strncat(buf, "T", bufsz - 1);
    return buf;
}

const char* elf_p_type_str(Elf64_Word p_type)
{
    switch (p_type) {
        case PT_NULL:     return "PT_NULL";
        case PT_LOAD:     return "PT_LOAD";
        case PT_DYNAMIC:  return "PT_DYNAMIC";
        case PT_INTERP:   return "PT_INTERP";
        case PT_NOTE:     return "PT_NOTE";
        case PT_PHDR:     return "PT_PHDR";
        case PT_TLS:      return "PT_TLS";
        case PT_GNU_EH_FRAME: return "PT_GNU_EH_FRAME";
        case PT_GNU_STACK:    return "PT_GNU_STACK";
        case PT_GNU_RELRO:    return "PT_GNU_RELRO";
        case PT_GNU_PROPERTY: return "PT_GNU_PROPERTY";
        default:          return "(other)";
    }
}

const char* elf_p_flags_str(Elf64_Word p_flags, char *buf, size_t bufsz)
{
    buf[0] = '\0';
    strncat(buf, (p_flags & PF_R) ? "R" : "-", bufsz - 1);
    strncat(buf, (p_flags & PF_W) ? "W" : "-", bufsz - 1);
    strncat(buf, (p_flags & PF_X) ? "X" : "-", bufsz - 1);
    return buf;
}

const char* elf_st_bind_str(unsigned char info)
{
    unsigned char bind = ELF64_ST_BIND(info);
    switch (bind) {
        case STB_LOCAL:  return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK:   return "WEAK";
        default:         return "?";
    }
}

const char* elf_st_type_str(unsigned char info)
{
    unsigned char type = ELF64_ST_TYPE(info);
    switch (type) {
        case STT_NOTYPE:  return "NOTYPE";
        case STT_OBJECT:  return "OBJECT";
        case STT_FUNC:    return "FUNC";
        case STT_SECTION: return "SECTION";
        case STT_FILE:    return "FILE";
        case STT_TLS:     return "TLS";
        default:          return "?";
    }
}

const char* elf_d_tag_str(Elf64_Sxword d_tag)
{
    switch (d_tag) {
        case DT_NULL:     return "DT_NULL";
        case DT_NEEDED:   return "DT_NEEDED";
        case DT_PLTRELSZ: return "DT_PLTRELSZ";
        case DT_PLTGOT:   return "DT_PLTGOT";
        case DT_HASH:     return "DT_HASH";
        case DT_STRTAB:   return "DT_STRTAB";
        case DT_SYMTAB:   return "DT_SYMTAB";
        case DT_RELA:     return "DT_RELA";
        case DT_RELASZ:   return "DT_RELASZ";
        case DT_RELAENT:  return "DT_RELAENT";
        case DT_STRSZ:    return "DT_STRSZ";
        case DT_SYMENT:   return "DT_SYMENT";
        case DT_INIT:     return "DT_INIT";
        case DT_FINI:     return "DT_FINI";
        case DT_SONAME:   return "DT_SONAME";
        case DT_RPATH:    return "DT_RPATH";
        case DT_SYMBOLIC: return "DT_SYMBOLIC";
        case DT_REL:      return "DT_REL";
        case DT_RELSZ:    return "DT_RELSZ";
        case DT_RELENT:   return "DT_RELENT";
        case DT_PLTREL:   return "DT_PLTREL";
        case DT_DEBUG:    return "DT_DEBUG";
        case DT_TEXTREL:  return "DT_TEXTREL";
        case DT_JMPREL:   return "DT_JMPREL";
        case DT_BIND_NOW: return "DT_BIND_NOW";
        case DT_INIT_ARRAY:    return "DT_INIT_ARRAY";
        case DT_FINI_ARRAY:    return "DT_FINI_ARRAY";
        case DT_RUNPATH:  return "DT_RUNPATH";
        case DT_FLAGS:    return "DT_FLAGS";
        case DT_GNU_HASH: return "DT_GNU_HASH";
        case DT_VERSYM:   return "DT_VERSYM";
        case DT_VERDEF:   return "DT_VERDEF";
        case DT_VERDEFNUM: return "DT_VERDEFNUM";
        case DT_VERNEED:  return "DT_VERNEED";
        case DT_VERNEEDNUM: return "DT_VERNEEDNUM";
        default:          return "(other)";
    }
}

const char* elf_reloc_type_str(int machine, Elf64_Xword r_info)
{
    uint32_t type = r_info & 0xffffffff;
    if (machine != EM_X86_64) return "(non-x86-64)";
    switch (type) {
        case R_X86_64_NONE:      return "R_X86_64_NONE";
        case R_X86_64_64:        return "R_X86_64_64";
        case R_X86_64_PC32:      return "R_X86_64_PC32";
        case R_X86_64_GOT32:     return "R_X86_64_GOT32";
        case R_X86_64_PLT32:     return "R_X86_64_PLT32";
        case R_X86_64_COPY:      return "R_X86_64_COPY";
        case R_X86_64_GLOB_DAT:  return "R_X86_64_GLOB_DAT";
        case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
        case R_X86_64_RELATIVE:  return "R_X86_64_RELATIVE";
        case R_X86_64_GOTPCREL:  return "R_X86_64_GOTPCREL";
        case R_X86_64_32:        return "R_X86_64_32";
        case R_X86_64_32S:       return "R_X86_64_32S";
        case R_X86_64_16:        return "R_X86_64_16";
        case R_X86_64_PC16:      return "R_X86_64_PC16";
        case R_X86_64_8:         return "R_X86_64_8";
        case R_X86_64_PC8:       return "R_X86_64_PC8";
        case R_X86_64_IRELATIVE: return "R_X86_64_IRELATIVE";
        default:                 return "(other)";
    }
}

const char* elf_note_type_str(Elf64_Word n_type)
{
    switch (n_type) {
        case NT_GNU_ABI_TAG:  return "NT_GNU_ABI_TAG";
        case NT_GNU_BUILD_ID: return "NT_GNU_BUILD_ID";
        case NT_GNU_PROPERTY_TYPE_0: return "NT_GNU_PROPERTY_TYPE_0";
        default: return "(other)";
    }
}

/* ================================================================
 * 字段数组管理
 * ================================================================ */

Elf64_Field* fields_alloc(int count)
{
    Elf64_Field *fields = calloc(count, sizeof(Elf64_Field));
    return fields;
}

void fields_free(Elf64_Field *fields, int count)
{
    if (!fields) return;
    for (int i = 0; i < count; i++) {
        free(fields[i].text);
    }
    free(fields);
}

void field_set(Elf64_Field *f, const char *text, int indent,
               int selectable, DetailKind kind, int index)
{
    f->text = text ? strdup(text) : NULL;
    f->indent = indent;
    f->selectable = selectable;
    f->detail_kind = kind;
    f->detail_index = index;
}

int fields_add(PanelData *pd, const char *text, int indent,
               int selectable, DetailKind kind, int index)
{
    if (pd->count >= pd->capacity) {
        int new_cap = pd->capacity ? pd->capacity * 2 : 64;
        Elf64_Field *new_fields = realloc(pd->fields,
                                          new_cap * sizeof(Elf64_Field));
        if (!new_fields) return -1;
        pd->fields = new_fields;
        pd->capacity = new_cap;
    }
    field_set(&pd->fields[pd->count], text, indent, selectable, kind, index);
    pd->count++;
    return 0;
}
