/*
 * tui_middle.c — 中面板: 结构体字段展开视图
 *
 * 显示左面板选中项目的详细字段列表，格式为"字段名: 值"。
 * 选中某字段后按 Enter → 右面板显示字段详解。
 */

#include "tui.h"
#include "tui_panels.h"
#include "tui_colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void middle_panel_init(PanelData *pd)
{
    pd->count = 0;
    pd->capacity = 0;
    pd->fields = NULL;
    pd->cursor = 0;
    pd->scroll = 0;
}

/* 中面板选中 → 填充右面板(字段详解) */
void middle_panel_handle_enter(PanelData *middle, PanelData *right,
                                Elf64_Ctx *ctx)
{
    if (!middle || middle->cursor < 0 || middle->cursor >= middle->count) return;
    if (!right) return;
    (void)ctx;  /* used via right_panel_init and detail parsing */

    /* 清空右面板 */
    if (right->fields) {
        fields_free(right->fields, right->count);
        right->fields = NULL;
        right->count = 0;
        right->capacity = 0;
        right->cursor = 0;
        right->scroll = 0;
    }

    Elf64_Field *sel = &middle->fields[middle->cursor];
    if (!sel->selectable || !sel->text) return;

    /* 在右面板显示字段的详细说明 */
    right_panel_init(right);

    /* 标题 */
    char buf[512];
    snprintf(buf, sizeof(buf), "=== Field Detail ===");
    fields_add(right, buf, 0, 0, DETAIL_NONE, -1);

    /* 字段名/值 */
    snprintf(buf, sizeof(buf), "Selected: %s", sel->text);
    fields_add(right, buf, 1, 0, DETAIL_NONE, -1);

    /* 根据 detail_kind 提供上下文解释 */
    fields_add(right, "", 0, 0, DETAIL_NONE, -1);
    fields_add(right, "--- Explanation ---", 1, 0, DETAIL_NONE, -1);

    /* 尝试从字段文本中提取字段名并解释 */
    char field_name[64] = "";
    const char *colon = strchr(sel->text, ':');
    if (colon) {
        size_t len = colon - sel->text;
        if (len > 63) len = 63;
        strncpy(field_name, sel->text, len);
        field_name[len] = '\0';

        /* 去掉前导空白 */
        char *start = field_name;
        while (*start == ' ' || *start == '\t') start++;
    }

    /* 提供常见字段的解释 */
    if (strstr(sel->text, "e_ident")) {
        fields_add(right, "e_ident[16] is the ELF identification array.", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Bytes 0-3: Magic number (\\x7fELF)", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Byte 4 (EI_CLASS): File class (32/64-bit)", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Byte 5 (EI_DATA): Endianness", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Byte 6 (EI_VERSION): ELF version", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Byte 7 (EI_OSABI): Target OS/ABI", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "Byte 8 (EI_ABIVERSION): ABI version", 2, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "e_type")) {
        fields_add(right, "e_type specifies the object file type:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "ET_REL(1) = Relocatable file (.o)", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "ET_EXEC(2) = Executable file", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "ET_DYN(3) = Shared object (.so) or PIE", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "ET_CORE(4) = Core dump file", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "e_machine")) {
        fields_add(right, "e_machine specifies the target ISA:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "EM_X86_64(62) = AMD/Intel x86-64", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "EM_AARCH64(183) = ARM 64-bit", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "EM_RISCV(243) = RISC-V", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "e_entry")) {
        fields_add(right, "e_entry is the virtual address of the", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "program entry point (_start).", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "For ET_EXEC: absolute virtual address", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "For ET_DYN (PIE): offset from load base", 2, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "p_type")) {
        fields_add(right, "p_type specifies the segment type:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_LOAD = Loadable segment (mapped to memory)", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_DYNAMIC = .dynamic section location", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_INTERP = Program interpreter path", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_NOTE = Auxiliary info (ABI/Build-ID)", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_GNU_STACK = Stack executability flag", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PT_GNU_RELRO = Read-only after relocation", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "sh_type")) {
        fields_add(right, "sh_type specifies the section type:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_PROGBITS(1) = Program data/code", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_SYMTAB(2) = Symbol table", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_STRTAB(3) = String table", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_RELA(4) = Relocations with addends", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_DYNAMIC(6) = Dynamic linking info", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_NOTE(7) = Note section", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHT_NOBITS(8) = No file data (.bss)", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "st_info")) {
        fields_add(right, "st_info encodes symbol binding and type:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "High 4 bits = Binding: LOCAL(0)/GLOBAL(1)/WEAK(2)", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "Low 4 bits = Type: NOTYPE/FUNC/OBJECT/SECTION/FILE/TLS", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "sh_flags")) {
        fields_add(right, "sh_flags is a bitmask of section attributes:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_WRITE(0x1) = Writable at runtime", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_ALLOC(0x2) = Occupies memory", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_EXECINSTR(0x4) = Executable code", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_MERGE(0x10) = Can be merged by linker", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_STRINGS(0x20) = Contains null-terminated strings", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "SHF_TLS(0x400) = Thread-local storage", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "p_flags")) {
        fields_add(right, "p_flags specifies segment permissions:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "PF_R(4) = Readable", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PF_W(2) = Writable", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "PF_X(1) = Executable", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "Common combinations: R-X(5)=code, RW-(6)=data, R--(4)=rodata", 3, 0, DETAIL_NONE, -1);
    } else if (strstr(sel->text, "d_tag")) {
        fields_add(right, "d_tag specifies the dynamic entry type:", 2, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_NEEDED(1) = Required shared library", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_STRTAB(5) = Address of .dynstr", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_SYMTAB(6) = Address of .dynsym", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_RELA(7) = Address of .rela.*", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_INIT(12)/DT_FINI(13) = Init/fini functions", 3, 0, DETAIL_NONE, -1);
        fields_add(right, "DT_RUNPATH(29) = Runtime library search path", 3, 0, DETAIL_NONE, -1);
    } else {
        fields_add(right, "(Select a field in the middle panel to see detailed explanation)", 2, 0, DETAIL_NONE, -1);
    }
}

/*
 * Rendering is handled in tui.c via region_lines() / region_border().
 * middle_panel_init() and middle_panel_handle_enter() provide the data layer.
 */
