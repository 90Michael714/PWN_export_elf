/*
 * struct_out.h — 结构化输出类型
 *
 * 替代纯字符串 fields_add("0x401000: mov rbp, rsp") 的方式。
 * TUI 渲染时可以从结构体字段精确控制显示、跳转、高亮。
 *
 * 使用方式:
 *   StructField sf = {.kind=1, .data.disasm={.addr=0x401000, ...}};
 *   panel_add_struct(pd, &sf);
 *   // pd->fields[].text 自动生成为 "0x401000: ..."
 *   // TUI 可从 StructField 中获取 addr 用于跳转
 */

#ifndef STRUCT_OUT_H
#define STRUCT_OUT_H

#include "elf_parser.h"
#include <stdint.h>

/* ── 结构化数据类型 ──────────────────────────────────────────────── */

/* 反汇编行 */
typedef struct {
    uint64_t addr;
    uint8_t  bytes[16];
    int      nb;
    char     mnemonic[16];
    char     ops[64];
} DisasmLine;

/* 寄存器条目 */
typedef struct {
    char     name[16];
    uint64_t value;
    char     annotation[64];   /* "→ .text (代码段)" / "(小整数:7)" */
} RegEntry;

/* GOT 槽位 */
typedef struct {
    uint64_t got_addr;
    char     sym_name[64];
    uint64_t resolved;
    int      is_lazy;
} GotSlot;

/* 符号引用 */
typedef struct {
    uint64_t addr;
    char     sym[64];
    int64_t  offset;
} SymRef;

/* 栈帧 */
typedef struct {
    int      frame_no;
    uint64_t rbp;
    uint64_t ret_addr;
    char     sym_name[64];
    int64_t  offset;
} StackFrame;

/* 内存映射条目 */
typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t size;
    char     perms[8];
    char     path[128];
} VMMapEntry;

/* ================================================================== */
/* 统一结构化字段                                                     */
/* ================================================================== */

typedef enum {
    SF_STRING   = 0,   /* 纯字符串 */
    SF_DISASM   = 1,   /* 反汇编行 */
    SF_REG      = 2,   /* 寄存器 */
    SF_GOT      = 3,   /* GOT 条目 */
    SF_SYMREF   = 4,   /* 符号引用 */
    SF_STACK    = 5,   /* 栈帧 */
    SF_VMMAP    = 6,   /* 内存映射 */
} StructFieldKind;

typedef struct StructField {
    int              kind;       /* StructFieldKind */
    union {
        DisasmLine   disasm;
        RegEntry     reg;
        GotSlot      got;
        SymRef       sym;
        StackFrame   stack;
        VMMapEntry   vmmap;
    } data;
} StructField;

/* ================================================================== */
/* PanelData 扩展                                                     */
/* ================================================================== */

/**
 * 结构化追加: 同时设置 fields[].text (格式化字符串) 和 sf (结构化数据)。
 * panel_data 里自动分配 StructField 数组。
 */
int panel_add_struct(PanelData *pd, const StructField *sf);

/**
 * 获取面板中指定行的结构化字段 (如果没有则返回 NULL)
 */
const StructField* panel_get_struct(const PanelData *pd, int index);

/**
 * 释放面板中的结构化数据 (fields_free 的扩展版)
 */
void panel_structs_free(PanelData *pd);

#endif
