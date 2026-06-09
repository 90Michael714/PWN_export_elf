/*
 * elf_parser.h — ELF64 解析器公共头文件
 *
 * 定义 ELF64 所有标准结构体类型、解析上下文、以及各解析模块的统一接口。
 * 仅支持 ELF64 (64-bit objects)，不处理 32-bit。
 */

#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * ELF64 基础类型定义 (与 elf.h 一致)
 * ================================================================ */

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

/* ================================================================
 * ELF64 标准结构体定义 (仅 ELF64 部分)
 * ================================================================ */

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Xword   sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Xword   sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Xword   sh_addralign;
    Elf64_Xword   sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word    p_type;
    Elf64_Word    p_flags;
    Elf64_Off     p_offset;
    Elf64_Addr    p_vaddr;
    Elf64_Addr    p_paddr;
    Elf64_Xword   p_filesz;
    Elf64_Xword   p_memsz;
    Elf64_Xword   p_align;
} Elf64_Phdr;

typedef struct {
    Elf64_Word    st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half    st_shndx;
    Elf64_Addr    st_value;
    Elf64_Xword   st_size;
} Elf64_Sym;

typedef struct {
    Elf64_Sxword  d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
} Elf64_Dyn;

typedef struct {
    Elf64_Addr    r_offset;
    Elf64_Xword   r_info;
    Elf64_Sxword  r_addend;
} Elf64_Rela;

typedef struct {
    Elf64_Addr    r_offset;
    Elf64_Xword   r_info;
} Elf64_Rel;

typedef struct {
    Elf64_Word    n_namesz;
    Elf64_Word    n_descsz;
    Elf64_Word    n_type;
} Elf64_Nhdr;

typedef struct {
    Elf64_Half    vd_version;
    Elf64_Half    vd_flags;
    Elf64_Half    vd_ndx;
    Elf64_Half    vd_cnt;
    Elf64_Word    vd_hash;
    Elf64_Word    vd_aux;
    Elf64_Word    vd_next;
} Elf64_Verdef;

typedef struct {
    Elf64_Word    vda_name;
    Elf64_Word    vda_next;
} Elf64_Verdaux;

typedef struct {
    Elf64_Half    vn_version;
    Elf64_Half    vn_cnt;
    Elf64_Word    vn_file;
    Elf64_Word    vn_aux;
    Elf64_Word    vn_next;
} Elf64_Verneed;

typedef struct {
    Elf64_Word    vna_hash;
    Elf64_Half    vna_flags;
    Elf64_Half    vna_other;
    Elf64_Word    vna_name;
    Elf64_Word    vna_next;
} Elf64_Vernaux;

typedef struct {
    Elf64_Word    ch_type;
    Elf64_Word    ch_reserved;
    Elf64_Xword   ch_size;
    Elf64_Xword   ch_addralign;
} Elf64_Chdr;

/* ================================================================
 * ELF64 常量定义
 * ================================================================ */

/* e_ident 索引 */
#define EI_MAG0        0
#define EI_MAG1        1
#define EI_MAG2        2
#define EI_MAG3        3
#define EI_CLASS       4
#define EI_DATA        5
#define EI_VERSION     6
#define EI_OSABI       7
#define EI_ABIVERSION  8
#define EI_PAD         9

/* ELF 魔数 */
#define ELFMAG0  0x7f
#define ELFMAG1  'E'
#define ELFMAG2  'L'
#define ELFMAG3  'F'

/* e_ident[EI_CLASS] */
#define ELFCLASS32  1
#define ELFCLASS64  2

/* e_ident[EI_DATA] */
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

/* e_ident[EI_OSABI] */
#define ELFOSABI_NONE    0
#define ELFOSABI_SYSV    0
#define ELFOSABI_GNU     3
#define ELFOSABI_LINUX   3

/* e_type */
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4

/* e_machine */
#define EM_X86_64  62
#define EM_AARCH64 183
#define EM_RISCV   243
#define EM_ARM     40

/* 节类型 sh_type */
#define SHT_NULL          0
#define SHT_PROGBITS      1
#define SHT_SYMTAB        2
#define SHT_STRTAB        3
#define SHT_RELA          4
#define SHT_HASH          5
#define SHT_DYNAMIC       6
#define SHT_NOTE          7
#define SHT_NOBITS        8
#define SHT_REL           9
#define SHT_SHLIB         10
#define SHT_DYNSYM        11
#define SHT_INIT_ARRAY    14
#define SHT_FINI_ARRAY    15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP         17
#define SHT_SYMTAB_SHNDX  18
#define SHT_RELR          19
#define SHT_NUM           20
#define SHT_GNU_HASH      0x6ffffff6
#define SHT_GNU_verdef    0x6ffffffd
#define SHT_GNU_verneed   0x6ffffffe
#define SHT_GNU_versym    0x6fffffff

/* 节标志 sh_flags */
#define SHF_WRITE      (1 << 0)
#define SHF_ALLOC      (1 << 1)
#define SHF_EXECINSTR  (1 << 2)
#define SHF_MERGE      (1 << 4)
#define SHF_STRINGS    (1 << 5)
#define SHF_INFO_LINK  (1 << 6)
#define SHF_LINK_ORDER (1 << 7)
#define SHF_GROUP      (1 << 9)
#define SHF_TLS        (1 << 10)
#define SHF_COMPRESSED (1 << 11)

/* 段类型 p_type */
#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_SHLIB        5
#define PT_PHDR         6
#define PT_TLS          7
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552
#define PT_GNU_PROPERTY 0x6474e553

/* 段标志 p_flags */
#define PF_X  (1 << 0)
#define PF_W  (1 << 1)
#define PF_R  (1 << 2)

/* 动态条目类型 d_tag */
#define DT_NULL          0
#define DT_NEEDED        1
#define DT_PLTRELSZ      2
#define DT_PLTGOT        3
#define DT_HASH          4
#define DT_STRTAB        5
#define DT_SYMTAB        6
#define DT_RELA          7
#define DT_RELASZ        8
#define DT_RELAENT       9
#define DT_STRSZ         10
#define DT_SYMENT        11
#define DT_INIT          12
#define DT_FINI          13
#define DT_SONAME        14
#define DT_RPATH         15
#define DT_SYMBOLIC      16
#define DT_REL           17
#define DT_RELSZ         18
#define DT_RELENT        19
#define DT_PLTREL        20
#define DT_DEBUG         21
#define DT_TEXTREL       22
#define DT_JMPREL        23
#define DT_BIND_NOW      24
#define DT_INIT_ARRAY    25
#define DT_FINI_ARRAY    26
#define DT_INIT_ARRAYSZ  27
#define DT_FINI_ARRAYSZ  28
#define DT_RUNPATH       29
#define DT_FLAGS         30
#define DT_FLAGS_1       0x6ffffffb

/* DT_FLAGS / DT_FLAGS_1 标志位 */
#define DF_BIND_NOW      8     /* DT_FLAGS: BIND_NOW */
#define DF_1_NOW         1     /* DT_FLAGS_1: NOW (Full RELRO) */
#define DF_1_PIE         0x08000000  /* DT_FLAGS_1: PIE */
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33
#define DT_SYMTAB_SHNDX  34
#define DT_RELRSZ        35
#define DT_RELR          36
#define DT_RELRENT       37
#define DT_NUM           38
#define DT_VERSYM        0x6ffffff0
#define DT_VERDEF        0x6ffffffc
#define DT_VERDEFNUM     0x6ffffffd
#define DT_VERNEED       0x6ffffffe
#define DT_VERNEEDNUM    0x6fffffff
#define DT_GNU_HASH      0x6ffffef5

/* 符号绑定和类型 */
#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_TLS     6

#define ELF64_ST_BIND(info)  ((info) >> 4)
#define ELF64_ST_TYPE(info)  ((info) & 0xf)

/* 重定位类型 (x86-64) */
#define R_X86_64_NONE      0
#define R_X86_64_64        1
#define R_X86_64_PC32      2
#define R_X86_64_GOT32     3
#define R_X86_64_PLT32     4
#define R_X86_64_COPY      5
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8
#define R_X86_64_GOTPCREL  9
#define R_X86_64_32        10
#define R_X86_64_32S       11
#define R_X86_64_16        12
#define R_X86_64_PC16      13
#define R_X86_64_8         14
#define R_X86_64_PC8       15
#define R_X86_64_IRELATIVE 37

/* Note 类型 */
#define NT_GNU_ABI_TAG  1
#define NT_GNU_BUILD_ID 3
#define NT_GNU_PROPERTY_TYPE_0 5

/* 特殊节索引 */
#define SHN_UNDEF  0
#define SHN_ABS    0xfff1
#define SHN_COMMON 0xfff2

/* ================================================================
 * 解析器通用数据结构
 * ================================================================ */

/* 解析上下文 — 解析操作的"句柄" */
typedef struct {
    int         fd;            /* 文件描述符 */
    size_t      size;          /* 文件大小 */
    uint8_t    *map;           /* mmap 映射指针 */
    const char *filename;      /* 文件名 */
} Elf64_Ctx;

/* 字段详情类型枚举 — 用于 TUI 右侧面板展开 */
typedef enum {
    DETAIL_NONE = 0,
    DETAIL_EHDR,         /* ELF Header 字段 */
    DETAIL_PHDR,         /* Program Header 字段 */
    DETAIL_SHDR,         /* Section Header 字段 */
    DETAIL_SYM,          /* 符号表条目字段 */
    DETAIL_DYN,          /* 动态条目字段 */
    DETAIL_RELA,         /* 重定位条目字段 */
    DETAIL_NOTE,         /* Note 字段 */
    DETAIL_VERDEF,       /* 版本定义字段 */
    DETAIL_VERNEED,      /* 版本需求字段 */
    DETAIL_REG,          /* 寄存器字段 (NT_PRSTATUS) */
} DetailKind;

/* 解析输出 — 一个格式化的显示行 */
typedef struct {
    char     *text;           /* 格式化文本 (TUI 直接输出用) */
    int       indent;         /* 缩进级别 0=heading, 1=field, 2=sub-field */
    int       selectable;     /* 0=不可选, 1=可选中以查看详情 */
    DetailKind detail_kind;   /* 选中后用什么类型详情展开 */
    int       detail_index;   /* 在所属数组中的索引 (如第几个 section/第几个符号) */
} Elf64_Field;

/* 面板数据模型 */
typedef struct {
    Elf64_Field *fields;
    int          count;
    int          capacity;
    int          cursor;      /* 当前选中行索引 */
    int          scroll;      /* 垂直滚动偏移 (行) */
    int          scroll_x;    /* 水平滚动偏移 (列) */
} PanelData;

/* ================================================================
 * ELF 解析模块 API 声明
 * ================================================================ */

/* elf_parser.c — 核心操作 */
Elf64_Ctx*    elf_open(const char *filename);
void          elf_close(Elf64_Ctx *ctx);
Elf64_Ehdr*   elf_get_ehdr(Elf64_Ctx *ctx);
const char*   elf_strtab_get(Elf64_Ctx *ctx, Elf64_Off stroff, Elf64_Word idx);
const char*   elf_dynstr_get(Elf64_Ctx *ctx, Elf64_Off stroff, Elf64_Word idx);
Elf64_Shdr*   elf_get_shdr(Elf64_Ctx *ctx, int index);
Elf64_Phdr*   elf_get_phdr(Elf64_Ctx *ctx, int index);
const char*   elf_section_name(Elf64_Ctx *ctx, int index);
const char*   elf_sh_type_str(Elf64_Word sh_type);
const char*   elf_sh_flags_str(Elf64_Xword sh_flags, char *buf, size_t bufsz);
const char*   elf_p_type_str(Elf64_Word p_type);
const char*   elf_p_flags_str(Elf64_Word p_flags, char *buf, size_t bufsz);
const char*   elf_e_type_str(Elf64_Half e_type);
const char*   elf_e_machine_str(Elf64_Half e_machine);
const char*   elf_e_osabi_str(unsigned char osabi);
const char*   elf_st_bind_str(unsigned char info);
const char*   elf_st_type_str(unsigned char info);
const char*   elf_d_tag_str(Elf64_Sxword d_tag);
const char*   elf_reloc_type_str(int machine, Elf64_Xword r_info);
const char*   elf_note_type_str(Elf64_Word n_type);

/* 字段数组管理 */
Elf64_Field*  fields_alloc(int count);
void          fields_free(Elf64_Field *fields, int count);
void          field_set(Elf64_Field *f, const char *text, int indent,
                        int selectable, DetailKind kind, int index);
int           fields_add(PanelData *pd, const char *text, int indent,
                         int selectable, DetailKind kind, int index);

/* strings.c — 字符串表操作 */
char*         elf_strtable_extract(Elf64_Ctx *ctx, Elf64_Off offset,
                                   Elf64_Xword size);

/* security.c — 安全加固检查 */
int           parse_security(Elf64_Ctx *ctx, PanelData *pd);

/* disasm.c — Capstone 反汇编 (Intel 语法) */
int           parse_disasm(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* danger.c — 危险函数调用检测 (Pass1 字符串 + Pass2 反汇编) */
int           parse_danger(Elf64_Ctx *ctx, PanelData *pd);

/* callgraph.c — 函数交叉引用图 (caller → callees) */
int           parse_callgraph(Elf64_Ctx *ctx, PanelData *pd);

/* cfg_view.c — 控制流图 (基本块 + 边 + ASCII 渲染) */
int           parse_cfg_view(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* xref.c — 交叉引用查看器 (代码/数据 xref 按目标分组) */
int           parse_xref(Elf64_Ctx *ctx, PanelData *pd);

/* hexdump.c — Hex dump 视图 (类似 xxd) */
int           parse_hexdump(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* seg_perm.c — 段权限冲突检测 (RWX/重叠) */
int           parse_seg_perm(Elf64_Ctx *ctx, PanelData *pd);

/* mem_layout.c — 内存布局 ASCII 可视化 */
int           parse_mem_layout(Elf64_Ctx *ctx, PanelData *pd);

/* init_array.c — init/fini/preinit 数组展开 */
int           parse_init_array(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* got_plt.c — GOT/PLT 表解析 */
int           parse_got_plt(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* attack_surface.c — 攻击面摘要 (网络/文件/进程) */
int           parse_attack_surface(Elf64_Ctx *ctx, PanelData *pd);

/* gadget.c — ROP Gadget 搜索 */
int           parse_gadget(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* func_boundary.c — 函数边界扫描 */
int           parse_func_boundary(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* strings_xref.c — 字符串交叉引用 */
int           parse_strings_xref(Elf64_Ctx *ctx, PanelData *pd);

/* eh_frame.c — .eh_frame DWARF CFI 栈展开表解析 */
int           parse_eh_frame(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* search.c — 符号/地址/字符串搜索 */
int           search_symbol(Elf64_Ctx *ctx, const char *query, PanelData *pd);
int           search_address(Elf64_Ctx *ctx, Elf64_Addr addr, PanelData *pd);
int           search_string(Elf64_Ctx *ctx, const char *pattern, PanelData *pd);
int           search_disasm(Elf64_Ctx *ctx, const char *query, PanelData *pd);
int           search_bytes(Elf64_Ctx *ctx, const char *pattern, PanelData *pd);

/* ehdr.c — ELF Header 解析 */
int           parse_ehdr(Elf64_Ctx *ctx, PanelData *pd);

/* phdr.c — Program Headers 解析 */
int           parse_phdr(Elf64_Ctx *ctx, PanelData *pd);

/* shdr.c — Section Headers 解析 */
int           parse_shdr_list(Elf64_Ctx *ctx, PanelData *pd);
int           parse_shdr_detail(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* symtab.c — 符号表解析 */
int           parse_symtab(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
int           parse_sym_detail(Elf64_Ctx *ctx, int shdr_idx,
                               int sym_idx, PanelData *pd);

/* dynamic.c — 动态节解析 */
int           parse_dynamic(Elf64_Ctx *ctx, PanelData *pd);

/* rela.c — 重定位表解析 */
int           parse_rela(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* note.c — 注释节解析 */
int           parse_note(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* version.c — 版本信息解析 */
int           parse_version(Elf64_Ctx *ctx, PanelData *pd);

/* registers.c — NT_PRSTATUS 寄存器解析 */
int           parse_registers(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* expr_eval.c — 表达式求值引擎 */
int           expr_eval(const char *expr, uint64_t regs[], uint64_t *result);

/* syscall_ctx.c — x86-64 系统调用表 */
int           syscall_lookup(const char *name, PanelData *pd);
int           syscall_list_all(PanelData *pd);

/* one_gadget.c — One-gadget 搜索器 */
int           one_gadget_search(Elf64_Ctx *ctx, PanelData *pd);

/* bp_condition.c — 条件断点引擎 */
int           bp_condition_parse(const char *cond_str, void *cond);
int           bp_condition_eval(const void *cond, const uint64_t regs[]);
int           bp_condition_format(const void *cond, char *buf, size_t bufsz);

/* vmmap_live.c — 运行时内存映射 (依赖 debug_worker.h) */
int           vmmap_to_panel(const void *ds, PanelData *pd);

/* symbol_resolve.c — 运行时符号解析 */
int           symbol_resolve_live(void *ds, const char *name, PanelData *pd);

/* backtrace.c — RBP 链栈回溯 */
int           backtrace_unwind(void *ds, void *frames, int max);

/* telescope.c — 指针解引用链 */
int           telescope_chain(void *ds, uint64_t addr, PanelData *pd);

/* taint.c — 污点追踪引擎 (依赖 disasm.h) */
struct disasm_ctx;
typedef struct taint_report_t taint_report_t;
int           taint_analyze(Elf64_Ctx *ctx, struct disasm_ctx *d, taint_report_t *report);
void          taint_report_free(taint_report_t *r);
int           parse_taint(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* translate_insn.c — 指令语义自然语言翻译 */
struct cs_insn;
int           translate_insn(const struct cs_insn *insn, char *buf, size_t bufsz);
int           translate_disasm_section(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);


/* translate_vuln.c — 漏洞视角风险报告 */
int           translate_vuln_single(const char *func_name, char *buf, size_t sz);
int           translate_vuln_scan(Elf64_Ctx *ctx, PanelData *pd);

/* rop_chain.c — ROP 链编译器 (内部类型, 无公共 PanelData 接口) */

/* stack_view.c — 栈视图面板 (运行时调试) */
int           render_stack_view(void *ds, Elf64_Ctx *ctx, PanelData *pd);

/* hw_breakpoint.c — 硬件断点 (DR0-DR7) */
int           hw_breakpoint_set(void *ds, int slot, uint64_t addr, int type);
int           hw_breakpoint_clear(void *ds, int slot);
int           hw_breakpoint_list(void *ds, PanelData *pd);

/* dataflow.c — 基于 IR 的函数内数据流分析 (use-def/liveness/value-range) */
int           parse_dataflow(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
void          dataflow_set_target(uint64_t addr);  /* 设置分析目标地址 */

/* dataflow_inter.c — 跨过程数据流分析 (callgraph + IR) */
int           parse_dataflow_inter(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* trace_view.c — 执行 Trace 可视化 (PT/BTS session 列表/覆盖率/时间轴) */
struct AnalysisDB;  /* 前向声明 (定义在 core/db.h) */
int           parse_trace_view(Elf64_Ctx *ctx, int session_id, PanelData *pd);
int           trace_view_handle_key(struct AnalysisDB *adb, int session_id,
                                    int key, PanelData *pd);

/* bindiff_view.c — 二进制差异比对面板 */
int           parse_bindiff_view(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

/* decompile.c — C 伪代码反编译引擎 */
int           parse_decompile(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
int           decompile_function_at(uint64_t func_addr, PanelData *pd);

#endif /* ELF_PARSER_H */
