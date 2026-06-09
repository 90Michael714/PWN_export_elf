/*
 * eh_frame.c — .eh_frame / DWARF CFI 解析器 (Prompt 13)
 *
 * .eh_frame = 异常处理帧信息, 本质上是程序栈展开表 (Call Frame Information).
 *
 * 对漏洞研究的独特价值:
 *   1. 函数边界: FDE 的 PC_start + PC_range 给出精确的函数范围
 *      → 比 .symtab 更可靠, 包含 stripped 函数, 且包含内联代码的范围
 *   2. 栈布局: CFA 偏移 → 知道返回地址在栈上的位置
 *      → ROP chain 构造时精确计算偏移
 *   3. 保存在哪: 寄存器保存规则 → 知道 rbx/rbp/r12..r15 保存在栈的哪个位置
 *      → 信息泄露/栈溢出利用的精确目标
 *   4. Personality/LSDA: 标识哪些函数有 C++ 异常处理器
 *      → LSDA 指针指向 catch/cleanup 表, 额外攻击面
 *
 * DWARF .eh_frame 格式:
 *   CIE (Common Information Entry):
 *     length(4B) + CIE_id(4B=0) + version(1B) + aug(string) +
 *     code_align(LEB128) + data_align(LEB128) + ret_reg(LEB128) +
 *     [aug data if 'z'] + initial_instructions
 *
 *   FDE (Frame Description Entry):
 *     length(4B) + CIE_ptr(4B) + PC_start(enc) + PC_range(enc) +
 *     [aug data if CIE 'z'] + instructions
 *
 * 符合 COORDINATION.md: int parse_eh_frame(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 * 依赖: 无 (纯字节解析, 不需要 Capstone)
 */
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ================================================================== */
/* DWARF 编码常量                                                     */
/* ================================================================== */

/* 指针编码 (DW_EH_PE_*) */
enum {
    PE_ABS   = 0x00,  /* 绝对地址 */
    PE_PCREL = 0x10,  /* 相对于当前 PC */
    PE_DATAREL=0x30,  /* 相对于数据段基址 */
    PE_FUNCREL=0x40, /* 相对于函数基址 */
    PE_ALIGNED=0x50, /* 对其的绝对地址 */

    PE_OMIT   = 0xFF, /* 省略 */
};

/* 编码修饰符 */
#define PE_INDIRECT  0x80  /* 值是间接指针 (需额外解引用) */
#define PE_UDATA4    0x03  /* unsigned 4-byte */
#define PE_SDATA4    0x0B  /* signed 4-byte */
#define PE_UDATA8    0x04  /* unsigned 8-byte */
#define PE_SDATA8    0x0C  /* signed 8-byte */
#define PE_ULEB      0x01  /* ULEB128 */
#define PE_SLEB      0x09  /* SLEB128 */

/* DW_CFA 操作码 */
enum {
    CFA_NOP              = 0x00,
    CFA_SET_LOC          = 0x01,
    CFA_ADVANCE_LOC1     = 0x02,
    CFA_ADVANCE_LOC2     = 0x03,
    CFA_ADVANCE_LOC4     = 0x04,
    CFA_OFFSET_EXT       = 0x05,
    CFA_RESTORE_EXT      = 0x06,
    CFA_UNDEFINED        = 0x07,
    CFA_SAME_VALUE       = 0x08,
    CFA_REGISTER         = 0x09,
    CFA_REMEMBER_STATE   = 0x0A,
    CFA_RESTORE_STATE    = 0x0B,
    CFA_DEF_CFA          = 0x0C,
    CFA_DEF_CFA_REGISTER = 0x0D,
    CFA_DEF_CFA_OFFSET   = 0x0E,
    CFA_DEF_CFA_EXPR     = 0x0F,
    CFA_EXPRESSION       = 0x10,
    CFA_OFFSET_EXT_SF    = 0x11,
    CFA_DEF_CFA_SF       = 0x12,
    CFA_DEF_CFA_OFFSET_SF= 0x13,
    CFA_VAL_OFFSET       = 0x14,
    CFA_VAL_OFFSET_SF    = 0x15,
    CFA_VAL_EXPRESSION   = 0x16,
    CFA_GNU_ARGS_SIZE    = 0x2E,
    CFA_GNU_NEGATIVE_OFFSET_EXT = 0x2F,
};

/* ================================================================== */
/* LEB128 编解码                                                      */
/* ================================================================== */

/** 从缓冲区解码 ULEB128, 返回消耗的字节数 */
static int decode_uleb128(const uint8_t *data, const uint8_t *end,
                          uint64_t *val)
{
    *val = 0;
    int shift = 0;
    int i = 0;
    while (data + i < end) {
        uint8_t byte = data[i++];
        *val |= (uint64_t)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) return i;
        shift += 7;
    }
    return -1; /* 截断 */
}

/** 从缓冲区解码 SLEB128 */
static int decode_sleb128(const uint8_t *data, const uint8_t *end,
                          int64_t *val)
{
    *val = 0;
    int shift = 0;
    int i = 0;
    uint8_t byte;
    while (data + i < end) {
        byte = data[i++];
        *val |= (int64_t)(byte & 0x7F) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) break;
    }
    /* 符号扩展: 如果最高有效位是 1 */
    if (shift < 64 && (byte & 0x40))
        *val |= -(1LL << shift);
    return i;
}

/* ================================================================== */
/* DWARF 指针解码                                                     */
/* ================================================================== */

/**
 * 解码编码后的 DWARF 指针。
 * @param data   数据指针 (会被更新)
 * @param end    缓冲区末尾
 * @param enc    编码字节
 * @param base   解码基准地址 (如 CIE 地址, 数据段基址)
 * @param pc     当前 PC 值 (用于 PC-relative 解码)
 * @param result 输出: 解码后的绝对地址
 * @return 0 成功, -1 失败
 */
static int decode_ptr(const uint8_t **data, const uint8_t *end,
                      uint8_t enc, uint64_t base, uint64_t pc,
                      uint64_t *result)
{
    if (enc == PE_OMIT || enc == 0) {
        *result = 0;
        return 0;
    }

    uint8_t fmt = enc & 0x0F;
    uint64_t val = 0;

    switch (fmt) {
    case PE_ULEB: {
        int n = decode_uleb128(*data, end, &val);
        if (n < 0) return -1;
        *data += n;
        break;
    }
    case PE_SLEB: {
        int64_t sval;
        int n = decode_sleb128(*data, end, &sval);
        if (n < 0) return -1;
        *data += n;
        val = (uint64_t)sval;
        break;
    }
    case PE_UDATA4: case PE_SDATA4:
        if (*data + 4 > end) return -1;
        val = (uint64_t)(*(const uint32_t *)(*data));
        if (fmt == PE_SDATA4 && (val & 0x80000000))
            val |= 0xFFFFFFFF00000000ULL;
        *data += 4;
        break;
    case PE_UDATA8: case PE_SDATA8:
        if (*data + 8 > end) return -1;
        val = *(const uint64_t *)(*data);
        *data += 8;
        break;
    default:
        /* 不支持 ABS/其他 */
        if (end - *data >= (ptrdiff_t)sizeof(void *)) {
            val = (uint64_t)(*(const uintptr_t *)(*data));
            *data += sizeof(void *);
        } else {
            return -1;
        }
        break;
    }

    /* 应用地址修饰符 */
    uint8_t mod = enc & 0xF0;
    switch (mod) {
    case PE_PCREL:  *result = pc + val;     break; /* 注意: DWARF 的 "PC" 是编码字段的地址 */
    case PE_DATAREL: *result = base + val;   break;
    case PE_FUNCREL: *result = base + val;   break;
    default:         *result = val;          break; /* PE_ABS 或未知 */
    }

    /* 间接指针: 需要从内存读取 (在 ELF 分析中跳过此步) */
    if (enc & PE_INDIRECT) {
        /* 简化: 不解析间接指针 (需要映射目标地址) */
        *result = val; /* 返回编码值而非解引用后的值 */
    }

    return 0;
}

/* ================================================================== */
/* CFI 记录解析                                                       */
/* ================================================================== */

typedef struct {
    uint64_t    cfa_offset;       /* CFA 相对栈帧的偏移 */
    uint64_t    saved_regs[17];   /* 保存的寄存器偏移 [reg_num] = offset from CFA */
} cfi_state_t;

typedef struct {
    uint64_t offset;         /* CIE 在 .eh_frame 中的偏移 */
    int      version;
    const char *aug_string;  /* 如 "zR", "zPLR" */
    uint8_t  addr_enc;       /* FDE PC 指针编码 */
    uint8_t  lsda_enc;       /* LSDA 指针编码 */
    int      has_aug_data:1;
    int      has_lsda:1;     /* augmentation 包含 'L' */
    int      has_personality:1; /* augmentation 包含 'P' */
    uint64_t code_align;
    int64_t  data_align;
    uint64_t ret_reg;
    uint64_t personality;    /* personality routine 地址 */
} cie_t;

typedef struct {
    uint64_t offset;         /* FDE 在 .eh_frame 中的偏移 */
    uint64_t cie_off;        /* 关联的 CIE 偏移 */
    uint64_t pc_start;
    uint64_t pc_range;
    uint64_t lsda;           /* Language-Specific Data Area 指针 */
    uint64_t personality;    /* 继承自 CIE 的 personality */
    const char *func_name;   /* 从 .symtab 解析的函数名 (可为 NULL) */
} fde_t;

/* ================================================================== */
/* 解析一个 CIE                                                       */
/* ================================================================== */

static int parse_cie(const uint8_t *base, const uint8_t *end,
                     uint64_t cie_off, cie_t *cie)
{
    const uint8_t *p = base + cie_off;
    if (p + 8 > end) return -1;

    memset(cie, 0, sizeof(*cie));
    cie->offset = cie_off;

    /* Length field */
    uint32_t length = *(const uint32_t *)p;
    p += 4;
    if (length == 0 || p + length > end) return -1;

    /* CIE_id: must be 0 */
    uint32_t cie_id = *(const uint32_t *)p;
    p += 4;
    if (cie_id != 0) return -1;  /* not a CIE */

    /* Version */
    cie->version = *p++;

    /* Augmentation string */
    cie->aug_string = (const char *)p;
    while (p < end && *p != '\0') p++;
    if (p >= end) return -1;
    p++; /* skip NUL */

    /* 分析 augmentation */
    if (cie->aug_string[0] == 'z') {
        cie->has_aug_data = 1;
        /* 'z' 后面可能跟 'P' (personality), 'L' (LSDA), 'R' (FDE pointer encoding) */
        for (const char *a = cie->aug_string; *a; a++) {
            if (*a == 'P') cie->has_personality = 1;
            if (*a == 'L') cie->has_lsda = 1;
            if (*a == 'R') {
                /* 下一个字节是地址编码, 但 'R' 本身在 aug string 中 */
                /* 实际编码值在 augmentation data 之前, 之后解析 */
            }
        }
    }

    /* code_alignment_factor (ULEB128) */
    int n = decode_uleb128(p, end, &cie->code_align);
    if (n < 0) return -1;
    p += n;

    /* data_alignment_factor (SLEB128) */
    int64_t dalign;
    n = decode_sleb128(p, end, &dalign);
    if (n < 0) return -1;
    cie->data_align = dalign;
    p += n;

    /* return_address_register (ULEB128) */
    n = decode_uleb128(p, end, &cie->ret_reg);
    if (n < 0) return -1;
    p += n;

    /* Augmentation data (if 'z') */
    if (cie->has_aug_data && p < end) {
        /* z-augmentation: 下一个字节是总长度 */
        uint8_t aug_len = *p++;
        const uint8_t *aug_end = p + aug_len;

        /* 'R': FDE PC pointer encoding */
        if (strchr(cie->aug_string, 'R') && p < aug_end) {
            cie->addr_enc = *p++;
        }

        /* 'L': LSDA pointer encoding */
        if (cie->has_lsda && p < aug_end) {
            cie->lsda_enc = *p++;
        }

        /* 'P': Personality routine */
        if (cie->has_personality && p < aug_end) {
            uint8_t pers_enc = *p++;
            /* 解码 personality routine 地址 */
            uint64_t pers_addr;
            const uint8_t *saved = p;
            if (decode_ptr(&p, aug_end, pers_enc & 0x0F ? pers_enc : PE_UDATA8,
                          cie_off, (uint64_t)(uintptr_t)p, &pers_addr) == 0) {
                cie->personality = pers_addr;
            } else {
                p = saved; /* 解码失败, 跳过 */
            }
        }

        p = aug_end;
    }

    return 0;
}

/* ================================================================== */
/* 解析一个 FDE                                                       */
/* ================================================================== */

static int parse_fde(const uint8_t *base, const uint8_t *end,
                     uint64_t fde_off, const cie_t *cies, int ncies,
                     fde_t *fde, Elf64_Ctx *ctx)
{
    const uint8_t *p = base + fde_off;
    if (p + 8 > end) return -1;

    memset(fde, 0, sizeof(*fde));
    fde->offset = fde_off;

    /* Length */
    uint32_t length = *(const uint32_t *)p;
    p += 4;
    if (length == 0 || p + length > end) return -1;
    const uint8_t *entry_end = p + length;

    /* CIE_pointer */
    uint32_t cie_ptr = *(const uint32_t *)p;
    p += 4;

    /* 找到关联的 CIE */
    uint64_t cie_off = fde_off + 4 - (uint64_t)cie_ptr;
    fde->cie_off = cie_off;

    const cie_t *cie = NULL;
    for (int i = 0; i < ncies; i++) {
        if (cies[i].offset == cie_off) { cie = &cies[i]; break; }
    }
    if (!cie) return -1;
    fde->personality = cie->personality; /* propagated from CIE */

    /* Validate FDE against CIE */
    (void)cie;

    /* 解码 PC_start 和 PC_range */
    uint8_t addr_enc = cie->addr_enc ? cie->addr_enc : PE_ABS;
    const uint8_t *enc_addr = p; /* DWARF PC-relative: "PC" = 编码字段的地址 */

    uint64_t pc_val;
    if (decode_ptr(&p, end, addr_enc,
                   (uint64_t)(uintptr_t)base,   /* 数据段基址 */
                   (uint64_t)(uintptr_t)enc_addr, /* 当前 PC */
                   &pc_val) != 0) return -1;
    fde->pc_start = pc_val;

    /* pc_range 是长度值, 不是地址指针 — 去掉地址修饰符只保留编码格式 */
    if (decode_ptr(&p, end, addr_enc & 0x0F,
                   (uint64_t)(uintptr_t)base,
                   0,
                   &fde->pc_range) != 0) return -1;

    /* Augmentation data */
    if (cie->has_aug_data && p < entry_end) {
        const uint8_t *aug_start = p;
        uint8_t aug_len = *p++;
        const uint8_t *aug_end = p + aug_len;
        if (aug_end > entry_end) aug_end = entry_end;

        /* LSDA (if CIE has 'L') */
        if (cie->has_lsda && p < aug_end) {
            const uint8_t *enc_lsda = p;
            decode_ptr(&p, aug_end, cie->lsda_enc,
                      (uint64_t)(uintptr_t)base,
                      (uint64_t)(uintptr_t)enc_lsda,
                      &fde->lsda);
        }

        p = aug_start + 1 + aug_len; /* 跳过 augmentation data */
        if (p > entry_end) p = entry_end;
    }

    /* 尝试从符号表解析函数名 */
    if (fde->pc_start > 0) {
        int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
        for (int pass = 0; pass < 2; pass++) {
            Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
            for (int si = 0; si < shnum; si++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, si);
                if (!sh || sh->sh_type != want) continue;
                Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
                if (!strsh) continue;

                Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
                int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));

                for (int j = 0; j < nsym; j++) {
                    if (syms[j].st_value == fde->pc_start &&
                        ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC) {
                        const char *n = elf_strtab_get(ctx, strsh->sh_offset,
                                                       syms[j].st_name);
                        if (n && n[0]) {
                            fde->func_name = n;
                            goto found_name;
                        }
                    }
                }
            }
        }
    }
found_name:;

    (void)base; /* unused after pointer decode */
    return 0;
}

/* ================================================================== */
/* DW_CFA 指令解码 (解释执行, 建立 CFA + 寄存器状态)                   */
/* ================================================================== */

/**
 * 在初始状态上执行 CFI 指令序列, 得到最终状态。
 * 返回消耗的字节数, -1 表示出错。
 *
 * 初始状态由 CIE 的 initial_instructions 设定,
 * 每个 FDE 的指令在此基础上修改。
 *
 * 为简洁性, 仅处理最常见的 DW_CFA 操作码。
 */
__attribute__((unused)) static int exec_cfa_instructions(const uint8_t *start, const uint8_t *end,
                                 cfi_state_t *state, uint64_t code_align,
                                 int64_t data_align)
{
    const uint8_t *p = start;
    uint64_t loc = 0; /* 当前 PC (相对值, 用于 advance_loc) */

    while (p < end) {
        uint8_t op = *p++;

        if (op >= 0x40 && op < 0x80) {
            /* CFA_advance_loc(n) — 高 6 位编码增量 */
            loc += (uint64_t)(op & 0x3F) * code_align;
            continue;
        }

        if (op >= 0x80 && op < 0xC0) {
            /* CFA_offset(r, n) — 高 6 位编码偏移 */
            uint8_t reg = op & 0x3F;
            uint64_t off;
            int n = decode_uleb128(p, end, &off);
            if (n < 0) return -1;
            p += n;
            if (reg < 17) state->saved_regs[reg] = off * (uint64_t)data_align;
            continue;
        }

        switch (op) {
        case CFA_NOP:
            break;

        case CFA_ADVANCE_LOC1:
            if (p >= end) return -1;
            loc += (uint64_t)(*p++) * code_align;
            break;

        case CFA_ADVANCE_LOC2:
            if (p + 2 > end) return -1;
            loc += (uint64_t)(*(const uint16_t *)p) * code_align;
            p += 2;
            break;

        case CFA_ADVANCE_LOC4:
            if (p + 4 > end) return -1;
            loc += (uint64_t)(*(const uint32_t *)p) * code_align;
            p += 4;
            break;

        case CFA_DEF_CFA: {
            /* def_cfa(reg, offset) → CFA = reg:offset */
            uint64_t reg, off;
            int n1 = decode_uleb128(p, end, &reg);
            { if (n1 < 0) return -1; p += n1; }
            int n2 = decode_uleb128(p, end, &off);
            { if (n2 < 0) return -1; p += n2; }
            state->cfa_offset = off;
            break;
        }

        case CFA_DEF_CFA_OFFSET: {
            /* def_cfa_offset(off) */
            uint64_t off;
            int n = decode_uleb128(p, end, &off);
            { if (n < 0) return -1; p += n; }
            state->cfa_offset = off;
            break;
        }

        case CFA_REMEMBER_STATE:
        case CFA_RESTORE_STATE:
            /* 简化: 不维护状态栈, 跳过后续指令直到遇到还原 */
            break;

        case CFA_NOP+1: /* CFA_set_loc — 引入定位 */
        default: {
            /* 实际地址已被 FDE 的 PC_start + loc 覆盖, 这里追踪 loc */
            break;
        }

            /* 未处理的操作码: 跳过 */
            break;
        }
    }

    (void)loc;
    return 0;
}

/* ================================================================== */
/* 符号名解析                                                         */
/* ================================================================== */


/* ================================================================== */
/* 公共接口: parse_eh_frame                                           */
/* ================================================================== */

int parse_eh_frame(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    /* 查找 .eh_frame 节 */
    Elf64_Shdr *sh = NULL;
    const char *sec_name = NULL;

    if (shdr_idx >= 0) {
        sh = elf_get_shdr(ctx, shdr_idx);
        sec_name = elf_section_name(ctx, shdr_idx);
    } else {
        int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
        for (int i = 0; i < shnum; i++) {
            const char *n = elf_section_name(ctx, i);
            if (n && strcmp(n, ".eh_frame") == 0) {
                sh = elf_get_shdr(ctx, i);
                sec_name = n;
                break;
            }
        }
    }
    (void)sec_name; /* used for debugging / future display */

    if (!sh || sh->sh_size == 0) {
        fields_add(pd, "(.eh_frame section not found)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const uint8_t *data = ctx->map + sh->sh_offset;
    size_t size = sh->sh_size;

    char buf[320];
    snprintf(buf, sizeof(buf), "=== .eh_frame Analysis (%lu bytes) ===",
             (unsigned long)size);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "(DWARF Call Frame Information — stack unwinding table)",
               1, 0, DETAIL_NONE, -1);

    /* -------------------------------------------------------------- */
    /* Pass 1: 收集所有 CIE                                            */
    /* -------------------------------------------------------------- */
    cie_t cies[256];
    int ncies = 0;

    {
        const uint8_t *p = data;
        const uint8_t *end = data + size;

        while (p + 4 <= end) {
            uint32_t length = *(const uint32_t *)p;
            if (length == 0) { p += 4; continue; } /* terminator */
            if (p + 4 + length > end) break;

            uint32_t cie_id = *(const uint32_t *)(p + 4);
            if (cie_id == 0 && ncies < 256) {
                uint64_t off = (uint64_t)(uintptr_t)(p - data);
                if (parse_cie(data, end, off, &cies[ncies]) == 0) {
                    ncies++;
                }
            }

            p += 4 + length;
        }
    }

    snprintf(buf, sizeof(buf), "CIEs found: %d", ncies);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 显示每个 CIE 摘要 */
    for (int c = 0; c < ncies && c < 20; c++) {
        const char *aug = cies[c].aug_string;
        if (!aug || !aug[0]) aug = "(none)";
        char extra[64] = "";
        if (cies[c].has_personality) strcat(extra, " PERS");
        if (cies[c].has_lsda)        strcat(extra, " LSDA");
        snprintf(buf, sizeof(buf),
                 "CIE[%d]: version=%d, aug=\"%s\"%s, "
                 "code_align=%lu, data_align=%ld, ret_reg=r%lu",
                 c, cies[c].version, aug, extra,
                 (unsigned long)cies[c].code_align,
                 (long)cies[c].data_align,
                 (unsigned long)cies[c].ret_reg);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    /* -------------------------------------------------------------- */
    /* Pass 2: 收集所有 FDE                                            */
    /* -------------------------------------------------------------- */
    #define MAX_FDES 2048
    fde_t *fdes = malloc(MAX_FDES * sizeof(fde_t));
    int nfdes = 0;

    if (fdes) {
        const uint8_t *p = data;
        const uint8_t *end = data + size;

        while (p + 4 <= end && nfdes < MAX_FDES) {
            uint32_t length = *(const uint32_t *)p;
            if (length == 0) { p += 4; continue; }
            if (p + 4 + length > end) break;

            uint32_t cie_id = *(const uint32_t *)(p + 4);
            if (cie_id != 0) { /* FDE: CIE_id is non-zero */
                uint64_t off = (uint64_t)(uintptr_t)(p - data);
                parse_fde(data, end, off, cies, ncies, &fdes[nfdes], ctx);
                if (fdes[nfdes].pc_start > 0)
                    nfdes++;
            }

            p += 4 + length;
        }
    }

    snprintf(buf, sizeof(buf), "FDEs found: %d (function coverage records)", nfdes);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (nfdes == 0) {
        fields_add(pd, "(no FDEs — unusual for a compiled binary)", 1, 0, DETAIL_NONE, -1);
        free(fdes);
        return pd->count;
    }

    /* -------------------------------------------------------------- */
    /* 用 FDE 覆盖范围计算总代码大小                                    */
    /* -------------------------------------------------------------- */
    uint64_t total_code = 0;
    uint64_t min_addr = UINT64_MAX, max_addr = 0;
    for (int i = 0; i < nfdes; i++) {
        total_code += fdes[i].pc_range;
        if (fdes[i].pc_start < min_addr) min_addr = fdes[i].pc_start;
        if (fdes[i].pc_start + fdes[i].pc_range > max_addr)
            max_addr = fdes[i].pc_start + fdes[i].pc_range;
    }

    uint64_t coverage = max_addr - min_addr;
    snprintf(buf, sizeof(buf),
             "Coverage: 0x%lx-0x%lx (%lu KB) across %d functions",
             (unsigned long)min_addr, (unsigned long)max_addr,
             (unsigned long)coverage / 1024, nfdes);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* -------------------------------------------------------------- */
    /* 输出 FDE 列表                                                   */
    /* -------------------------------------------------------------- */
    fields_add(pd, "─ ─ ─ Function Coverage Records (FDEs) ─ ─ ─",
               0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < nfdes; i++) {
        fde_t *f = &fdes[i];
        const char *fn = f->func_name;

        char fn_buf[64];
        if (!fn || !fn[0]) {
            snprintf(fn_buf, sizeof(fn_buf), "sub_0x%lx",
                     (unsigned long)f->pc_start);
            fn = fn_buf;
        }

        /* 查找关联 CIE */
        int cie_idx = -1;
        for (int c = 0; c < ncies; c++) {
            if (cies[c].offset == f->cie_off) { cie_idx = c; break; }
        }

        char tags[64] = "";
        if (cie_idx >= 0) {
            snprintf(tags, sizeof(tags), "CIE=%d", cie_idx);
        }
        if (f->personality) strcat(tags, " PERS");
        if (f->lsda)        strcat(tags, " LSDA");

        /* 行 1: FDE 编号 + 函数名 */
        snprintf(buf, sizeof(buf), "[%d] %s", i, fn);
        fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)f->pc_start);

        /* 行 2: 地址区间 + 大小 + CIE/属性 */
        {
            unsigned long sz = (unsigned long)f->pc_range;
            char size_str[32];
            if (sz >= 1024 * 1024)
                snprintf(size_str, sizeof(size_str), "%.2fMB", (double)sz / (1024.0 * 1024.0));
            else if (sz >= 1024)
                snprintf(size_str, sizeof(size_str), "%.1fKB", (double)sz / 1024.0);
            else
                snprintf(size_str, sizeof(size_str), "%luB", sz);

            snprintf(buf, sizeof(buf),
                     "    0x%lx-0x%lx   %s   %s",
                     (unsigned long)f->pc_start,
                     (unsigned long)(f->pc_start + f->pc_range),
                     size_str,
                     tags[0] ? tags : "");
        }
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    /* -------------------------------------------------------------- */
    /* 统计摘要                                                        */
    /* -------------------------------------------------------------- */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    /* 统计: 有 personality 的函数 */
    int npers = 0, nlsda = 0;
    for (int i = 0; i < nfdes; i++) {
        if (fdes[i].personality) npers++;
        if (fdes[i].lsda)        nlsda++;
    }

    snprintf(buf, sizeof(buf),
             "Summary: %d CIEs, %d FDEs, %lu KB total code",
             ncies, nfdes, (unsigned long)total_code / 1024);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf),
             "Functions with personality routine: %d  |  with LSDA (catch/cleanup): %d",
             npers, nlsda);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (nlsda > 0) {
        fields_add(pd, "[!] LSDA = Language-Specific Data Area "
                   "(C++ exception catch/cleanup — potential attack surface)",
                   2, 0, DETAIL_NONE, -1);
    }

    free(fdes);
    return pd->count;
}
