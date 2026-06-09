/*
 * disasm.c — Capstone x86-64 反汇编引擎 (elf-tui)
 *
 * 修复自 elf-disasm/src/disasm_engine.c:
 *   Fix #1: CS_OPT_DETAIL 已启用 → insn->detail 非 NULL
 *   Fix #2: insn 参数已移除 → 统一用 disasm_insn() 获取结果
 *   Fix #3: 无外部依赖 → 纯返回码
 *   Fix #4: disasm_run() 回调式批量反汇编
 *   Fix #5: disasm_last_error() 可查失败原因
 *
 * 符合 COORDINATION.md 规范:
 *   实现 parse_disasm(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 */
#include "disasm.h"
#include "elf_parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 自然语言翻译 (translate_insn.c 提供) */
extern int translate_insn(const struct cs_insn *insn, char *buf, size_t bufsz);

/* ================================================================== */
/* 内部结构                                                           */
/* ================================================================== */

struct disasm_ctx {
    csh      handle;         /* Capstone library handle                */
    cs_insn *buf;            /* reusable instruction (cs_malloc)       */
    cs_err   last_err;       /* 最后一次失败的错误码                   */
};

/* ================================================================== */
/* Lifecycle                                                          */
/* ================================================================== */

disasm_ctx *disasm_open(void)
{
    csh handle = 0;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != CS_ERR_OK) {
        fprintf(stderr, "disasm: cs_open failed: %s\n", cs_strerror(err));
        return NULL;
    }

    /* Intel 语法 */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    /* Fix #1: 启用 detail 模式 — 这是关键修复 */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    /* 预分配可复用的指令缓冲区 (热路径零堆分配) */
    cs_insn *buf = cs_malloc(handle);
    if (!buf) {
        fprintf(stderr, "disasm: cs_malloc failed\n");
        cs_close(&handle);
        return NULL;
    }

    disasm_ctx *d = calloc(1, sizeof(*d));
    if (!d) {
        fprintf(stderr, "disasm: out of memory\n");
        cs_free(buf, 1);
        cs_close(&handle);
        return NULL;
    }

    d->handle   = handle;
    d->buf      = buf;
    d->last_err = CS_ERR_OK;
    return d;
}

void disasm_close(disasm_ctx *d)
{
    if (!d) return;
    cs_free(d->buf, 1);
    cs_close(&d->handle);
    free(d);
}

/* ================================================================== */
/* 单步反汇编 (热路径)                                                */
/* ================================================================== */

bool disasm_next(disasm_ctx *d,
                 const uint8_t **code, size_t *size,
                 uint64_t *address)
{
    if (!d || !code || !size || !address) {
        if (d) d->last_err = CS_ERR_HANDLE;
        return false;
    }

    /* Fix #2 + Fix #5: 直接返回 bool, 失败记录原因 */
    bool ok = cs_disasm_iter(d->handle, code, size, address, d->buf);
    if (ok) {
        d->last_err = CS_ERR_OK;
    } else {
        d->last_err = cs_errno(d->handle);
    }
    return ok;
}

cs_insn *disasm_insn(disasm_ctx *d)
{
    return d ? d->buf : NULL;
}

cs_err disasm_last_error(const disasm_ctx *d)
{
    return d ? d->last_err : CS_ERR_HANDLE;
}

csh disasm_handle(const disasm_ctx *d)
{
    return d ? d->handle : 0;
}

/* ================================================================== */
/* 批量反汇编                                                         */
/* ================================================================== */

int disasm_run(disasm_ctx *d,
               const uint8_t *code, size_t size, uint64_t base_addr,
               disasm_callback_t cb, void *user)
{
    if (!d || !code || !size || !cb) return 0;

    const uint8_t *ptr = code;
    size_t         left = size;
    uint64_t       addr = base_addr;
    int            count = 0;

    while (left > 0 && disasm_next(d, &ptr, &left, &addr)) {
        if (!cb(disasm_insn(d), user))
            break;
        count++;
    }

    return count;
}

/* ================================================================== */
/* Capstone 版本                                                      */
/* ================================================================== */

unsigned int disasm_version(void)
{
    int major = 0, minor = 0;
    return cs_version(&major, &minor);
}

/* ================================================================== */
/* TUI 面板接口: parse_disasm                                         */
/* ================================================================== */

/**
 * 反汇编指定的代码节, 以 PanelData 行输出。
 *
 * 用法: 用户在左侧面板选中 .text 节 → 按 Enter → 调用 parse_disasm
 * 每行格式: "  ADDR:  HEX_BYTES  MNEMONIC  OPERANDS"
 */
int parse_disasm(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_size == 0) {
        fields_add(pd, "(empty section)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const char *sec_name = elf_section_name(ctx, shdr_idx);

    /* 标题 */
    char title[128];
    snprintf(title, sizeof(title),
             "=== Disassembly of section %s ===",
             sec_name ? sec_name : "?");
    fields_add(pd, title, 0, 0, DETAIL_NONE, -1);

    /* 创建反汇编引擎 */
    disasm_ctx *d = disasm_open();
    if (!d) {
        fields_add(pd, "(disasm: Capstone init failed)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const uint8_t *code = ctx->map + sh->sh_offset;
    size_t         size = sh->sh_size;
    uint64_t       addr = sh->sh_addr;
    int            count = 0;

    char buf[256];
    while (size > 0 && disasm_next(d, &code, &size, &addr)) {
        cs_insn *insn = disasm_insn(d);

        /* 构建字节 hex: "55 48 89 e5" */
        char hex[48] = "";
        int hpos = 0;
        for (size_t i = 0; i < insn->size && hpos < (int)sizeof(hex) - 4; i++) {
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%02x ", insn->bytes[i]);
        }

        /* 指令翻译: 匹配规则, 追加自然语言解释 */
        char trans[128];
        translate_insn(insn, trans, sizeof(trans));

        snprintf(buf, sizeof(buf),
                 "  0x%lx:  %-24s  %-8s %-36s %s",
                 (unsigned long)insn->address,
                 hex,
                 insn->mnemonic,
                 insn->op_str,
                 trans);

        fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)(insn->address & 0xFFFF));
        count++;
    }

    disasm_close(d);
    return pd->count;
}
