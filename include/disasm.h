/*
 * disasm.h — Capstone x86-64 反汇编引擎 (elf-tui)
 *
 * 修复自 elf-disasm/src/disasm_engine.c 的审计问题:
 *   Fix #1: 启用 CS_OPT_DETAIL (detail 非 NULL, 可分析操作数)
 *   Fix #2: 移除无用 cs_insn* 参数, 接口清晰
 *   Fix #3: 移除 output.h 依赖, 纯返回码
 *   Fix #4: 添加 disasm_section() 便捷函数
 *   Fix #5: 失败时可查 cs_errno()
 *
 * 依赖: libcapstone (pkg-config capstone)
 * 链接: -lcapstone
 */
#ifndef DISASM_H
#define DISASM_H

#include <capstone/capstone.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ================================================================== */
/* Opaque context                                                     */
/* ================================================================== */
typedef struct disasm_ctx disasm_ctx;

/* ================================================================== */
/* Lifecycle                                                          */
/* ================================================================== */

/**
 * 创建 x86-64 反汇编上下文。
 * 自动配置: Intel 语法 + CS_OPT_DETAIL (启用操作数分析)
 *
 * 返回 NULL 表示 Capstone 初始化失败。
 */
disasm_ctx *disasm_open(void);

/**
 * 销毁上下文, 释放 Capstone handle 和内部缓冲区。
 */
void disasm_close(disasm_ctx *d);

/* ================================================================== */
/* 单步反汇编 (热路径, 零堆分配)                                      */
/* ================================================================== */

/**
 * 解码一条指令。
 *
 * 成功:  *code,*size,*address 前进, 结果通过 disasm_insn(d) 获取, 返回 true
 * 失败:  指针不变, 返回 false
 *
 * 获取解码结果:  disasm_insn(d)->address / ->mnemonic / ->op_str / ->detail
 */
bool disasm_next(disasm_ctx *d,
                 const uint8_t **code, size_t *size,
                 uint64_t *address);

/**
 * 返回当前解码的指令 (内部缓冲区指针, 不要 free)。
 * 只在 disasm_next() 返回 true 后有效。
 */
cs_insn *disasm_insn(disasm_ctx *d);

/**
 * 返回最后一次 disasm_next 失败的错误码。
 * CS_ERR_OK = 没有错误。
 */
cs_err disasm_last_error(const disasm_ctx *d);

/**
 * 返回原始 Capstone handle (供 cs_reg_name 等高级 API 使用)。
 */
csh disasm_handle(const disasm_ctx *d);

/* ================================================================== */
/* 批量反汇编 (便捷函数)                                              */
/* ================================================================== */

/**
 * 对一个内存区域进行完整的线性反汇编。
 *
 * 回调 cb 对每条解码的指令调用一次。返回 false 可提前终止。
 * 返回成功解码的指令数。
 */
typedef bool (*disasm_callback_t)(const cs_insn *insn, void *user);

int disasm_run(disasm_ctx *d,
               const uint8_t *code, size_t size, uint64_t base_addr,
               disasm_callback_t cb, void *user);

/* ================================================================== */
/* Capstone 版本                                                      */
/* ================================================================== */

/** 返回 Capstone 库版本号 (major << 8 | minor) */
unsigned int disasm_version(void);

#endif /* DISASM_H */
