/*
 * ir.h — IR (中间表示) 抽象层
 *
 * 设计原则:
 *   1. 与 DB 中的 ir_stmts 表对齐 (op_type: reg_read/reg_write/mem_access/immediate)
 *   2. 可插拔提升器注册表 (ir_lifter_t) — 支持 x86-64/AArch64/RISC-V
 *   3. 分析引擎消费 IR → 产生 PanelData (不修改已有代码路径)
 *
 * 架构:
 *   Capstone → ir_stmts (DB, 已有)
 *   ir_lift.c → ir_bb_t (内存, 结构化)
 *   ir_analysis.c → use-def chains, liveness, reaching-defs
 *   dataflow.c  → PanelData (TUI 展示)
 */

#ifndef IR_H
#define IR_H

#include <stdint.h>
#include <stddef.h>
#include "elf_parser.h"   /* PanelData, Elf64_Ctx */
#include "db.h"           /* AnalysisDB */

/* ================================================================== */
/* IR 操作类型 (与 ir_stmts.op_type 对齐)                              */
/* ================================================================== */

typedef enum {
    IR_REG_READ   = 0,  /* dst = register[src]; 从寄存器读 */
    IR_REG_WRITE  = 1,  /* register[dst] = src; 向寄存器写 */
    IR_MEM_LOAD   = 2,  /* dst = Mem[base + disp] */
    IR_MEM_STORE  = 3,  /* Mem[base + disp] = src */
    IR_IMMEDIATE  = 4,  /* dst = immediate_value */
    IR_ALU_OP     = 5,  /* dst = src1 op src2 (加减乘除移位) */
    IR_CALL       = 6,  /* call target; dst = return_value */
    IR_JMP_COND   = 7,  /* if (flags) goto target */
    IR_JMP_ALWAYS = 8,  /* goto target */
    IR_RET        = 9,  /* return */
    IR_SYSCALL    = 10, /* syscall */
    IR_PUSH       = 11, /* rsp -= 8; Mem[rsp] = src */
    IR_POP        = 12, /* dst = Mem[rsp]; rsp += 8 */
} ir_op_type_t;

/* ================================================================== */
/* IR 操作数                                                           */
/* ================================================================== */

typedef enum {
    OPND_NONE   = 0,
    OPND_REG    = 1,  /* 寄存器: 值为 x86_reg 枚举或寄存器名 */
    OPND_MEM    = 2,  /* 内存: base + disp */
    OPND_IMM    = 3,  /* 立即数 */
    OPND_ADDR   = 4,  /* 绝对地址 */
} ir_opnd_type_t;

typedef struct {
    ir_opnd_type_t type;
    union {
        int      reg;       /* OPND_REG: Capstone x86_reg 值 */
        int64_t  imm;       /* OPND_IMM: 立即数 */
        uint64_t addr;      /* OPND_ADDR: 绝对地址 */
        struct {
            int     base;   /* OPND_MEM: 基址寄存器 */
            int64_t disp;   /*          偏移量 */
        } mem;
    };
} ir_opnd_t;

/* ================================================================== */
/* IR 语句                                                             */
/* ================================================================== */

typedef struct {
    ir_op_type_t  op_type;
    ir_opnd_t     dst;       /* 目标操作数 */
    ir_opnd_t     src1;      /* 源操作数 1 */
    ir_opnd_t     src2;      /* 源操作数 2 (用于 ALU) */
    uint64_t      address;   /* 源指令地址 */
    int           stmt_idx;  /* 该指令内的 IR 语句序号 */
    int           size;      /* 操作大小 (字节) */
} ir_stmt_t;

/* ================================================================== */
/* IR 基本块                                                           */
/* ================================================================== */

typedef struct {
    uint64_t   start_addr;   /* 第一个源指令的地址 */
    uint64_t   end_addr;     /* 最后一个源指令的地址 */
    uint64_t   func_addr;    /* 所属函数地址 */
    ir_stmt_t *stmts;        /* IR 语句数组 */
    int        stmt_count;
    int        stmt_cap;
    /* 后继基本块索引 */
    int        succ[2];
    int        succ_count;
} ir_bb_t;

/* ================================================================== */
/* IR 函数                                                            */
/* ================================================================== */

#define IR_FUNC_NAME_MAX 128
typedef struct {
    uint64_t  start_addr;
    uint64_t  end_addr;
    char      name[IR_FUNC_NAME_MAX];
    ir_bb_t  *bbs;
    int       bb_count;
    int       bb_cap;
} ir_func_t;

/* ================================================================== */
/* Use-Def 分析结果                                                    */
/* ================================================================== */

typedef struct {
    uint64_t  use_addr;      /* 使用该值的指令地址 */
    uint64_t  def_addr;      /* 定义该值的指令地址 */
    uint64_t  func_addr;     /* 所属函数 */
    int       var_kind;      /* 0=register, 1=memory */
    int       reg_id;        /* Capstone 寄存器 ID (仅 register) */
    int       distance;      /* 指令间的距离 (条数) */
} ir_use_def_t;

/* ================================================================== */
/* 活跃变量分析结果                                                    */
/* ================================================================== */

typedef struct {
    uint64_t  insn_addr;     /* 指令地址 */
    int       live_regs[32]; /* 活跃寄存器位图 (1=live, 0=dead) */
} ir_liveness_t;

/* ================================================================== */
/* 值域分析结果                                                        */
/* ================================================================== */

typedef struct {
    uint64_t  insn_addr;
    int       reg_id;        /* -1 = 内存位置 */
    int64_t   min_val;       /* 最小值 (INT64_MIN = unknown) */
    int64_t   max_val;       /* 最大值 (INT64_MAX = unknown) */
    int       is_top;        /* 1 = 未知/任意值 */
} ir_value_range_t;

/* ================================================================== */
/* 可插拔 IR 提升器注册表                                             */
/* ================================================================== */

typedef struct ir_lifter {
    const char *name;
    const char *arch;          /* "x86-64", "AArch64", "RISC-V" */
    int         e_machine;     /* ELF e_machine 值 */

    /* 探测: 该架构是否被当前二进制 + 硬件支持 */
    int (*probe)(Elf64_Ctx *ctx);

    /* 单函数提升: 将汇编指令序列转换为 ir_func_t */
    int (*lift_function)(Elf64_Ctx *ctx, uint64_t func_addr,
                         AnalysisDB *adb, ir_func_t *out);

    /* 批量提升: 全量导入到 DB (ir_stmts 表) */
    int (*lift_all)(Elf64_Ctx *ctx, AnalysisDB *adb);
} ir_lifter_t;

/* 全局注册表: NULL 终止数组 */
extern ir_lifter_t *ir_lifters[];

/* ================================================================== */
/* IR 分析 API                                                         */
/* ================================================================== */

/* 从 DB 加载一个函数的 IR 语句到内存 */
ir_func_t* ir_func_load(AnalysisDB *adb, uint64_t func_addr);
void       ir_func_free(ir_func_t *f);

/* Use-Def 链: 对指定地址的指令，找出所有读寄存器的定义点 */
int ir_use_def_query(AnalysisDB *adb, uint64_t insn_addr,
                     ir_use_def_t *results, int max_results);

/* Def-Use 链: 对指定地址的指令，找出所有使用它定义的值的点 */
int ir_def_use_query(AnalysisDB *adb, uint64_t insn_addr,
                     ir_use_def_t *results, int max_results);

/* 活跃变量分析: 对指定函数，计算每个指令点的活跃寄存器集合 */
int ir_liveness_analyze(AnalysisDB *adb, uint64_t func_addr,
                        ir_liveness_t *results, int max_results);

/* 值域分析: 对指定函数做抽象解释，推断寄存器取值范围 */
int ir_value_range_analyze(AnalysisDB *adb, uint64_t func_addr,
                           ir_value_range_t *results, int max_results);

/* 危险调用检测增强: 基于值域分析判断缓冲区操作安全性 */
int ir_check_buffer_safety(AnalysisDB *adb, uint64_t call_addr,
                           PanelData *pd);

/* 自动选择并使用第一个匹配的架构提升器 */
ir_lifter_t* ir_detect_lifter(Elf64_Ctx *ctx);

#endif /* IR_H */
