/*
 * ir_analysis.c — IR 分析引擎 (use-def, liveness, value-range)
 *
 * 消费 ir_stmts 表中的数据，构建内存中分析结构，产出分析结果。
 * 不修改任何已有代码。通过 AnalysisDB + PanelData 接口集成。
 *
 * 算法:
 *   use-def:  对每个 reg_read，向前扫描最近的 reg_write (same dst)
 *   liveness: 反向遍历 IR 语句，跟踪 "之后还会被使用" 的寄存器集合
 *   value-range: 前向抽象解释，对每个寄存器维护 [min, max] 区间
 */

#include "core/ir.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── 寄存器名 → 位图索引 (16 个 x86-64 GPRs) ──────────────────────── */

static int reg_name_to_bit(const char *reg)
{
    if (!reg) return -1;
    /* 快速路径: 2-3 字符寄存器名 (rXX 格式) */
    if (reg[0] == 'r') {
        if (reg[1] >= '0' && reg[1] <= '9') {
            /* r8-r15: reg[1]是十位, reg[2]可能是个位 */
            int n = reg[1] - '0';
            if (reg[2] >= '0' && reg[2] <= '9')
                n = n * 10 + (reg[2] - '0');
            if (n >= 8 && n <= 15) return n;
            return -1;
        }
        /* rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7 */
        switch (reg[1]) {
            case 'a': if (reg[2] == 'x' || reg[2] == '\0') return 0; break;
            case 'c': if (reg[2] == 'x' || reg[2] == '\0') return 1; break;
            case 'd': if (reg[2] == 'x' || reg[2] == '\0') return 2; break;
            case 'b': if (reg[2] == 'x' || reg[2] == '\0') return 3; break;
            case 's': if (reg[2] == 'p' || reg[2] == 'i') return (reg[2]=='p') ? 4 : 6; break;
            case 'i': /* rdi: 'd' → 7 after 'i' check */
                      if (reg[2] == 'p') return -1; /* rip — skip */
                      break;
        }
    }
    /* 32-bit / 16-bit / 8-bit 别名 */
    if (reg[0] == 'e') {
        switch (reg[1]) {
            case 'a': if (reg[2] == 'x' || reg[2] == '\0') return 0; break;
            case 'c': if (reg[2] == 'x' || reg[2] == '\0') return 1; break;
            case 'd': if (reg[2] == 'x' || reg[2] == '\0') return 2; break;
            case 'b': if (reg[2] == 'x' || reg[2] == '\0') return 3; break;
            case 's': if (reg[2] == 'p' || reg[2] == '\0') return 4;
                      if (reg[2] == 'i' || reg[2] == '\0') return 6; break;
        }
    }
    if (reg[0] == 'r' && reg[1] == 'd' && reg[2] == 'i') return 7;
    if (reg[0] == 'r' && reg[1] == 's' && reg[2] == 'i') return 6;
    return -1;  /* 非通用寄存器 (rip, eflags, cs, ds, ...) */
}

/* ================================================================== */
/* 从 DB 加载函数 IR                                                   */
/* ================================================================== */

ir_func_t* ir_func_load(AnalysisDB *adb, uint64_t func_addr)
{
    if (!adb) return NULL;

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return NULL;

    /* 1. 获取函数地址范围 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT start_addr, end_addr, name FROM functions WHERE start_addr=?",
        -1, &st, NULL);
    if (!st) return NULL;

    uint64_t f_end = func_addr;
    char fname[IR_FUNC_NAME_MAX] = "sub_unknown";

    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
    if (sqlite3_step(st) == SQLITE_ROW) {
        f_end = (uint64_t)sqlite3_column_int64(st, 1);
        const char *nm = (const char *)sqlite3_column_text(st, 2);
        if (nm) snprintf(fname, sizeof(fname), "%s", nm);
    }
    sqlite3_finalize(st);

    /* 2. 分配函数结构 */
    ir_func_t *f = calloc(1, sizeof(ir_func_t));
    if (!f) return NULL;
    f->start_addr = func_addr;
    f->end_addr   = f_end;
    snprintf(f->name, sizeof(f->name), "%s", fname);
    f->bb_cap = 16;
    f->bbs = calloc((size_t)f->bb_cap, sizeof(ir_bb_t));
    if (!f->bbs) { free(f); return NULL; }
    f->bb_count = 0;

    /* 3. 获取该函数内的 BB 列表 */
    sqlite3_prepare_v2(c,
        "SELECT start_addr, end_addr, insn_count FROM basic_blocks "
        "WHERE function_addr=? ORDER BY start_addr",
        -1, &st, NULL);
    if (!st) goto error;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);

    while (sqlite3_step(st) == SQLITE_ROW) {
        uint64_t bb_start = (uint64_t)sqlite3_column_int64(st, 0);
        uint64_t bb_end   = (uint64_t)sqlite3_column_int64(st, 1);
        int insn_cnt       = sqlite3_column_int(st, 2);

        /* 扩容 BB 数组 */
        if (f->bb_count >= f->bb_cap) {
            f->bb_cap *= 2;
            ir_bb_t *nb = realloc(f->bbs, (size_t)f->bb_cap * sizeof(ir_bb_t));
            if (!nb) goto error;
            f->bbs = nb;
        }

        ir_bb_t *bb = &f->bbs[f->bb_count];
        memset(bb, 0, sizeof(*bb));
        bb->start_addr = bb_start;
        bb->end_addr   = bb_end;
        bb->func_addr  = func_addr;
        bb->stmt_cap   = insn_cnt * 8;  /* 每条指令最多 8 条 IR */
        bb->stmts      = calloc((size_t)bb->stmt_cap, sizeof(ir_stmt_t));
        if (!bb->stmts) goto error;
        bb->stmt_count = 0;

        /* 加载该 BB 内的 IR 语句 (按地址排序) */
        sqlite3_stmt *sir = NULL;
        sqlite3_prepare_v2(c,
            "SELECT address, op_type, dst, src FROM ir_stmts "
            "WHERE address>=?1 AND address<=?2 ORDER BY address, rowid",
            -1, &sir, NULL);
        if (sir) {
            sqlite3_bind_int64(sir, 1, (sqlite3_int64)bb_start);
            sqlite3_bind_int64(sir, 2, (sqlite3_int64)bb_end);
            while (sqlite3_step(sir) == SQLITE_ROW && bb->stmt_count < bb->stmt_cap) {
                ir_stmt_t *is = &bb->stmts[bb->stmt_count];
                is->address  = (uint64_t)sqlite3_column_int64(sir, 0);
                const char *ot = (const char *)sqlite3_column_text(sir, 1);
                const char *ds = (const char *)sqlite3_column_text(sir, 2);
                const char *sc = (const char *)sqlite3_column_text(sir, 3);

                /* op_type 映射 */
                if (!strcmp(ot, "reg_read"))  is->op_type = IR_REG_READ;
                else if (!strcmp(ot, "reg_write")) is->op_type = IR_REG_WRITE;
                else if (!strcmp(ot, "mem_access")) {
                    /* 区分 load/store: store 的目标操作数含 '[...]' */
                    is->op_type = (ds && strchr(ds, '[')) ? IR_MEM_STORE : IR_MEM_LOAD;
                } else if (!strcmp(ot, "immediate")) is->op_type = IR_IMMEDIATE;
                else is->op_type = IR_REG_READ;

                is->stmt_idx = bb->stmt_count;
                bb->stmt_count++;
            }
            sqlite3_finalize(sir);
        }
        f->bb_count++;
    }
    sqlite3_finalize(st);

    /* 4. 连接 CFG 后继 */
    for (int i = 0; i < f->bb_count; i++) {
        ir_bb_t *bb = &f->bbs[i];
        sqlite3_prepare_v2(c,
            "SELECT to_addr FROM cfg_edges WHERE from_addr=? ORDER BY edge_type",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)bb->end_addr);
            bb->succ_count = 0;
            while (sqlite3_step(st) == SQLITE_ROW && bb->succ_count < 2) {
                uint64_t succ_addr = (uint64_t)sqlite3_column_int64(st, 0);
                /* 查找该后继地址属于哪个 BB */
                for (int j = 0; j < f->bb_count; j++) {
                    if (f->bbs[j].start_addr == succ_addr) {
                        bb->succ[bb->succ_count++] = j;
                        break;
                    }
                }
            }
            sqlite3_finalize(st);
        }
    }

    return f;

error:
    if (st) sqlite3_finalize(st);
    ir_func_free(f);
    return NULL;
}

void ir_func_free(ir_func_t *f)
{
    if (!f) return;
    if (f->bbs) {
        for (int i = 0; i < f->bb_count; i++)
            free(f->bbs[i].stmts);
        free(f->bbs);
    }
    free(f);
}

/* ================================================================== */
/* Use-Def 查询 (基于 DB, 增强版)                                     */
/* ================================================================== */

int ir_use_def_query(AnalysisDB *adb, uint64_t insn_addr,
                     ir_use_def_t *results, int max_results)
{
    if (!adb || !results || max_results <= 0) return -1;

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT ir2.address, ir1.dst, ir1.address-?1 "
        "FROM ir_stmts ir1 "
        "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write' "
        "JOIN instructions i2 ON ir2.address=i2.address "
        "WHERE ir1.address=?1 AND ir1.op_type='reg_read' "
        "AND ir2.address<=?1 "
        "ORDER BY ir2.address DESC LIMIT ?2",
        -1, &st, NULL);
    if (!st) return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)insn_addr);
    sqlite3_bind_int(st,   2, max_results);
    int count = 0;

    while (sqlite3_step(st) == SQLITE_ROW && count < max_results) {
        results[count].use_addr  = insn_addr;
        results[count].def_addr  = (uint64_t)sqlite3_column_int64(st, 0);
        results[count].var_kind  = 0;  /* register */
        results[count].reg_id    = 0;  /* TODO: 从 reg name 映射 */
        results[count].distance  = sqlite3_column_int(st, 2);
        count++;
    }
    sqlite3_finalize(st);
    return count;
}

/* ================================================================== */
/* Def-Use 查询                                                        */
/* ================================================================== */

int ir_def_use_query(AnalysisDB *adb, uint64_t insn_addr,
                     ir_use_def_t *results, int max_results)
{
    if (!adb || !results || max_results <= 0) return -1;

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT ir2.address, ir1.dst, ir2.address-?1 "
        "FROM ir_stmts ir1 "
        "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_read' "
        "WHERE ir1.address=?1 AND ir1.op_type='reg_write' "
        "AND ir2.address>=?1 "
        "ORDER BY ir2.address LIMIT ?2",
        -1, &st, NULL);
    if (!st) return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)insn_addr);
    sqlite3_bind_int(st,   2, max_results);
    int count = 0;

    while (sqlite3_step(st) == SQLITE_ROW && count < max_results) {
        results[count].use_addr  = (uint64_t)sqlite3_column_int64(st, 0);
        results[count].def_addr  = insn_addr;
        results[count].var_kind  = 0;
        results[count].reg_id    = 0;
        results[count].distance  = sqlite3_column_int(st, 2);
        count++;
    }
    sqlite3_finalize(st);
    return count;
}

/* ================================================================== */
/* 活跃变量分析 (函数内, 反向数据流)                                   */
/* ================================================================== */

int ir_liveness_analyze(AnalysisDB *adb, uint64_t func_addr,
                        ir_liveness_t *results, int max_results)
{
    if (!adb || !results || max_results <= 0) return -1;

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    sqlite3_stmt *st = NULL;

    /* 获取函数内所有指令的唯一地址 */
    sqlite3_prepare_v2(c,
        "SELECT DISTINCT address FROM ir_stmts "
        "WHERE address IN ("
        "  SELECT address FROM instructions WHERE address BETWEEN "
        "  (SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        "  AND "
        "  (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        ") ORDER BY address DESC",
        -1, &st, NULL);
    if (!st) return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);

    /* 简化活跃变量: 从函数末尾向前计算 */
    /* live_bits: 位图 32 位，每位代表一个 x86-64 调用约定寄存器 */
    uint32_t live_bits = 0;  /* 函数返回时 rax 是 live */
    int count = 0;

    while (sqlite3_step(st) == SQLITE_ROW && count < max_results) {
        uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
        results[count].insn_addr = addr;

        /* 检查该指令写了哪些寄存器 (从 live set 移除) */
        sqlite3_stmt *sw = NULL;
        sqlite3_prepare_v2(c,
            "SELECT dst FROM ir_stmts WHERE address=? AND op_type='reg_write'",
            -1, &sw, NULL);
        if (sw) {
            sqlite3_bind_int64(sw, 1, (sqlite3_int64)addr);
            while (sqlite3_step(sw) == SQLITE_ROW) {
                const char *reg = (const char *)sqlite3_column_text(sw, 0);
                if (reg) {
                    int bit = reg_name_to_bit(reg);
                    if (bit >= 0 && bit < 16) live_bits &= ~(1u << bit);
                }
            }
            sqlite3_finalize(sw);
        }

        /* 检查该指令读了哪些寄存器 (加入 live set) */
        sqlite3_stmt *sr = NULL;
        sqlite3_prepare_v2(c,
            "SELECT dst FROM ir_stmts WHERE address=? AND op_type='reg_read'",
            -1, &sr, NULL);
        if (sr) {
            sqlite3_bind_int64(sr, 1, (sqlite3_int64)addr);
            while (sqlite3_step(sr) == SQLITE_ROW) {
                const char *reg = (const char *)sqlite3_column_text(sr, 0);
                if (reg) {
                    int bit = reg_name_to_bit(reg);
                    if (bit >= 0 && bit < 16) live_bits |= (1u << bit);
                }
            }
            sqlite3_finalize(sr);
        }

        /* 记录当前 live set */
        for (int i = 0; i < 16; i++)
            results[count].live_regs[i] = (live_bits & (1u << i)) ? 1 : 0;
        count++;
    }

    sqlite3_finalize(st);
    return count;
}

/* ================================================================== */
/* 值域分析 (前向抽象解释, 简化版)                                     */
/* ================================================================== */

int ir_value_range_analyze(AnalysisDB *adb, uint64_t func_addr,
                           ir_value_range_t *results, int max_results)
{
    if (!adb || !results || max_results <= 0) return -1;

    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    /* 16 个通用寄存器的值域 */
    typedef struct { int64_t min, max; int top; } reg_range_t;
    reg_range_t regs[16];
    for (int i = 0; i < 16; i++) {
        regs[i].min = INT64_MIN;
        regs[i].max = INT64_MAX;
        regs[i].top = 1;  /* 初始为未知 */
    }

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT address, op_type, dst, imm_value FROM ir_stmts "
        "WHERE address IN ("
        "  SELECT address FROM instructions WHERE address BETWEEN "
        "  (SELECT start_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        "  AND "
        "  (SELECT end_addr FROM functions WHERE start_addr=?1 LIMIT 1)"
        ") ORDER BY address",
        -1, &st, NULL);
    if (!st) return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);

    int count = 0;
    while (sqlite3_step(st) == SQLITE_ROW && count < max_results) {
        uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
        const char *ot = (const char *)sqlite3_column_text(st, 1);
        const char *dst = (const char *)sqlite3_column_text(st, 2);

        results[count].insn_addr = addr;
        results[count].reg_id    = -1;
        results[count].min_val   = INT64_MIN;
        results[count].max_val   = INT64_MAX;
        results[count].is_top    = 1;

        /* 立即数约束 */
        if (ot && !strcmp(ot, "immediate")) {
            if (dst) {
                int bit = reg_name_to_bit(dst);
                if (bit >= 0 && bit < 16) {
                    int64_t imm = sqlite3_column_int64(st, 3);
                    regs[bit].min = imm;
                    regs[bit].max = imm;
                    regs[bit].top = 0;
                    results[count].reg_id  = bit;
                    results[count].min_val = imm;
                    results[count].max_val = imm;
                    results[count].is_top  = 0;
                }
            }
        }
        /* reg_write: 如果是 mov 指令，传播值域 */
        /* (简化: 仅追踪立即数，寄存器传播需要 IR 指令级分析，此处留待扩展) */

        count++;
    }

    sqlite3_finalize(st);
    return count;
}

/* ================================================================== */
/* 缓冲区安全检查 (危险调用 + 值域判断)                                */
/* ================================================================== */

int ir_check_buffer_safety(AnalysisDB *adb, uint64_t call_addr, PanelData *pd)
{
    if (!adb || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    char buf[512];

    /* 1. 确定调用了哪个函数 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT mnemonic, op_str FROM instructions WHERE address=?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);

    char callee[64] = "?";
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *op = (const char *)sqlite3_column_text(st, 1);
        if (op) {
            /* 提取 call 目标名 (去除 @plt 后缀) */
            snprintf(callee, sizeof(callee), "%s", op);
            char *at = strchr(callee, '@');
            if (at) *at = '\0';
        }
    }
    sqlite3_finalize(st);

    /* 2. 检查参数中的立即数 (值域分析结果) */
    snprintf(buf, sizeof(buf), "=== Buffer Check: %s @ 0x%lx ===",
             callee, (unsigned long)call_addr);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    sqlite3_prepare_v2(c,
        "SELECT imm_value, op_type, dst FROM ir_stmts "
        "WHERE address=?1 AND op_type='immediate'",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);
        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            int64_t imm = sqlite3_column_int64(st, 0);
            const char *reg = (const char *)sqlite3_column_text(st, 2);
            if (!found) { fields_add(pd, "── Immediate Arguments ──", 1, 0, DETAIL_NONE, -1); found = 1; }
            snprintf(buf, sizeof(buf), "%s = 0x%lx (%ld)", reg ? reg : "?", (unsigned long)imm, (long)imm);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        sqlite3_finalize(st);
    }

    /* 3. 追踪参数来源 (从 ir_stmts 追溯) */
    fields_add(pd, "── Argument Trace ──", 1, 0, DETAIL_NONE, -1);

    /* 追踪调用参数来源.
     * 用户函数 (System V ABI): rdi, rsi, rdx, rcx, r8, r9
     * 系统调用 (Linux ABI):    rdi, rsi, rdx, r10, r8, r9  (syscall 会破坏 rcx) */
    const char *arg_regs[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10"};
    for (int a = 0; a < 7; a++) {   /* 6 个用户调用参数 + r10 (系统调用) */
        sqlite3_stmt *st2 = NULL;
        sqlite3_prepare_v2(c,
            "SELECT i2.address, i2.mnemonic, i2.op_str "
            "FROM ir_stmts ir1 "
            "JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write' "
            "JOIN instructions i2 ON ir2.address=i2.address "
            "WHERE ir1.address=?1 AND ir1.op_type='reg_read' "
            "AND ir1.dst=?2 AND ir2.address<?1 "
            "ORDER BY ir2.address DESC LIMIT 1",
            -1, &st2, NULL);
        if (st2) {
            sqlite3_bind_int64(st2, 1, (sqlite3_int64)call_addr);
            sqlite3_bind_text(st2,  2, arg_regs[a], -1, SQLITE_STATIC);
            if (sqlite3_step(st2) == SQLITE_ROW) {
                uint64_t def_a = (uint64_t)sqlite3_column_int64(st2, 0);
                const char *m = (const char *)sqlite3_column_text(st2, 1);
                const char *o = (const char *)sqlite3_column_text(st2, 2);
                snprintf(buf, sizeof(buf), "arg%d(%s) ← 0x%lx  %-8s %s",
                         a, arg_regs[a], (unsigned long)def_a, m ? m : "?", o ? o : "");
                fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)def_a);
            }
            sqlite3_finalize(st2);
        }
    }

    /* 4. 风险判定 */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    int risk = 0;
    if (!strcmp(callee, "strcpy") || !strcmp(callee, "strcat") ||
        !strcmp(callee, "sprintf") || !strcmp(callee, "gets")) {
        /* 高危险: 没有边界检查 */
        snprintf(buf, sizeof(buf), "[CRITICAL] %s: no built-in bounds checking — "
                 "potential stack/heap buffer overflow", callee);
        risk = 4;
    } else if (!strcmp(callee, "memcpy") || !strcmp(callee, "memmove") ||
               !strcmp(callee, "read") || !strcmp(callee, "recv")) {
        /* 需检查第三参数 */
        snprintf(buf, sizeof(buf), "[HIGH] %s: verify size argument (rdx) against "
                 "destination buffer capacity", callee);
        risk = 3;
    } else if (!strcmp(callee, "scanf") || !strcmp(callee, "printf")) {
        /* 格式化字符串风险 */
        snprintf(buf, sizeof(buf), "[MEDIUM] %s: format string may be user-controlled "
                 "— check if fmt argument comes from input", callee);
        risk = 2;
    } else {
        snprintf(buf, sizeof(buf), "[INFO] %s: no high-risk pattern matched", callee);
        risk = 0;
    }
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "Risk Score: %d/4  [Enter]=dataflow [f]=trace [h]=back", risk);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* IR Lifter 探测                                                      */
/* ================================================================== */

ir_lifter_t* ir_detect_lifter(Elf64_Ctx *ctx)
{
    if (!ctx) return NULL;
    for (int i = 0; ir_lifters[i]; i++) {
        if (ir_lifters[i]->probe && ir_lifters[i]->probe(ctx))
            return ir_lifters[i];
    }
    return NULL;
}

/* 全局注册表: 默认空.
 * 架构特定的提升器实现 (x86-64/AArch64/RISC-V) 将在各自的 ir_lift_xxx.c
 * 文件中注册。当前 IR 分析直接消费 Capstone → DB 管道产生的 ir_stmts 表数据，
 * 因此 ir_lifters[] 为空不影响现有分析功能。 */
ir_lifter_t *ir_lifters[] = { NULL };
