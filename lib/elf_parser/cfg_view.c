/*
 * cfg_view.c — 控制流图面板 (Basic Block + CFG)
 *
 * 双路径:
 *   DB 路径: 从 basic_blocks + cfg_edges 表直接查询 (零反汇编, 带 CFG 箭头)
 *   mmap 路径: 全量反汇编 + leader 分析 (原有逻辑, DB 不可用时降级)
 *
 * 接口: int parse_cfg_view(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 *
 * 依赖: disasm.h (Capstone, 仅 mmap 路径)
 */
#include "elf_parser.h"
#include "disasm.h"
#include "core/db.h"
#include <sqlite3.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 基本块                                                             */
/* ================================================================== */

#define MAX_BB 1024
#define MAX_LEADERS 8192

typedef struct {
    uint64_t start;
    uint64_t end;          /* 最后一条指令地址 */
    int      insn_count;
    int      succ_count;
    uint64_t succ[2];      /* 后继 BB 起始地址 */
    int      is_call:1;
    int      is_cond:1;    /* 条件跳转结尾 */
    int      is_ret:1;     /* 返回结尾 */
    int      is_indirect:1;/* 间接跳转结尾 */
} bb_t;

/* ================================================================== */
/* 地址集合 (用于 leader 标记)                                        */
/* ================================================================== */

typedef struct {
    uint64_t addrs[MAX_LEADERS];
    int      count;
} addr_set_t;

static void as_add(addr_set_t *s, uint64_t a) {
    for (int i = 0; i < s->count; i++)
        if (s->addrs[i] == a) return;
    if (s->count < MAX_LEADERS) s->addrs[s->count++] = a;
}
static int as_has(addr_set_t *s, uint64_t a) {
    for (int i = 0; i < s->count; i++)
        if (s->addrs[i] == a) return 1;
    return 0;
}
static int as_cmp(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a, vb = *(const uint64_t*)b;
    return (va > vb) - (va < vb);
}

/* ================================================================== */
/* DB 路径: 从 basic_blocks + cfg_edges 查询                            */
/* ================================================================== */

static int parse_cfg_view_db(AnalysisDB *adb, Elf64_Ctx *ctx,
                              int shdr_idx, PanelData *pd)
{
    (void)ctx;
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    /* 获取 section 的地址范围 */
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_size == 0) {
        fields_add(pd, "(empty section)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }
    uint64_t sec_start = sh->sh_addr;
    uint64_t sec_end   = sh->sh_addr + sh->sh_size;
    const char *sec_name = elf_section_name(ctx, shdr_idx);
    char buf[256];

    snprintf(buf, sizeof(buf), "=== CFG: %s [DB] ===", sec_name ? sec_name : "?");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 统计 BB */
    sqlite3_stmt *st = NULL;
    int total_bb = 0;
    sqlite3_prepare_v2(c,
        "SELECT COUNT(*) FROM basic_blocks "
        "WHERE start_addr>=?1 AND start_addr<?2",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)sec_start);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)sec_end);
        if (sqlite3_step(st) == SQLITE_ROW) total_bb = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    /* 查询 BB 列表 */
    sqlite3_prepare_v2(c,
        "SELECT start_addr, end_addr, insn_count, function_addr "
        "FROM basic_blocks "
        "WHERE start_addr>=?1 AND start_addr<?2 "
        "ORDER BY start_addr LIMIT 200",
        -1, &st, NULL);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)sec_start);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)sec_end);

    fields_add(pd, "── Basic Blocks ──", 1, 0, DETAIL_NONE, -1);
    int shown = 0;
    while (sqlite3_step(st) == SQLITE_ROW && shown < 200) {
        uint64_t bb_start = (uint64_t)sqlite3_column_int64(st, 0);
        uint64_t bb_end   = (uint64_t)sqlite3_column_int64(st, 1);
        int insn_cnt       = sqlite3_column_int(st, 2);
        uint64_t func_addr = (uint64_t)sqlite3_column_int64(st, 3);

        /* 查询该 BB 的 CFG 后继 */
        sqlite3_stmt *sc = NULL;
        sqlite3_prepare_v2(c,
            "SELECT to_addr, edge_type FROM cfg_edges "
            "WHERE from_addr=?1 ORDER BY edge_type LIMIT 4",
            -1, &sc, NULL);
        sqlite3_bind_int64(sc, 1, (sqlite3_int64)bb_end);

        char succ_buf[128] = "";
        int slp = 0;
        while (sqlite3_step(sc) == SQLITE_ROW && slp < 120) {
            uint64_t to = (uint64_t)sqlite3_column_int64(sc, 0);
            const char *et = (const char *)sqlite3_column_text(sc, 1);
            slp += snprintf(succ_buf + slp, sizeof(succ_buf) - (size_t)slp,
                            "%s→0x%lx ", et ? et : "?",
                            (unsigned long)(to & 0xFFFF));
        }
        sqlite3_finalize(sc);

        snprintf(buf, sizeof(buf),
                 "BB[%d] 0x%lx-0x%lx  %d insns  %s",
                 shown, (unsigned long)bb_start, (unsigned long)bb_end,
                 insn_cnt, succ_buf[0] ? succ_buf : "(terminal)");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)bb_start);

        /* 跨函数标记 */
        if (func_addr != sec_start && shown < 10) {
            sqlite3_stmt *sf = NULL;
            sqlite3_prepare_v2(c,
                "SELECT name FROM functions WHERE start_addr=?1 LIMIT 1",
                -1, &sf, NULL);
            if (sf) {
                sqlite3_bind_int64(sf, 1, (sqlite3_int64)func_addr);
                if (sqlite3_step(sf) == SQLITE_ROW) {
                    snprintf(buf, sizeof(buf), "  func: %s",
                             (const char *)sqlite3_column_text(sf, 0));
                    fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                }
                sqlite3_finalize(sf);
            }
        }
        shown++;
    }
    sqlite3_finalize(st);

    snprintf(buf, sizeof(buf), "Total: %d BBs (%d shown)",
             total_bb, shown < total_bb ? shown : total_bb);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return 0;
}

/* ================================================================== */
/* mmap 路径: 原始实现 (DB 不可用时降级)                               */
/* ================================================================== */

static int parse_cfg_view_mmap(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_size == 0) {
        fields_add(pd, "(empty section)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const char *sec_name = elf_section_name(ctx, shdr_idx);
    char buf[256];

    snprintf(buf, sizeof(buf), "=== CFG: %s ===", sec_name ? sec_name : "?");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 创建反汇编引擎 */
    disasm_ctx *d = disasm_open();
    if (!d) {
        fields_add(pd, "(Capstone unavailable)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const uint8_t *code = ctx->map + sh->sh_offset;
    size_t         size = sh->sh_size;
    uint64_t       base = sh->sh_addr;

    /* -------------------------------------------------------------- */
    /* Pass 1: 收集所有 leader 地址                                    */
    /* -------------------------------------------------------------- */
    addr_set_t leaders;
    memset(&leaders, 0, sizeof(leaders));
    as_add(&leaders, base);  /* 第一条指令总是 leader */

    /* 临时存储: 所有指令的地址和大小 */
    #define MAX_INSNS 65536
    uint64_t *iaddr = malloc(MAX_INSNS * sizeof(uint64_t));
    uint16_t *isize = malloc(MAX_INSNS * sizeof(uint16_t));
    if (!iaddr || !isize) {
        free(iaddr); free(isize);
        disasm_close(d);
        fields_add(pd, "(memory error)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    int icount = 0;

    {
        const uint8_t *ptr = code;
        size_t left = size;
        uint64_t addr = base;

        while (left > 0 && icount < MAX_INSNS && disasm_next(d, &ptr, &left, &addr)) {
            cs_insn *insn = disasm_insn(d);
            if (!insn->detail) continue;

            iaddr[icount] = insn->address;
            isize[icount] = insn->size;

            /* 检查跳转 — 目标成为 leader */
            int is_jmp = 0, is_cond = 0, is_call = 0;
            for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
                unsigned int gid = insn->detail->groups[g];
                if (gid == X86_GRP_JUMP) is_jmp = 1;
                if (gid == X86_GRP_CALL) is_call = 1;
                if (gid == X86_GRP_RET || gid == X86_GRP_IRET) is_jmp = 1;
            }

            /* 条件跳转检测 */
            switch (insn->id) {
                case X86_INS_JE: case X86_INS_JNE: case X86_INS_JG:
                case X86_INS_JGE: case X86_INS_JL: case X86_INS_JLE:
                case X86_INS_JA: case X86_INS_JAE: case X86_INS_JB:
                case X86_INS_JBE: case X86_INS_JO: case X86_INS_JNO:
                case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP:
                case X86_INS_JNP: case X86_INS_LOOP: case X86_INS_LOOPE:
                case X86_INS_LOOPNE: case X86_INS_JECXZ: case X86_INS_JRCXZ:
                    is_cond = 1; is_jmp = 1; break;
                default: break;
            }

            if (is_jmp || is_call) {
                /* 提取目标地址 */
                cs_x86 *x86 = &insn->detail->x86;
                for (uint8_t oi = 0; oi < x86->op_count; oi++) {
                    if (x86->operands[oi].type == X86_OP_IMM) {
                        uint64_t target = (uint64_t)x86->operands[oi].imm;
                        if (target >= base && target < base + size)
                            as_add(&leaders, target);
                        break;
                    }
                }
            }

            /* 跳转/返回之后的地址是 leader (fall-through) */
            if (is_jmp) {
                uint64_t next = insn->address + insn->size;
                if ((is_cond || is_call) && next < base + size)
                    as_add(&leaders, next);
            }

            icount++;
        }
    }

    if (icount == 0) {
        fields_add(pd, "(no valid instructions)", 0, 0, DETAIL_NONE, -1);
        free(iaddr); free(isize);
        disasm_close(d);
        return pd->count;
    }

    /* 排序 leader */
    qsort(leaders.addrs, (size_t)leaders.count, sizeof(uint64_t), as_cmp);

    /* -------------------------------------------------------------- */
    /* Pass 2: 划分基本块                                              */
    /* -------------------------------------------------------------- */
    bb_t bb_list[MAX_BB];
    int   bb_cnt = 0;
    int   ii = 0;
    int   li __attribute__((unused)) = 0;

    while (ii < icount && bb_cnt < MAX_BB) {
        bb_t *bb = &bb_list[bb_cnt];
        memset(bb, 0, sizeof(*bb));
        bb->start = iaddr[ii];

        /* 扫描直到遇到 leader 或终止指令 */
        int start_idx = ii;
        while (ii < icount) {
            bb->end = iaddr[ii];
            ii++;

            /* 检查下一条是否为新 leader */
            if (ii < icount && as_has(&leaders, iaddr[ii]))
                break;
        }
        bb->insn_count = ii - start_idx;
        bb_cnt++;
    }

    /* -------------------------------------------------------------- */
    /* Pass 2.5: 重新反汇编确定出口类型                                */
    /* -------------------------------------------------------------- */
    disasm_close(d);
    d = disasm_open();
    if (d) {
        for (int bi = 0; bi < bb_cnt; bi++) {
            bb_t *bb = &bb_list[bi];

            /* 反汇编该 BB 的最后一条指令 */
            const uint8_t *ptr = code + (bb->end - base);
            size_t left = size - (bb->end - base);
            uint64_t addr = bb->end;

            if (disasm_next(d, &ptr, &left, &addr)) {
                cs_insn *insn = disasm_insn(d);
                if (insn->detail) {
                    for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
                        if (insn->detail->groups[g] == X86_GRP_JUMP) {
                            bb->is_ret = (insn->id == X86_INS_RET);
                        }
                        if (insn->detail->groups[g] == X86_GRP_CALL)
                            bb->is_call = 1;
                    }
                }

                /* 提取跳转目标 */
                cs_x86 *x86 = &insn->detail->x86;
                for (uint8_t oi = 0; oi < x86->op_count; oi++) {
                    if (x86->operands[oi].type == X86_OP_IMM) {
                        bb->succ[bb->succ_count++] =
                            (uint64_t)x86->operands[oi].imm;
                        break;
                    }
                }
            }

            /* Fall-through 后继: 如果下个 BB 紧跟在后面 */
            if (bi + 1 < bb_cnt && bb_list[bi+1].start == bb->end + 1) {
                /* 简化: 检查下个 BB 是否在 leader 表中 (即确认为有效 leader) */
                if (bb->succ_count < 2)
                    bb->succ[bb->succ_count++] = bb_list[bi+1].start;
            }
        }
        disasm_close(d);
    }

    /* -------------------------------------------------------------- */
    /* 输出                                                             */
    /* -------------------------------------------------------------- */

    snprintf(buf, sizeof(buf), "Basic Blocks: %d  Instructions: %d",
             bb_cnt, icount);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* ASCII 渲染 (≤50 BBs) */
    if (bb_cnt <= 50) {
        fields_add(pd, "─ ─ ─ Control Flow ─ ─ ─", 0, 0, DETAIL_NONE, -1);

        for (int bi = 0; bi < bb_cnt; bi++) {
            bb_t *bb = &bb_list[bi];

            /* BB 标题 */
            char marker[8] = "";
            if (bb->is_call) strcat(marker, "C");
            if (bb->is_cond) strcat(marker, "?");
            if (bb->is_ret)  strcat(marker, "R");
            if (marker[0] == '\0') strcpy(marker, " ");

            snprintf(buf, sizeof(buf),
                     "[%s] BB[%d] @ 0x%lx  %d insns",
                     marker, bi,
                     (unsigned long)bb->start,
                     bb->insn_count);
            fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)bb->start);

            /* 后继 */
            for (int s = 0; s < bb->succ_count; s++) {
                /* 查找目标 BB 索引 */
                int target_bi = -1;
                for (int tj = 0; tj < bb_cnt; tj++) {
                    if (bb_list[tj].start == bb->succ[s]) {
                        target_bi = tj; break;
                    }
                }

                const char *edge_type = "─→";
                if (bb->is_call) edge_type = "╍→ call";
                else if (bb->is_cond && s == 0) edge_type = "═→ taken";
                else if (bb->is_cond && s == 1) edge_type = "-→ fall";

                if (target_bi >= 0) {
                    snprintf(buf, sizeof(buf),
                             "  %s BB[%d] (0x%lx)",
                             edge_type, target_bi,
                             (unsigned long)bb->succ[s]);
                } else {
                    snprintf(buf, sizeof(buf),
                             "  %s 0x%lx (external)",
                             edge_type,
                             (unsigned long)bb->succ[s]);
                }
                fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            }

            if (bb->succ_count == 0 && !bb->is_ret) {
                fields_add(pd, "  (no successors — fall-through?)",
                           2, 0, DETAIL_NONE, -1);
            }
        }
    } else {
        /* 大型函数: 仅列表 */
        snprintf(buf, sizeof(buf),
                 "(large function, %d BBs — showing list only)", bb_cnt);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

        for (int bi = 0; bi < bb_cnt && bi < 100; bi++) {
            bb_t *bb = &bb_list[bi];
            snprintf(buf, sizeof(buf),
                     "BB[%d] 0x%lx  %d insns  → %s",
                     bi, (unsigned long)bb->start, bb->insn_count,
                     bb->succ_count > 0 ? "..." : "(terminal)");
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    }

    free(iaddr);
    free(isize);
    return pd->count;
}

/* ── 公共接口 ────────────────────────────────────────────────────── */

int parse_cfg_view(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    if (g_active_db) {
        return parse_cfg_view_db(g_active_db, ctx, shdr_idx, pd);
    }
    return parse_cfg_view_mmap(ctx, shdr_idx, pd);
}
