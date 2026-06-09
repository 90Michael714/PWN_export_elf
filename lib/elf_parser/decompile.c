/*
 * decompile.c — 反编译引擎 v3 (操作数感知 + DB 驱动)
 *
 * 核心设计:
 *   1. 分割 op_str 顶层逗号 → 获取正确的 dst/src 操作数
 *   2. ir_stmts 查询做变量名解析 (不是 strstr 模式匹配)
 *   3. cfg_edges + basic_blocks → 控制流结构化
 *   4. call_args + value_defs → 调用参数角色标注
 *   5. 干净输出: C 伪代码 | 底部汇编参考
 *
 * 接口:
 *   parse_decompile()       — 中间面板: 函数列表
 *   decompile_function_at() — 右面板: 选定函数的反编译
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

extern AnalysisDB *g_active_db;

/* ================================================================== */
/* 数据结构                                                           */
/* ================================================================== */

#define MAX_VARS   64
#define MAX_CALLS  64
#define MAX_BBS   128
#define MAX_INSNS 256

/* 栈变量 */
typedef struct {
    int   offset;
    int   size;
    int   access_count;
    int   is_arg;
    char  name[16];
    char  type[16];
} dvar_t;

/* 调用点 */
typedef struct {
    uint64_t call_addr;
    char     callee[64];
    int      nargs;
    struct { char text[64]; char role[24]; int tainted; } args[6];
} dcall_t;

/* 基本块 */
typedef struct {
    uint64_t start_addr, end_addr;
    int      succ_count;
    uint64_t succ[2];
    char     succ_type[2][16];
} dbb_t;

/* 操作数类型 */
typedef enum { OP_REG, OP_MEM, OP_IMM, OP_UNK } op_kind_t;

typedef struct {
    op_kind_t kind;
    char raw[64];         /* 原始文本 */
    char name[64];        /* 解析后名称: rax, var_20, 0x2a */
    /* OP_MEM 扩展 */
    char base[8];
    int  disp;
    int  is_rbp_rel;      /* 能否解析为栈变量 */
    /* OP_IMM 扩展 */
    int64_t imm_val;
} operand_t;

/* ================================================================== */
/* Phase 1: 从 ir_stmts 构建变量映射                                    */
/* ================================================================== */

static int build_var_map(sqlite3 *c, uint64_t faddr, uint64_t fend,
                          dvar_t *vars, int *nvars_out)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c,
        "SELECT mem_base, mem_disp, size_bytes FROM ir_stmts "
        "WHERE op_type='mem_access' "
        "AND address BETWEEN ?1 AND ?2 "
        "AND (mem_base='rbp' OR mem_base='rsp')",
        -1, &st, NULL);
    if (rc != SQLITE_OK || !st) return -1;

    sqlite3_bind_int64(st, 1, (sqlite3_int64)faddr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)fend);

    int nv = 0;
    while (sqlite3_step(st) == SQLITE_ROW && nv < MAX_VARS) {
        const char *base = (const char *)sqlite3_column_text(st, 0);
        int disp         = sqlite3_column_int(st, 1);
        int sz           = sqlite3_column_int(st, 2);
        if (!base) continue;
        if (sz <= 0) sz = 8;

        int offset = disp;
        if (!strcmp(base, "rbp")) {
            if (offset == 0 || offset == 8) continue; /* saved rbp / ret addr */
        } else {
            if (offset == 0) continue;
        }
        int is_arg = (!strcmp(base, "rbp") && offset > 8);

        int found = 0;
        for (int i = 0; i < nv; i++) {
            if (vars[i].offset == offset) {
                vars[i].access_count++;
                if (sz > vars[i].size) vars[i].size = sz;
                found = 1; break;
            }
        }
        if (!found && nv < MAX_VARS) {
            vars[nv].offset       = offset;
            vars[nv].size         = sz;
            vars[nv].access_count = 1;
            vars[nv].is_arg       = is_arg;
            if (is_arg) snprintf(vars[nv].name, sizeof(vars[nv].name), "arg%d", (offset-16)/8);
            else        snprintf(vars[nv].name, sizeof(vars[nv].name), "var_%x", -offset);
            if      (sz == 1) snprintf(vars[nv].type, sizeof(vars[nv].type), "uint8_t");
            else if (sz == 2) snprintf(vars[nv].type, sizeof(vars[nv].type), "uint16_t");
            else if (sz == 4) snprintf(vars[nv].type, sizeof(vars[nv].type), "int32_t");
            else              snprintf(vars[nv].type, sizeof(vars[nv].type), "int64_t");
            nv++;
        }
    }
    sqlite3_finalize(st);

    /* 按 offset 排序 */
    for (int i = 0; i < nv - 1; i++)
        for (int j = i + 1; j < nv; j++)
            if (vars[i].offset > vars[j].offset) {
                dvar_t t = vars[i]; vars[i] = vars[j]; vars[j] = t;
            }
    *nvars_out = nv;
    return 0;
}

/* ================================================================== */
/* Phase 2: 调用信息收集                                                */
/* ================================================================== */

static int build_call_info(sqlite3 *c, uint64_t faddr, uint64_t fend,
                            dcall_t *calls, int *ncalls_out)
{
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c,
        "SELECT address, op_str FROM instructions "
        "WHERE address BETWEEN ?1 AND ?2 AND mnemonic='call' ORDER BY address",
        -1, &st, NULL);
    if (rc != SQLITE_OK || !st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)faddr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)fend);

    int nc = 0;
    while (sqlite3_step(st) == SQLITE_ROW && nc < MAX_CALLS) {
        uint64_t ca     = (uint64_t)sqlite3_column_int64(st, 0);
        const char *op  = (const char *)sqlite3_column_text(st, 1);
        uint64_t target = op ? (uint64_t)strtoull(op, NULL, 16) : 0;

        calls[nc].call_addr = ca;
        calls[nc].nargs = 0;
        memset(calls[nc].args, 0, sizeof(calls[nc].args));

        /* 符号名解析 */
        if (target > 0) {
            sqlite3_stmt *s2 = NULL;
            sqlite3_prepare_v2(c, "SELECT name FROM symbols WHERE address=?1 LIMIT 1",
                               -1, &s2, NULL);
            if (s2) {
                sqlite3_bind_int64(s2, 1, (sqlite3_int64)target);
                if (sqlite3_step(s2) == SQLITE_ROW) {
                    const char *nm = (const char *)sqlite3_column_text(s2, 0);
                    if (nm) {
                        snprintf(calls[nc].callee, sizeof(calls[nc].callee), "%s", nm);
                        char *at = strchr(calls[nc].callee, '@');
                        if (at) *at = '\0';
                    }
                }
                sqlite3_finalize(s2);
            }
        }
        if (!calls[nc].callee[0])
            snprintf(calls[nc].callee, sizeof(calls[nc].callee), "sub_%lx", (unsigned long)target);

        /* call_args: 参数角色 */
        sqlite3_stmt *s3 = NULL;
        sqlite3_prepare_v2(c,
            "SELECT arg_index, arg_role, is_tainted FROM call_args "
            "WHERE call_addr=?1 ORDER BY arg_index", -1, &s3, NULL);
        if (s3) {
            sqlite3_bind_int64(s3, 1, (sqlite3_int64)ca);
            int max_arg = -1;
            while (sqlite3_step(s3) == SQLITE_ROW) {
                int ai = sqlite3_column_int(s3, 0);
                const char *role = (const char *)sqlite3_column_text(s3, 1);
                if (ai >= 0 && ai < 6) {
                    if (role) snprintf(calls[nc].args[ai].role, 24, "%s", role);
                    calls[nc].args[ai].tainted = sqlite3_column_int(s3, 2);
                    if (ai > max_arg) max_arg = ai;
                }
            }
            calls[nc].nargs = max_arg + 1;
            sqlite3_finalize(s3);
        }

        /* 回溯参数来源: ir_stmts reg_write */
        if (calls[nc].nargs == 0) {
            static const char *arg_regs[] = {"rdi","rsi","rdx","rcx","r8","r9",NULL};
            for (int ai = 0; ai < 6 && arg_regs[ai]; ai++) {
                sqlite3_stmt *s4 = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT i.op_str FROM ir_stmts ir "
                    "JOIN instructions i ON ir.address=i.address "
                    "WHERE ir.address<?1 AND ir.address>=?2 "
                    "AND ir.op_type='reg_write' AND ir.dst=?3 "
                    "ORDER BY ir.address DESC LIMIT 1",
                    -1, &s4, NULL);
                if (s4) {
                    sqlite3_bind_int64(s4, 1, (sqlite3_int64)ca);
                    sqlite3_bind_int64(s4, 2, (sqlite3_int64)faddr);
                    sqlite3_bind_text(s4, 3, arg_regs[ai], -1, SQLITE_STATIC);
                    if (sqlite3_step(s4) == SQLITE_ROW) {
                        const char *op2 = (const char *)sqlite3_column_text(s4, 0);
                        if (op2) {
                            const char *src = strchr(op2, ',');
                            if (src) { src++; while (*src == ' ') src++;
                                snprintf(calls[nc].args[ai].text, 64, "%s", src); }
                        }
                        calls[nc].nargs = ai + 1;
                    }
                    sqlite3_finalize(s4);
                }
            }
        }
        nc++;
    }
    sqlite3_finalize(st);
    *ncalls_out = nc;
    return 0;
}

/* ================================================================== */
/* Phase 3: 控制流                                                     */
/* ================================================================== */

static int build_cfg(sqlite3 *c, uint64_t faddr, uint64_t fend_unused,
                      dbb_t *bbs, int *nbbs_out)
{
    (void)fend_unused;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(c,
        "SELECT start_addr, end_addr FROM basic_blocks "
        "WHERE function_addr=?1 ORDER BY start_addr", -1, &st, NULL);
    if (rc != SQLITE_OK || !st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)faddr);

    int nb = 0;
    while (sqlite3_step(st) == SQLITE_ROW && nb < MAX_BBS) {
        bbs[nb].start_addr = (uint64_t)sqlite3_column_int64(st, 0);
        bbs[nb].end_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        bbs[nb].succ_count = 0;

        sqlite3_stmt *s2 = NULL;
        sqlite3_prepare_v2(c,
            "SELECT to_addr, edge_type FROM cfg_edges "
            "WHERE from_addr BETWEEN ?1 AND ?2 ORDER BY edge_type",
            -1, &s2, NULL);
        if (s2) {
            sqlite3_bind_int64(s2, 1, (sqlite3_int64)bbs[nb].start_addr);
            sqlite3_bind_int64(s2, 2, (sqlite3_int64)bbs[nb].end_addr);
            while (sqlite3_step(s2) == SQLITE_ROW && bbs[nb].succ_count < 2) {
                bbs[nb].succ[bbs[nb].succ_count] = (uint64_t)sqlite3_column_int64(s2, 0);
                const char *et = (const char *)sqlite3_column_text(s2, 1);
                if (et) snprintf(bbs[nb].succ_type[bbs[nb].succ_count], 16, "%s", et);
                bbs[nb].succ_count++;
            }
            sqlite3_finalize(s2);
        }
        nb++;
    }
    sqlite3_finalize(st);
    *nbbs_out = nb;
    return 0;
}

static int is_loop_back_edge(uint64_t from, uint64_t to) {
    return to < from;
}

/* ================================================================== */
/* Phase 4: 操作数解析 (顶层逗号分割 + ir_stmts 变量名解析)              */
/* ================================================================== */

/**
 * 在 op_str 中找到第一个不在方括号内的逗号, 分割为操作数。
 * e.g. "rax, [rbp-0x20]" → ops[0]="rax", ops[1]="[rbp-0x20]"
 *      "qword [rbp-0x20], 0" → ops[0]="qword [rbp-0x20]", ops[1]="0"
 */
static int split_operands(const char *op_str, char ops[3][64]) {
    if (!op_str) return 0;
    int depth = 0, n = 0;
    const char *s = op_str;
    while (*s == ' ') s++;

    const char *start = s;
    int done = 0;
    for (const char *p = s; !done; p++) {
        if (*p == '[') depth++;
        else if (*p == ']' && depth > 0) depth--;
        else if ((*p == ',' || *p == '\0') && depth == 0) {
            size_t len = (size_t)(p - start);
            while (len > 0 && start[len-1] == ' ') len--;
            if (len >= 63) len = 63;
            memcpy(ops[n], start, len); ops[n][len] = '\0';
            n++;
            if (*p == '\0' || n >= 3) done = 1;
            start = p + 1;
            while (*start == ' ') start++;
        }
        if (*p == '\0') done = 1;
    }
    return n;
}

/* 检查字符串是否是 x86-64 寄存器名 */
static int is_register(const char *s) {
    if (!s || !s[0]) return 0;
    /* 常见 GPR */
    static const char *regs[] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
        "ax","bx","cx","dx","si","di","bp","sp",
        "al","bl","cl","dl","sil","dil","bpl","spl",
        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
        "ah","bh","ch","dh",
        "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
        "ymm0","ymm1","ymm2","ymm3",
        "rip","eflags","cs","ds","es","fs","gs","ss",
        "cr0","cr2","cr3","cr4","cr8",
        "dr0","dr1","dr2","dr3","dr6","dr7",
        NULL
    };
    for (int i = 0; regs[i]; i++)
        if (!strcmp(s, regs[i])) return 1;
    return 0;
}

/* 判断操作数文本是否代表一个立即数 */
static int is_immediate(const char *s) {
    if (!s) return 0;
    /* 0x... 前缀 */
    if (s[0] == '0' && s[1] == 'x') return 1;
    /* 纯数字 (允许负号) */
    if (s[0] == '-') s++;
    if (!s[0]) return 0;
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

/* 解析操作数并利用 ir_stmts 做变量名解析 */
static void classify_operand(sqlite3 *c, uint64_t insn_addr,
                              const char *raw, dvar_t *vars, int nvars,
                              operand_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!raw) { out->kind = OP_UNK; return; }
    snprintf(out->raw, sizeof(out->raw), "%s", raw);

    /* 检查是否寄存器 */
    if (is_register(raw)) {
        out->kind = OP_REG;
        snprintf(out->name, sizeof(out->name), "%s", raw);
        return;
    }

    /* 检查是否立即数 */
    if (is_immediate(raw)) {
        out->kind = OP_IMM;
        const char *s = raw;
        int neg = 0;
        if (*s == '-') { neg = 1; s++; }
        if (s[0] == '0' && s[1] == 'x')
            out->imm_val = (int64_t)strtoull(s, NULL, 16);
        else
            out->imm_val = (int64_t)strtoull(s, NULL, 10);
        if (neg) out->imm_val = -out->imm_val;
        /* 尝试符号解析 (仅地址级立即数) */
        if (out->imm_val > 0x1000 && (uint64_t)out->imm_val < 0x7FFFFFFFFFFFULL) {
            sqlite3_stmt *ss = NULL;
            sqlite3_prepare_v2(c, "SELECT name FROM symbols WHERE address=?1 LIMIT 1",
                               -1, &ss, NULL);
            if (ss) {
                sqlite3_bind_int64(ss, 1, (sqlite3_int64)out->imm_val);
                if (sqlite3_step(ss) == SQLITE_ROW) {
                    const char *sn = (const char *)sqlite3_column_text(ss, 0);
                    if (sn) snprintf(out->name, sizeof(out->name), "&%s", sn);
                }
                sqlite3_finalize(ss);
            }
        }
        if (!out->name[0]) {
            if (out->imm_val < 256 && out->imm_val > -256)
                snprintf(out->name, sizeof(out->name), "%lld", (long long)out->imm_val);
            else
                snprintf(out->name, sizeof(out->name), "0x%llx", (unsigned long long)out->imm_val);
        }
        return;
    }

    /* 检查是否内存引用 (含 [ 或 ptr) */
    if (strchr(raw, '[') || strstr(raw, "ptr")) {
        out->kind = OP_MEM;
        /* 查询 ir_stmts 获取结构化内存操作数信息 */
        sqlite3_stmt *ms = NULL;
        sqlite3_prepare_v2(c,
            "SELECT mem_base, mem_disp FROM ir_stmts "
            "WHERE address=?1 AND op_type='mem_access' LIMIT 1",
            -1, &ms, NULL);
        if (ms) {
            sqlite3_bind_int64(ms, 1, (sqlite3_int64)insn_addr);
            if (sqlite3_step(ms) == SQLITE_ROW) {
                const char *mb = (const char *)sqlite3_column_text(ms, 0);
                int disp       = sqlite3_column_int(ms, 1);
                if (mb) {
                    snprintf(out->base, sizeof(out->base), "%s", mb);
                    out->disp = disp;
                    if (!strcmp(mb, "rbp") || !strcmp(mb, "rsp")) {
                        out->is_rbp_rel = 1;
                        /* 查变量映射 */
                        for (int v = 0; v < nvars; v++) {
                            if (vars[v].offset == disp) {
                                snprintf(out->name, sizeof(out->name), "%s", vars[v].name);
                                break;
                            }
                        }
                    }
                    if (!out->name[0]) {
                        /* 非栈变量: 显示指针解引用 */
                        if (disp != 0)
                            snprintf(out->name, sizeof(out->name), "*(%s%+d)", mb, disp);
                        else
                            snprintf(out->name, sizeof(out->name), "*(%s)", mb);
                    }
                }
            }
            sqlite3_finalize(ms);
        }
        if (!out->name[0])
            snprintf(out->name, sizeof(out->name), "*mem");
        return;
    }

    /* 未识别: 可能是标号名等 */
    out->kind = OP_UNK;
    snprintf(out->name, sizeof(out->name), "%s", raw);
}

/* ================================================================== */
/* Phase 5: 条件跳转类型 → C 比较运算符                                  */
/* ================================================================== */

static const char *jcc_to_cond(const char *jcc) {
    if      (!strcmp(jcc,"je")||!strcmp(jcc,"jz"))   return "==";
    if      (!strcmp(jcc,"jne")||!strcmp(jcc,"jnz")) return "!=";
    if      (!strcmp(jcc,"jg")||!strcmp(jcc,"jnle")) return ">";
    if      (!strcmp(jcc,"jge")||!strcmp(jcc,"jnl")) return ">=";
    if      (!strcmp(jcc,"jl")||!strcmp(jcc,"jnge")) return "<";
    if      (!strcmp(jcc,"jle")||!strcmp(jcc,"jng")) return "<=";
    if      (!strcmp(jcc,"ja")||!strcmp(jcc,"jnbe")) return "> (u)";
    if      (!strcmp(jcc,"jb")||!strcmp(jcc,"jnae")) return "< (u)";
    if      (!strcmp(jcc,"jae")||!strcmp(jcc,"jnb")) return ">= (u)";
    if      (!strcmp(jcc,"jbe")||!strcmp(jcc,"jna")) return "<= (u)";
    if      (!strcmp(jcc,"js"))  return "<0?";
    if      (!strcmp(jcc,"jns")) return ">=0?";
    if      (!strcmp(jcc,"jo"))  return "overflow?";
    if      (!strcmp(jcc,"jno")) return "!overflow?";
    return "?";
}

/* 操作数类型 → C 运算符组合 */
static const char *mnem_to_op(const char *mn) {
    if (!strcmp(mn,"add"))  return "+";
    if (!strcmp(mn,"sub"))  return "-";
    if (!strcmp(mn,"imul")||!strcmp(mn,"mul")) return "*";
    if (!strcmp(mn,"and"))  return "&";
    if (!strcmp(mn,"or"))   return "|";
    if (!strcmp(mn,"xor"))  return "^";
    if (!strcmp(mn,"shl")||!strcmp(mn,"sal")) return "<<";
    if (!strcmp(mn,"shr"))  return ">>";
    if (!strcmp(mn,"sar"))  return ">> (arithmetic)";
    return "?";
}

/* ================================================================== */
/* Phase 6: 输出反编译结果                                               */
/* ================================================================== */

static int output_decompiled(sqlite3 *c, uint64_t faddr, uint64_t fend,
                              const char *fname, dvar_t *vars, int nvars,
                              dcall_t *calls, int ncalls,
                              dbb_t *bbs, int nbb, PanelData *pd)
{
    (void)bbs; (void)nbb;
    char buf[512];
    sqlite3_stmt *st = NULL;

    /* 统计参数数 */
    int nargs = 0;
    for (int v = 0; v < nvars; v++) if (vars[v].is_arg) nargs++;

    /* ── 函数签名 ──────────────────────────────────────────── */
    {
        snprintf(buf, sizeof(buf), "void %s(", fname);
        if (nargs > 0) {
            int shown = 0;
            for (int v = 0; v < nvars; v++) {
                if (!vars[v].is_arg) continue;
                char t[48];
                snprintf(t, sizeof(t), "%s%s %s", shown?", ":"", vars[v].type, vars[v].name);
                strncat(buf, t, sizeof(buf) - strlen(buf) - 1);
                if (++shown >= 6) break;
            }
        } else strncat(buf, "void", sizeof(buf) - strlen(buf) - 1);
        strncat(buf, ") {", sizeof(buf) - strlen(buf) - 1);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    /* 栈帧大小 */
    {
        int frame_sz = 0;
        sqlite3_stmt *fs = NULL;
        sqlite3_prepare_v2(c,
            "SELECT op_str FROM instructions "
            "WHERE address BETWEEN ?1 AND ?2 AND mnemonic='sub' "
            "AND op_str LIKE '%rsp%' LIMIT 1", -1, &fs, NULL);
        if (fs) {
            sqlite3_bind_int64(fs, 1, (sqlite3_int64)faddr);
            sqlite3_bind_int64(fs, 2, (sqlite3_int64)fend);
            if (sqlite3_step(fs) == SQLITE_ROW) {
                const char *op = (const char *)sqlite3_column_text(fs, 0);
                if (op) {
                    const char *c2 = strchr(op, ',');
                    if (c2) { c2++; while (*c2 == ' ') c2++;
                        frame_sz = (strncmp(c2,"0x",2)==0)?(int)strtol(c2,NULL,16):atoi(c2); }
                }
            }
            sqlite3_finalize(fs);
        }
        snprintf(buf, sizeof(buf), "  // stack: 0x%x, %d vars, %d args",
                 frame_sz, nvars, nargs);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    /* 局部变量声明 */
    for (int v = 0; v < nvars; v++) {
        if (vars[v].is_arg) continue;
        snprintf(buf, sizeof(buf), "  %-10s %s;   // [rbp-0x%x]",
                 vars[v].type, vars[v].name, -vars[v].offset);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* ── 指令流 → 伪代码 ──────────────────────────────────── */

    /* 先收集所有指令到数组 (便于前后查阅) */
    typedef struct { uint64_t addr; char mn[16], op[128], bytes[16]; int bsz; } insn_rec_t;
    insn_rec_t insns[MAX_INSNS];
    int ninsn = 0;

    sqlite3_prepare_v2(c,
        "SELECT address, mnemonic, op_str, bytes, size FROM instructions "
        "WHERE address BETWEEN ?1 AND ?2 ORDER BY address",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)faddr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)fend);

    while (sqlite3_step(st) == SQLITE_ROW && ninsn < MAX_INSNS) {
        insn_rec_t *ir = &insns[ninsn];
        ir->addr = (uint64_t)sqlite3_column_int64(st, 0);
        const char *mn = (const char *)sqlite3_column_text(st, 1);
        const char *op = (const char *)sqlite3_column_text(st, 2);
        snprintf(ir->mn, sizeof(ir->mn), "%s", mn ? mn : "");
        snprintf(ir->op, sizeof(ir->op), "%s", op ? op : "");
        const uint8_t *by = (const uint8_t *)sqlite3_column_blob(st, 3);
        ir->bsz = sqlite3_column_bytes(st, 3);
        if (ir->bsz > 15) ir->bsz = 15;
        if (by) { int hp=0; for (int i=0;i<ir->bsz&&hp<14;i++) hp+=snprintf(ir->bytes+hp,16-(size_t)hp,"%02x ",by[i]); }
        ninsn++;
    }
    sqlite3_finalize(st);

    /* 遍历指令, 输出伪代码 */
    int indent   = 2;  /* 缩进级别 */

    for (int ii = 0; ii < ninsn; ii++) {
        insn_rec_t *ir = &insns[ii];
        const char *mn = ir->mn;
        const char *op = ir->op;

        /* 跳过栈帧序言 */
        if (!strcmp(mn,"push") && !strcmp(op,"rbp")) continue;
        if (!strcmp(mn,"mov")  && strstr(op,"rbp, rsp")) continue;
        if (!strcmp(mn,"sub")  && strstr(op,"rsp")) continue;
        if (!strcmp(mn,"endbr64") || !strcmp(mn,"nop")) continue;

        /* ── call ── */
        if (!strcmp(mn, "call")) {
            dcall_t *cl = NULL;
            for (int ci = 0; ci < ncalls; ci++)
                if (calls[ci].call_addr == ir->addr) { cl = &calls[ci]; break; }

            char spaces[16]; memset(spaces, ' ', sizeof(spaces));
            int sp = indent * 2; if (sp > 14) sp = 14; spaces[sp] = '\0';

            if (cl && cl->nargs > 0) {
                char argbuf[256] = "";
                for (int ai = 0; ai < cl->nargs && ai < 6; ai++) {
                    if (ai > 0) strncat(argbuf, ", ", sizeof(argbuf)-strlen(argbuf)-1);
                    if (cl->args[ai].text[0])
                        strncat(argbuf, cl->args[ai].text, sizeof(argbuf)-strlen(argbuf)-1);
                    else
                        strncat(argbuf, "?", sizeof(argbuf)-strlen(argbuf)-1);
                    /* 角色标注 */
                    if (cl->args[ai].role[0] && strcmp(cl->args[ai].role,"UNKNOWN")) {
                        strncat(argbuf, " /*", sizeof(argbuf)-strlen(argbuf)-1);
                        strncat(argbuf, cl->args[ai].role, sizeof(argbuf)-strlen(argbuf)-1);
                        strncat(argbuf, "*/", sizeof(argbuf)-strlen(argbuf)-1);
                    }
                }
                snprintf(buf, sizeof(buf), "%s%s(%s);", spaces, cl->callee, argbuf);
            } else if (cl) {
                snprintf(buf, sizeof(buf), "%s%s();", spaces, cl->callee);
            } else {
                const char *cn = op[0] ? op : "??";
                snprintf(buf, sizeof(buf), "%s%s();", spaces, cn);
            }
            fields_add(pd, buf, 0, 0, DETAIL_NONE, (int)(ir->addr & 0x7FFFFFFF));
            continue;
        }

        /* ── cmp + 下一条条件跳转 → if 语句 ── */
        if ((!strcmp(mn,"cmp") || !strcmp(mn,"test")) && ii+1 < ninsn) {
            insn_rec_t *next = &insns[ii+1];
            const char *jcc = next->mn;
            if (jcc[0]=='j' && strcmp(jcc,"jmp") && strcmp(jcc,"jrcxz")) {
                /* 解析 cmp 的操作数 */
                char opps[3][64]; int nops = split_operands(op, opps);
                operand_t a, b;
                classify_operand(c, ir->addr, nops>=1?opps[0]:NULL, vars, nvars, &a);
                classify_operand(c, ir->addr, nops>=2?opps[1]:NULL, vars, nvars, &b);

                char spaces[16]; memset(spaces, ' ', sizeof(spaces));
                int sp = indent * 2; if (sp > 14) sp = 14; spaces[sp] = '\0';

                if (!strcmp(mn,"test") && a.kind == OP_REG && b.kind == OP_REG &&
                    !strcmp(a.raw, b.raw)) {
                    /* test reg, reg → 检测 reg 是否为 0 */
                    snprintf(buf, sizeof(buf), "%sif (%s %s 0) {",
                             spaces, a.name, jcc_to_cond(jcc));
                } else if (a.name[0] && b.name[0]) {
                    snprintf(buf, sizeof(buf), "%sif (%s %s %s) {",
                             spaces, a.name, jcc_to_cond(jcc), b.name);
                } else {
                    snprintf(buf, sizeof(buf), "%sif (%s %s %s) {  // cmp %s",
                             spaces,
                             nops>=1?opps[0]:"?", jcc_to_cond(jcc),
                             nops>=2?opps[1]:"?", op);
                }
                fields_add(pd, buf, 0, 0, DETAIL_NONE, (int)(ir->addr & 0x7FFFFFFF));
                indent++;
                ii++; /* 跳过 jcc 指令 */
                continue;
            }
        }

        /* ── 无条件跳转 → 回边 / goto / break ── */
        if (!strcmp(mn, "jmp")) {
            uint64_t tgt = op ? (uint64_t)strtoull(op, NULL, 16) : 0;
            indent--; if (indent < 1) indent = 1;
            char spaces[16]; memset(spaces, ' ', sizeof(spaces));
            int sp = indent * 2; if (sp > 14) sp = 14; spaces[sp] = '\0';

            if (tgt > 0 && is_loop_back_edge(ir->addr, tgt)) {
                snprintf(buf, sizeof(buf), "%s}  // loop → 0x%lx", spaces, (unsigned long)tgt);
            } else {
                snprintf(buf, sizeof(buf), "%sgoto 0x%lx;", spaces, (unsigned long)tgt);
            }
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
            continue;
        }

        /* ── ret / leave → return ── */
        if (!strcmp(mn,"ret") || !strcmp(mn,"retn") || !strcmp(mn,"leave")) {
            /* 闭合所有未闭合的 if */
            while (indent > 2) {
                char spaces[16]; memset(spaces,' ',sizeof(spaces));
                int sp = indent * 2; if (sp>14) sp=14; spaces[sp]='\0';
                fields_add(pd, "}", 0, 0, DETAIL_NONE, -1);
                indent--;
            }
            fields_add(pd, "  return;", 0, 0, DETAIL_NONE, -1);
            continue;
        }

        /* ── 所有其他指令: 操作数解析 → C 表达式 ── */
        {
            char opps[3][64]; int nops = split_operands(op, opps);
            operand_t dst, src;
            classify_operand(c, ir->addr, nops>=1?opps[0]:NULL, vars, nvars, &dst);
            classify_operand(c, ir->addr, nops>=2?opps[1]:NULL, vars, nvars, &src);

            char spaces[16]; memset(spaces, ' ', sizeof(spaces));
            int sp = indent * 2; if (sp > 14) sp = 14; spaces[sp] = '\0';

            /* mov / movsx / movzx / lea → 赋值 */
            if (!strcmp(mn,"mov") || !strcmp(mn,"movsx") || !strcmp(mn,"movzx")) {
                if (dst.name[0] && src.name[0])
                    snprintf(buf, sizeof(buf), "%s%s = %s;", spaces, dst.name, src.name);
                else
                    snprintf(buf, sizeof(buf), "%s%s = %s;", spaces,
                             nops>=1?opps[0]:"?", nops>=2?opps[1]:"?");
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                continue;
            }

            if (!strcmp(mn,"lea")) {
                if (dst.name[0])
                    snprintf(buf, sizeof(buf), "%s%s = &(%s);", spaces, dst.name,
                             src.name[0] ? src.name : (nops>=2?opps[1]:"?"));
                else
                    snprintf(buf, sizeof(buf), "%slea %s;", spaces, op);
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                continue;
            }

            /* 算术/逻辑指令 (读-改-写 dst) */
            const char *opc = mnem_to_op(mn);
            if (strcmp(opc, "?")) {
                /* 对于 inc/dec: 特殊处理 */
                if (!strcmp(mn,"inc")) {
                    snprintf(buf, sizeof(buf), "%s%s++;", spaces,
                             dst.name[0]?dst.name:(nops>=1?opps[0]:"?"));
                } else if (!strcmp(mn,"dec")) {
                    snprintf(buf, sizeof(buf), "%s%s--;", spaces,
                             dst.name[0]?dst.name:(nops>=1?opps[0]:"?"));
                } else if (dst.name[0] && src.name[0]) {
                    /* dst = dst OP src */
                    snprintf(buf, sizeof(buf), "%s%s = %s %s %s;",
                             spaces, dst.name, dst.name, opc, src.name);
                } else {
                    /* fallback: 显示汇编 */
                    snprintf(buf, sizeof(buf), "%s%s %s;",
                             spaces, mn, op);
                }
                fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
                continue;
            }

            /* push/pop/syscall/其他 */
            if (!strcmp(mn,"push")) {
                snprintf(buf, sizeof(buf), "%spush(%s);", spaces,
                         dst.name[0]?dst.name:(op?op:"?"));
            } else if (!strcmp(mn,"pop")) {
                snprintf(buf, sizeof(buf), "%s%s = pop();", spaces,
                         dst.name[0]?dst.name:(op?op:"?"));
            } else if (!strcmp(mn,"syscall")) {
                snprintf(buf, sizeof(buf), "%ssyscall;", spaces);
            } else if (!strcmp(mn,"int3")) {
                snprintf(buf, sizeof(buf), "%s// breakpoint", spaces);
            } else {
                /* 未识别: 显示为注释 */
                snprintf(buf, sizeof(buf), "%s// %-8s %s", spaces, mn, op);
            }
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        }
    }

    /* 闭合所有未闭合的 if */
    while (indent > 2) {
        indent--;
        fields_add(pd, "  }", 0, 0, DETAIL_NONE, -1);
    }

    fields_add(pd, "}", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* ── 汇编参考 (底部独立区域) ────────────────────────────── */
    fields_add(pd, "/* ── Assembly Reference ────────────────────────────── */", 0, 0, DETAIL_NONE, -1);
    for (int ii = 0; ii < ninsn; ii++) {
        insn_rec_t *ir = &insns[ii];
        snprintf(buf, sizeof(buf), "  /* 0x%lx: %-16s %-8s %s */",
                 (unsigned long)ir->addr, ir->bytes, ir->mn, ir->op);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    }

    /* 摘要 */
    snprintf(buf, sizeof(buf),
             "── %d insns, %d BBs, %d vars, %d calls ──",
             ninsn, nbb, nvars, ncalls);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    return 0;
}

/* ================================================================== */
/* 公共接口                                                            */
/* ================================================================== */

int decompile_function_at(uint64_t func_addr, PanelData *pd)
{
    if (!g_active_db || !pd) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) return -1;

    char     fname[128] = "sub_unknown";
    uint64_t fend       = func_addr + 0x1000;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT name, end_addr FROM functions WHERE start_addr=?1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *n = (const char *)sqlite3_column_text(st, 0);
            if (n) snprintf(fname, sizeof(fname), "%s", n);
            fend = (uint64_t)sqlite3_column_int64(st, 1);
        }
        sqlite3_finalize(st);
    }

    if (pd->fields) {
        fields_free(pd->fields, pd->count);
        pd->fields = NULL; pd->count = 0; pd->capacity = 0;
        pd->cursor = 0; pd->scroll = 0;
    }

    dvar_t vars[MAX_VARS]; int nvars = 0;
    if (build_var_map(c, func_addr, fend, vars, &nvars) != 0) {
        fields_add(pd, "(var map build failed)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    dcall_t calls[MAX_CALLS]; int ncalls = 0;
    build_call_info(c, func_addr, fend, calls, &ncalls);

    dbb_t bbs[MAX_BBS]; int nbb = 0;
    build_cfg(c, func_addr, fend, bbs, &nbb);

    return output_decompiled(c, func_addr, fend, fname,
                              vars, nvars, calls, ncalls, bbs, nbb, pd);
}

int parse_decompile(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)ctx; (void)shdr_idx;
    if (!g_active_db) {
        fields_add(pd, "(DB not available — import ELF first)", 0, 0, DETAIL_NONE, -1);
        return 0;
    }
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) { fields_add(pd, "(DB connection failed)", 0, 0, DETAIL_NONE, -1); return 0; }

    char buf[512];
    fields_add(pd, "=== Decompile — select function, Enter = decompile → right panel ===", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "v3: operand-aware + ir_stmts variable resolution", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT f.start_addr, f.name, f.bb_count, f.end_addr "
        "FROM functions f ORDER BY f.start_addr", -1, &st, NULL);
    if (!st) { fields_add(pd, "(query failed)", 0, 0, DETAIL_NONE, -1); return 0; }

    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        uint64_t fa   = (uint64_t)sqlite3_column_int64(st, 0);
        const char *nm = (const char *)sqlite3_column_text(st, 1);
        int bbc        = sqlite3_column_int(st, 2);
        uint64_t fe    = (uint64_t)sqlite3_column_int64(st, 3);

        sqlite3_stmt *ic = NULL;
        int insn_cnt = 0;
        sqlite3_prepare_v2(c,
            "SELECT COUNT(*) FROM instructions WHERE address BETWEEN ?1 AND ?2",
            -1, &ic, NULL);
        if (ic) {
            sqlite3_bind_int64(ic, 1, (sqlite3_int64)fa);
            sqlite3_bind_int64(ic, 2, (sqlite3_int64)fe);
            if (sqlite3_step(ic) == SQLITE_ROW)
                insn_cnt = sqlite3_column_int(ic, 0);
            sqlite3_finalize(ic);
        }

        n++;
        snprintf(buf, sizeof(buf),
                 "[%3d] 0x%lx  %-35s  %3d BBs  %4d insns",
                 n, (unsigned long)fa, nm ? nm : "?", bbc, insn_cnt);
        fields_add(pd, buf, 0, 1, DETAIL_NONE, (int)(fa & 0x7FFFFFFF));
    }
    sqlite3_finalize(st);
    return pd->count;
}
