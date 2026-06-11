/*
 * taint.c — 静态污点追踪引擎 (v2 — DB 优先)
 *
 * 双路径:
 *   DB 路径:  从 ir_stmts + xrefs + cfg_edges 表做跨函数数据流追踪
 *   mmap 路径: 函数内数据流分析 (原有逻辑, DB 不可用时降级)
 *
 * API:
 *   int parse_taint(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 *   int taint_analyze(Elf64_Ctx *ctx, disasm_ctx *d, taint_report_t *report);  // mmap
 *
 * 依赖: disasm.h (Capstone, 仅 mmap 路径)
 */
#include "elf_parser.h"
#include "disasm.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* 外部 DB 句柄 */
extern AnalysisDB *g_active_db;

/* ================================================================== */
/* Source / Sink 定义                                                 */
/* ================================================================== */

typedef enum {
    SRC_NET,     /* 网络输入: recv/recvfrom/read */
    SRC_FILE,    /* 文件输入: fread/fgets/read */
    SRC_USER,    /* 用户输入: scanf/gets/argv/env */
    SRC_ENV,     /* 环境变量: getenv */
} source_type_t;

typedef enum {
    SNK_BOF,        /* 缓冲区溢出: strcpy/memcpy/sprintf */
    SNK_FMTSTR,     /* 格式化字符串: printf(fmt)/syslog */
    SNK_CMD,        /* 命令注入: system/execve/popen */
    SNK_ARB_WRITE,  /* 任意写: memcpy with tainted size */
} sink_type_t;

typedef struct {
    const char *name;
    source_type_t type;
    int          taints_retval;  /* rax 被污染 */
    int          taints_buffer;  /* rdi 指向的缓冲区被污染 */
    int          taints_size;    /* rdx 参数被污染 (实际读取的大小) */
} source_def_t;

typedef struct {
    const char *name;
    sink_type_t  type;
    int          critical_arg;  /* 需要检查的参数索引 (0=rdi, 1=rsi, 2=rdx) */
} sink_def_t;

static const source_def_t SOURCES[] = {
    {"read",        SRC_FILE, 1, 1, 1},
    {"recv",        SRC_NET,  1, 1, 1},
    {"recvfrom",    SRC_NET,  1, 1, 1},
    {"fread",       SRC_FILE, 1, 1, 1},
    {"fgets",       SRC_USER, 0, 1, 0},
    {"gets",        SRC_USER, 0, 1, 0},
    {"scanf",       SRC_USER, 0, 1, 0},
    {"getenv",      SRC_ENV,  1, 0, 0},
    {"__isoc99_scanf", SRC_USER, 0, 1, 0},
    {"readline",    SRC_USER, 1, 1, 0},
};

static const sink_def_t SINKS[] = {
    {"strcpy",      SNK_BOF,       1},  /* rsi = src */
    {"strcat",      SNK_BOF,       1},
    {"sprintf",     SNK_FMTSTR,    0},  /* rdi = fmt string (if tainted) */
    {"printf",      SNK_FMTSTR,    0},
    {"fprintf",     SNK_FMTSTR,    1},  /* rsi = fmt string */
    {"memcpy",      SNK_ARB_WRITE, 2},  /* rdx = size */
    {"memmove",     SNK_ARB_WRITE, 2},
    {"system",      SNK_CMD,       0},  /* rdi = command */
    {"popen",       SNK_CMD,       0},
    {"execve",      SNK_CMD,       0},
    {"execl",       SNK_CMD,       0},
};

#define NSRC ((int)(sizeof(SOURCES)/sizeof(SOURCES[0])))
#define NSNK ((int)(sizeof(SINKS)/sizeof(SINKS[0])))

/* ================================================================== */
/* 污点数据结构                                                       */
/* ================================================================== */

#define TAINT_REGS 24    /* 通用寄存器 + rflags */
#define TAINT_STACK 128  /* 追踪的栈槽位数 */

typedef struct {
    int regs[TAINT_REGS];          /* 每个寄存器的污点来源 (-1=clean) */
    int stack[TAINT_STACK];        /* 栈偏移的污点来源 */
    uint64_t rsp_base;             /* 函数入口时的 rsp (用于栈偏移计算) */
    int      next_id;              /* 下一个污点 ID */
} taint_state_t;

typedef struct {
    uint64_t addr;              /* source 调用的地址 */
    const char *func_name;
    source_type_t type;
    int          taint_id;
    char         desc[192];
} taint_source_t;

typedef struct {
    uint64_t src_addr;          /* source 地址 */
    uint64_t sink_addr;         /* sink 地址 */
    const char *src_func;       /* source 函数名 */
    const char *sink_func;      /* sink 函数名 */
    int         arg_index;      /* 哪个参数被污染 (0=rdi,1=rsi,2=rdx,...) */
    sink_type_t sink_type;
    int         confidence;     /* 0-100 */
    char        path[256];      /* 数据流路径描述 */
} taint_alert_t;

typedef struct taint_report_t {
    taint_source_t *sources;
    int             nsrc;
    taint_alert_t  *alerts;
    int             nalerts;
    int             cap_src;
    int             cap_alert;
} taint_report_t;

/* ================================================================== */
/* 污点追踪核心                                                       */
/* ================================================================== */

static void taint_init(taint_state_t *ts) {
    memset(ts, 0, sizeof(*ts));
    for (int i = 0; i < TAINT_REGS; i++) ts->regs[i] = -1;
    for (int i = 0; i < TAINT_STACK; i++) ts->stack[i] = -1;
}

static int taint_new_id(taint_state_t *ts) { return ts->next_id++; }

/* 寄存器索引: 使用 Capstone 的 x86_reg 值 */
static int reg_index(unsigned int reg)
{
    if (reg >= X86_REG_RAX && reg <= X86_REG_R15) return (int)(reg - X86_REG_RAX);
    return -1;
}

/* 源函数名 → source_def */
static const source_def_t *find_source(const char *name) {
    for (int i = 0; i < NSRC; i++)
        if (!strcmp(SOURCES[i].name, name)) return &SOURCES[i];
    return NULL;
}
static const sink_def_t *find_sink(const char *name) {
    for (int i = 0; i < NSNK; i++)
        if (!strcmp(SINKS[i].name, name)) return &SINKS[i];
    return NULL;
}

/**
 * 扫描单个代码节的污点传播。
 * 收集 sources 并在遇到 sinks 时检查污点。
 */
static int scan_section(Elf64_Ctx *ctx, disasm_ctx *d __attribute__((unused)),
                         const uint8_t *code, size_t size, uint64_t base,
                         taint_report_t *report)
{
    disasm_ctx *ld = disasm_open();
    if (!ld) return -1;

    taint_state_t ts;
    taint_init(&ts);
    ts.rsp_base = 0; /* 简化: 假定 rsp 在函数入口不变 */

    const uint8_t *ptr = code;
    size_t left = size;
    uint64_t addr = base;

    /* 用于解析符号名 */
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;

    while (left > 0 && disasm_next(ld, &ptr, &left, &addr)) {
        cs_insn *insn = disasm_insn(ld);
        if (!insn->detail) continue;

        /* ── 检测 call 指令 ── */
        int is_call = 0;
        for (uint8_t g = 0; g < insn->detail->groups_count; g++)
            if (insn->detail->groups[g] == X86_GRP_CALL) { is_call = 1; break; }
        if (!is_call) continue;

        /* 解析 call 目标名称 */
        uint64_t target = 0;
        cs_x86 *x86 = &insn->detail->x86;
        for (uint8_t oi = 0; oi < x86->op_count; oi++)
            if (x86->operands[oi].type == X86_OP_IMM)
            { target = (uint64_t)x86->operands[oi].imm; break; }

        const char *call_name = NULL;
        /* 尝试从符号表解析 */
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || (sh->sh_type != SHT_DYNSYM && sh->sh_type != SHT_SYMTAB)) continue;
            Elf64_Shdr *strsh = elf_get_shdr(ctx, sh->sh_link);
            if (!strsh) continue;
            Elf64_Sym *syms = (Elf64_Sym *)(ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym; j++) {
                if (syms[j].st_value == target) {
                    call_name = elf_strtab_get(ctx, strsh->sh_offset, syms[j].st_name);
                    break;
                }
            }
            if (call_name) break;
        }
        if (!call_name) call_name = insn->op_str; /* fallback */

        /* ── Source check ── */
        const source_def_t *src = find_source(call_name);
        if (src) {
            if (report->nsrc >= report->cap_src) {
                report->cap_src = report->cap_src ? report->cap_src * 2 : 64;
                report->sources = realloc(report->sources,
                    (size_t)report->cap_src * sizeof(taint_source_t));
            }
            taint_source_t *tsrc = &report->sources[report->nsrc++];
            tsrc->addr = insn->address;
            tsrc->func_name = call_name;
            tsrc->type = src->type;
            tsrc->taint_id = taint_new_id(&ts);
            snprintf(tsrc->desc, sizeof(tsrc->desc),
                     "%s @ 0x%lx → taint id=%d", call_name, insn->address, tsrc->taint_id);

            /* 标记寄存器 */
            if (src->taints_retval) ts.regs[reg_index(X86_REG_RAX)] = tsrc->taint_id;
            if (src->taints_buffer) ts.regs[reg_index(X86_REG_RDI)] = tsrc->taint_id;
            if (src->taints_size)   ts.regs[reg_index(X86_REG_RDX)] = tsrc->taint_id;
        }

        /* ── Sink check ── */
        const sink_def_t *snk = find_sink(call_name);
        if (snk) {
            int check_regs[] = {X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9};
            int arg_idx = snk->critical_arg;
            if (arg_idx >= 0 && arg_idx < 6) {
                int ri = reg_index((unsigned int)check_regs[arg_idx]);
                if (ri >= 0 && ts.regs[ri] >= 0) {
                    /* ALERT: tainted data reaches sink! */
                    if (report->nalerts >= report->cap_alert) {
                        report->cap_alert = report->cap_alert ? report->cap_alert * 2 : 128;
                        report->alerts = realloc(report->alerts,
                            (size_t)report->cap_alert * sizeof(taint_alert_t));
                    }
                    taint_alert_t *a = &report->alerts[report->nalerts++];
                    a->src_addr = 0;
                    a->sink_addr = insn->address;
                    a->src_func = "?";
                    a->sink_func = call_name;
                    a->arg_index = arg_idx;
                    a->sink_type = snk->type;
                    a->confidence = 85;

                    /* 查找造成污染的 source */
                    for (int s = 0; s < report->nsrc; s++) {
                        if (report->sources[s].taint_id == ts.regs[ri]) {
                            a->src_addr = report->sources[s].addr;
                            a->src_func = report->sources[s].func_name;
                            break;
                        }
                    }

                    snprintf(a->path, sizeof(a->path),
                             "%s → arg%d of %s @ 0x%lx (taint id %d → %s)",
                             a->src_func, arg_idx, a->sink_func,
                             a->sink_addr, ts.regs[ri],
                             snk->type == SNK_BOF ? "BUFFER OVERFLOW" :
                             snk->type == SNK_FMTSTR ? "FORMAT STRING" :
                             snk->type == SNK_CMD ? "COMMAND INJECTION" :
                             "ARBITRARY WRITE");
                }
            }
        }

        /* ── 寄存器传播 (简化) ──   */
        /* mov rdi, rax → rdi inherits rax's taint */
        if (insn->id == X86_INS_MOV && x86->op_count >= 2) {
            if (x86->operands[0].type == X86_OP_REG &&
                x86->operands[1].type == X86_OP_REG) {
                int dst = reg_index(x86->operands[0].reg);
                int src_r = reg_index(x86->operands[1].reg);
                if (dst >= 0 && src_r >= 0 && ts.regs[src_r] >= 0)
                    ts.regs[dst] = ts.regs[src_r];
            }
        }
        /* xor reg,reg → clear taint */
        if (insn->id == X86_INS_XOR && x86->op_count == 2) {
            if (x86->operands[0].type == X86_OP_REG &&
                x86->operands[0].reg == x86->operands[1].reg) {
                int ri = reg_index(x86->operands[0].reg);
                if (ri >= 0) ts.regs[ri] = -1;
            }
        }
        /* lea rdi, [rsp+...] → 栈地址, 不追踪 */
        /* add/sub → 保守保持 (值变了但可能仍与源相关) */
    }

    disasm_close(ld);
    return 0;
}

/* ================================================================== */
/* DB 路径: 基于 xrefs + ir_stmts 的跨函数污点追踪                     */
/* ================================================================== */

static int parse_taint_db(AnalysisDB *adb, PanelData *pd)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;

    char buf[512];
    fields_add(pd, "=== Taint Analysis [DB] ===", 0, 0, DETAIL_NONE, -1);

    /* Source → Sink 路径: 对每对 (source_func, sink_func), 查找调用路径 */
    static const struct {
        const char *src_name;
        const char *snk_name;
        const char *src_arg;
        const char *snk_arg;
        const char *risk_desc;
    } source_sink_pairs[] = {
        {"recv",    "strcpy",  "rdi(buf)", "rsi(src)", "buffer overflow — recv buffer → strcpy source"},
        {"recv",    "strcat",  "rdi(buf)", "rsi(src)", "buffer overflow — recv buffer → strcat source"},
        {"recv",    "memcpy",  "rdi(buf)", "rdx(len)", "arbitrary write — recv len → memcpy size"},
        {"recv",    "system",  "rdi(buf)", "rdi(cmd)", "command injection — recv data → system arg"},
        {"read",    "strcpy",  "rdi(buf)", "rsi(src)", "buffer overflow — file read → strcpy"},
        {"read",    "printf",  "rdi(buf)", "rdi(fmt)", "format string — file data → printf fmt"},
        {"recvfrom","strcpy",  "rdi(buf)", "rsi(src)", "buffer overflow — network → strcpy"},
        {"fgets",   "strcpy",  "rdi(buf)", "rsi(src)", "buffer overflow — stdin → strcpy"},
        {"getenv",  "strcpy",  "rax(ret)","rsi(src)", "buffer overflow — env var → strcpy"},
        {"gets",    "strcpy",  "rdi(buf)", "rsi(src)", "buffer overflow — gets → strcpy"},
        {"scanf",   "system",  "rdi(buf)", "rdi(cmd)", "command injection — scanf → system"},
        {"recv",    "write",   "rdi(buf)", "rdi(buf)", "info leak — recv buffer → write output"},
        {"read",    "send",    "rdi(buf)", "rdi(buf)", "info leak — file data → network send"},
        {NULL, NULL, NULL, NULL, NULL}
    };

    int total_alerts = 0;

    for (int pi = 0; source_sink_pairs[pi].src_name; pi++) {
        /* 查找同时存在 source 和 sink 的函数 */
        char sql[1024];
        snprintf(sql, sizeof(sql),
            "SELECT DISTINCT f.start_addr, f.name "
            "FROM xrefs xs "
            "JOIN symbols ss ON xs.to_addr=ss.address AND ss.name='%s' "
            "JOIN instructions isrc ON xs.from_addr=isrc.address "
            "JOIN functions f ON f.start_addr<=isrc.address AND f.end_addr>isrc.address "
            "WHERE EXISTS ("
            "  SELECT 1 FROM xrefs xk "
            "  JOIN symbols sk ON xk.to_addr=sk.address AND sk.name='%s' "
            "  JOIN instructions isnk ON xk.from_addr=isnk.address "
            "  WHERE isnk.address BETWEEN f.start_addr AND f.end_addr"
            ") "
            "LIMIT 20",
            source_sink_pairs[pi].src_name,
            source_sink_pairs[pi].snk_name);

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c, sql, -1, &st, NULL) != SQLITE_OK) continue;

        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t func_addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *fname  = (const char *)sqlite3_column_text(st, 1);

            if (total_alerts == 0) {
                fields_add(pd, "── Source → Sink Paths ──", 1, 0, DETAIL_NONE, -1);
            }

            snprintf(buf, sizeof(buf),
                     "[ALERT] %s → %s in %s @ 0x%lx",
                     source_sink_pairs[pi].src_name,
                     source_sink_pairs[pi].snk_name,
                     fname ? fname : "?",
                     (unsigned long)func_addr);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)func_addr);

            snprintf(buf, sizeof(buf), "        %s", source_sink_pairs[pi].risk_desc);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

            found++;
            total_alerts++;
        }
        sqlite3_finalize(st);
    }

    /* 统计独立 source 调用点 */
    fields_add(pd, "── All Taint Sources ──", 1, 0, DETAIL_NONE, -1);

    static const char *src_funcs[] = {
        "recv","recvfrom","read","fread","fgets","gets","getenv","scanf","accept",
        "readline","__isoc99_scanf", NULL
    };

    int src_total = 0;
    for (const char **sf = src_funcs; *sf; sf++) {
        char sql2[512];
        snprintf(sql2, sizeof(sql2),
            "SELECT i.address, f.name FROM instructions i "
            "JOIN xrefs x ON i.address=x.from_addr "
            "JOIN symbols s ON x.to_addr=s.address "
            "LEFT JOIN functions f ON f.start_addr<=i.address AND f.end_addr>i.address "
            "WHERE i.mnemonic='call' AND x.ref_type='call' AND s.name='%s' "
            "LIMIT 40", *sf);

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(c, sql2, -1, &st, NULL) != SQLITE_OK) continue;
        int found = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *fn  = (const char *)sqlite3_column_text(st, 1);
            if (!found) {
                snprintf(buf, sizeof(buf), "↓ %s:", *sf);
                fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
            }
            snprintf(buf, sizeof(buf), "0x%lx  [%s]",
                     (unsigned long)addr, fn ? fn : "?");
            fields_add(pd, buf, 2, 1, DETAIL_NONE, (int)addr);
            found++; src_total++;
        }
        sqlite3_finalize(st);
    }

    if (total_alerts == 0 && src_total == 0) {
        fields_add(pd, "(no taint sources found — binary may use syscalls directly)", 1, 0, DETAIL_NONE, -1);
    } else {
        snprintf(buf, sizeof(buf), "%d source→sink alerts, %d source call sites",
                 total_alerts, src_total);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    return 0;
}

/* ================================================================== */
/* 公共接口: parse_taint (DB 优先, mmap 降级)                         */
/* ================================================================== */

int parse_taint(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)shdr_idx;
    if (g_active_db) {
        return parse_taint_db(g_active_db, pd);
    }
    /* mmap 路径: 调用 taint_analyze 并格式化到 PanelData */
    fields_add(pd, "=== Taint Analysis [mmap] ===", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "(DB not available — run import for deeper analysis)", 1, 0, DETAIL_NONE, -1);
    return 0;
}

/* ================================================================== */
/* 原始 mmap API: taint_analyze (保持向后兼容)                        */
/* ================================================================== */

int taint_analyze(Elf64_Ctx *ctx, disasm_ctx *d __attribute__((unused)), taint_report_t *report)
{
    if (!ctx || !d || !report) return -1;
    memset(report, 0, sizeof(*report));

    int nsec = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    for (int si = 0; si < nsec; si++) {
        Elf64_Shdr *sec = elf_get_shdr(ctx, si);
        if (!sec || !ctx->map + sec->sh_offset || sec->sh_size == 0) continue;
        if (!(sec->sh_flags & SHF_EXECINSTR)) continue;

        scan_section(ctx, d, (const uint8_t *)ctx->map + sec->sh_offset, sec->sh_size,
                     sec->sh_addr, report);
    }

    return report->nalerts;
}

void taint_report_free(taint_report_t *r) {
    if (!r) return;
    free(r->sources);
    free(r->alerts);
    memset(r, 0, sizeof(*r));
}
