/*
 * db.c — SQLite3 分析数据库实现 (v2 — Address-Centric)
 *
 * 11 张表, Address = 全局主键. 导入时 9 步完成, 查询时 address → 一切.
 * 依赖: sqlite3, capstone (disasm.h), elf_parser.h, core/debug_worker.h
 */

#include "core/db.h"
#include "core/debug_worker.h"
#include "disasm.h"
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

/* ── 内部结构 ────────────────────────────────────────────────────── */
struct AnalysisDB {
    sqlite3 *conn;
    char     err_msg[256];
    int      insn_count, snap_count;
};

static void set_error(AnalysisDB *db, const char *fmt, ...) {
    if (!db) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(db->err_msg, sizeof(db->err_msg), fmt, ap);
    va_end(ap);
}

static int exec_sql(AnalysisDB *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db->conn, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        set_error(db, "SQL: %s", err ? err : "?");
        sqlite3_free(err); return -1;
    }
    return 0;
}

#define DB_SCHEMA_VERSION 13

/* ── 建表 SQL (只建表, 不建索引 — 索引在数据导入后统一创建) ────── */
static const char *TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS sections("
    "  shdr_idx INTEGER PRIMARY KEY, name TEXT NOT NULL,"
    "  addr INTEGER, offset INTEGER, size INTEGER,"
    "  type INTEGER, flags INTEGER);"
    "CREATE TABLE IF NOT EXISTS segments("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  vaddr INTEGER NOT NULL, memsz INTEGER,"
    "  type TEXT, flags TEXT);"
    "CREATE TABLE IF NOT EXISTS symbols("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  address INTEGER NOT NULL, name TEXT NOT NULL,"
    "  size INTEGER, type TEXT, bind TEXT, table_name TEXT);"
    "CREATE TABLE IF NOT EXISTS instructions("
    "  address INTEGER PRIMARY KEY, bytes BLOB,"
    "  mnemonic TEXT NOT NULL, op_str TEXT,"
    "  size INTEGER NOT NULL, section TEXT,"
    /* Phase 4: 操作数结构分解 (消除 op_str 文本解析依赖) */
    "  op_count INTEGER DEFAULT 0,"
    "  op0_type TEXT,"             /* reg / mem / imm */
    "  op0_reg TEXT,"              /* 寄存器名: rax, rdi */
    "  op0_mem_base TEXT,"         /* 内存基址寄存器 */
    "  op0_mem_index TEXT,"        /* 内存索引寄存器 */
    "  op0_mem_scale INTEGER,"     /* 比例 1/2/4/8 */
    "  op0_mem_disp INTEGER,"      /* 偏移量 */
    "  op0_size INTEGER,"          /* 操作数大小 (字节) */
    "  op1_type TEXT, op1_reg TEXT,"
    "  op1_mem_base TEXT, op1_mem_index TEXT,"
    "  op1_mem_scale INTEGER, op1_mem_disp INTEGER, op1_size INTEGER,"
    "  op2_type TEXT, op2_reg TEXT,"
    "  op2_mem_base TEXT, op2_mem_index TEXT,"
    "  op2_mem_scale INTEGER, op2_mem_disp INTEGER, op2_size INTEGER);"
    "CREATE TABLE IF NOT EXISTS strings("
    "  address INTEGER PRIMARY KEY, value TEXT NOT NULL,"
    "  length INTEGER, section TEXT);"
    "CREATE TABLE IF NOT EXISTS functions("
    "  start_addr INTEGER PRIMARY KEY, end_addr INTEGER NOT NULL,"
    "  name TEXT, bb_count INTEGER DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS basic_blocks("
    "  start_addr INTEGER PRIMARY KEY, end_addr INTEGER NOT NULL,"
    "  function_addr INTEGER NOT NULL, insn_count INTEGER DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS cfg_edges("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  from_addr INTEGER NOT NULL, to_addr INTEGER NOT NULL,"
    "  edge_type TEXT NOT NULL);"
    "CREATE TABLE IF NOT EXISTS xrefs("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  from_addr INTEGER NOT NULL, to_addr INTEGER NOT NULL,"
    "  ref_type TEXT NOT NULL, detail TEXT);"
    "CREATE TABLE IF NOT EXISTS reg_snapshots("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL, step_num INTEGER NOT NULL,"
    "  rip INTEGER NOT NULL,"
    "  rax INTEGER,rbx INTEGER,rcx INTEGER,rdx INTEGER,"
    "  rsi INTEGER,rdi INTEGER,rbp INTEGER,rsp INTEGER,"
    "  r8 INTEGER,r9 INTEGER,r10 INTEGER,r11 INTEGER,"
    "  r12 INTEGER,r13 INTEGER,r14 INTEGER,r15 INTEGER,"
    "  eflags INTEGER,"
    "  cs INTEGER,ds INTEGER,es INTEGER,fs INTEGER,gs INTEGER,ss INTEGER);"
    "CREATE TABLE IF NOT EXISTS mem_snapshots("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL, address INTEGER NOT NULL,"
    "  data BLOB, size INTEGER, label TEXT);"
    "CREATE TABLE IF NOT EXISTS vuln_candidates("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  address INTEGER NOT NULL,"
    "  vuln_type TEXT, severity TEXT,"
    "  sink_func TEXT, description TEXT,"
    "  function_addr INTEGER);"
    "CREATE TABLE IF NOT EXISTS taint_sources("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  address INTEGER NOT NULL,"
    "  source_func TEXT NOT NULL,"
    "  target_reg TEXT,"
    "  function_addr INTEGER);"

    "CREATE TABLE IF NOT EXISTS heap_sessions("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  pid INTEGER, timestamp INTEGER, allocator TEXT,"
    "  heap_start INTEGER, heap_end INTEGER,"
    "  chunk_count INTEGER DEFAULT 0, anomaly_count INTEGER DEFAULT 0);"

    "CREATE TABLE IF NOT EXISTS heap_chunks("
    "  addr INTEGER NOT NULL, session_id INTEGER,"
    "  size INTEGER NOT NULL, allocator TEXT,"
    "  state TEXT NOT NULL, arena_addr INTEGER,"
    "  prev_size INTEGER DEFAULT 0, flags INTEGER DEFAULT 0);"
    "CREATE INDEX IF NOT EXISTS idx_hc_addr ON heap_chunks(addr);"
    "CREATE INDEX IF NOT EXISTS idx_hc_state ON heap_chunks(state);"

    "CREATE TABLE IF NOT EXISTS heap_links("
    "  src_addr INTEGER NOT NULL, dst_addr INTEGER NOT NULL,"
    "  link_type TEXT NOT NULL, session_id INTEGER);"
    "CREATE INDEX IF NOT EXISTS idx_hl_src ON heap_links(src_addr);"
    "CREATE INDEX IF NOT EXISTS idx_hl_dst ON heap_links(dst_addr);"

    "CREATE TABLE IF NOT EXISTS heap_anomalies("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER,"
    "  chunk_addr INTEGER, anomaly_type TEXT,"
    "  confidence REAL, description TEXT, severity TEXT);"

    "CREATE TABLE IF NOT EXISTS ir_stmts("
    "  address INTEGER NOT NULL,"
    "  op_type TEXT NOT NULL,"
    "  dst TEXT, src TEXT,"
    "  mem_base TEXT, mem_disp INTEGER,"
    "  imm_value INTEGER,"
    /* Phase 4: SSA 风格 use-def 链 */
    "  def_insn_addr INTEGER,"      /* 该寄存器值最近定义点 */
    "  size_bytes INTEGER);"        /* 操作大小 (字节) */

    /* Phase 2: Trace Tables */
    "CREATE TABLE IF NOT EXISTS trace_sessions("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  pid INTEGER NOT NULL, backend TEXT,"
    "  start_time INTEGER, bb_count INTEGER DEFAULT 0,"
    "  unique_bbs INTEGER DEFAULT 0);"

    "CREATE TABLE IF NOT EXISTS trace_blocks("
    "  session_id INTEGER NOT NULL,"
    "  bb_addr INTEGER NOT NULL,"
    "  exec_count INTEGER DEFAULT 1,"
    "  timestamp INTEGER,"
    "  UNIQUE(session_id, bb_addr));"
    "CREATE INDEX IF NOT EXISTS idx_tb_session ON trace_blocks(session_id);"
    "CREATE INDEX IF NOT EXISTS idx_tb_addr ON trace_blocks(bb_addr);"

    /* Phase 2: Heap Event Trace Table */
    "CREATE TABLE IF NOT EXISTS heap_events("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  session_id INTEGER NOT NULL,"
    "  timestamp INTEGER,"
    "  event_type TEXT NOT NULL,"
    "  chunk_addr INTEGER,"
    "  size INTEGER,"
    "  return_addr INTEGER,"
    "  extra_arg INTEGER);"
    "CREATE INDEX IF NOT EXISTS idx_he_session ON heap_events(session_id);"
    "CREATE INDEX IF NOT EXISTS idx_he_type ON heap_events(event_type);"

    /* Phase 3: Value Definition & Classification */
    "CREATE TABLE IF NOT EXISTS value_defs("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  def_addr INTEGER NOT NULL,"          /* 定义该值的指令地址 */
    "  def_type TEXT NOT NULL,"             /* IMMEDIATE/CALL_RET/ARG_IN/MEM_LOAD_STACK/MEM_LOAD_HEAP/MEM_LOAD_GLOBAL/REG_COPY/COMPUTATION/SOURCE_TAINTED */
    "  target TEXT,"                         /* 目标寄存器名 或 内存地址描述 */
    "  source_desc TEXT,"                    /* 人类可读描述 */
    "  related_addr INTEGER);"              /* 关联地址 */
    "CREATE INDEX IF NOT EXISTS idx_vd_addr ON value_defs(def_addr);"
    "CREATE INDEX IF NOT EXISTS idx_vd_type ON value_defs(def_type);"

    /* Phase 3: Call Argument Classification */
    "CREATE TABLE IF NOT EXISTS call_args("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  call_addr INTEGER NOT NULL,"         /* call 指令地址 */
    "  arg_index INTEGER NOT NULL,"  /* 0=rdi 1=rsi 2=rdx 3=rcx(用户)/r10(syscall) 4=r8 5=r9 */
    "  arg_role TEXT,"                       /* DST_BUFFER/SRC_STRING/SIZE/FD/FMT_STRING/CMD_PATH/FLAGS/UNKNOWN */
    "  val_def_addr INTEGER,"               /* 该参数值最近定义点 */
    "  is_tainted INTEGER DEFAULT 0);"      /* 是否来自外部输入 */
    "CREATE INDEX IF NOT EXISTS idx_ca_call ON call_args(call_addr);"
    "CREATE INDEX IF NOT EXISTS idx_ca_role ON call_args(arg_role, is_tainted);"

    /* Phase 3: Memory Region Classification */
    "CREATE TABLE IF NOT EXISTS memory_regions("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  address INTEGER NOT NULL,"
    "  size INTEGER,"
    "  region_type TEXT NOT NULL,"           /* STACK_FRAME/HEAP_CHUNK/GLOBAL_BSS/GLOBAL_DATA/TLS/MMAP */
    "  owner_func INTEGER,"                 /* 所属函数地址 */
    "  label TEXT);"                         /* 变量名 */
    "CREATE INDEX IF NOT EXISTS idx_mr_addr ON memory_regions(address);"

    /* Phase 3: Taint Propagation Path */
    "CREATE TABLE IF NOT EXISTS taint_propagation("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  src_addr INTEGER NOT NULL,"          /* 污点来源指令 */
    "  taint_id INTEGER NOT NULL,"          /* 污点批次 */
    "  insn_addr INTEGER NOT NULL,"         /* 被污染的指令地址 */
    "  target TEXT NOT NULL,"               /* 被污染目标 */
    "  propagation TEXT);"                  /* DIRECT/REG_COPY/MEM_STORE/ARITHMETIC */
    "CREATE INDEX IF NOT EXISTS idx_tp_taint ON taint_propagation(taint_id);"
    "CREATE INDEX IF NOT EXISTS idx_tp_addr ON taint_propagation(insn_addr);"

    /* Phase 3: Type Hints */
    "CREATE TABLE IF NOT EXISTS type_hints("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  address INTEGER NOT NULL,"
    "  hint_type TEXT NOT NULL,"             /* PTR/INT/SIZE_T/CHAR_BUF/STRUCT */
    "  confidence REAL DEFAULT 0.5,"
    "  evidence TEXT);"
    "CREATE INDEX IF NOT EXISTS idx_th_addr ON type_hints(address);"

    /* ── Phase 4: 反编译支撑表 ─────────────────────────────────── */

    /* 4a. 栈变量: 局部变量与函数参数识别 */
    "CREATE TABLE IF NOT EXISTS stack_vars("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  function_addr INTEGER NOT NULL,"  /* 所属函数 */
    "  offset INTEGER NOT NULL,"         /* 相对 rbp 偏移 (正=参数 负=局部变量) */
    "  size INTEGER NOT NULL,"           /* 变量大小 (字节) */
    "  var_name TEXT,"                   /* 推断名称 var_20 / 用户重命名 */
    "  var_type TEXT,"                   /* 推断类型 int* / char[32] / FILE* */
    "  first_access INTEGER,"            /* 首次访问地址 */
    "  access_count INTEGER DEFAULT 0,"
    "  is_arg INTEGER DEFAULT 0,"        /* 1=函数参数 0=局部变量 */
    "  arg_index INTEGER);"              /* 参数序号 0-based */
    "CREATE INDEX IF NOT EXISTS idx_sv_func ON stack_vars(function_addr);"
    "CREATE INDEX IF NOT EXISTS idx_sv_offset ON stack_vars(function_addr, offset);"

    /* 4b. 类型推断: 操作数→C类型映射 */
    "CREATE TABLE IF NOT EXISTS data_types("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  insn_addr INTEGER NOT NULL,"      /* 产生该推断的指令地址 */
    "  operand_index INTEGER,"           /* 操作数序号 0=dst 1=src1 2=src2 */
    "  c_type TEXT NOT NULL,"            /* int / char* / long / float / struct* */
    "  ptr_depth INTEGER DEFAULT 0,"     /* 指针层数 0=值 1=* 2=** */
    "  element_size INTEGER,"            /* 数组/结构体元素大小 */
    "  confidence REAL DEFAULT 0.5);"    /* 推断置信度 0-1 */
    "CREATE INDEX IF NOT EXISTS idx_dt_insn ON data_types(insn_addr);"

    /* 4c. 控制结构: CFG拓扑→if/while/for/switch */
    "CREATE TABLE IF NOT EXISTS control_structures("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  function_addr INTEGER NOT NULL,"
    "  struct_type TEXT NOT NULL,"       /* if_then / if_else / while / for / switch / do_while */
    "  header_addr INTEGER,"             /* 条件判断 BB 入口 */
    "  body_start INTEGER,"              /* 体入口 */
    "  body_end INTEGER,"                /* 体出口 */
    "  else_start INTEGER,"              /* else体入口 (if_else) */
    "  follow_addr INTEGER,"             /* 结构之后地址 */
    "  condition_text TEXT,"             /* 反编译条件字符串 "var_20 < 10" */
    "  nesting_depth INTEGER DEFAULT 0);"
    "CREATE INDEX IF NOT EXISTS idx_cs_func ON control_structures(function_addr);"

    /* 4d. 循环归纳变量: for(i=0; i<N; i++) 识别 */
    "CREATE TABLE IF NOT EXISTS loop_induction_vars("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  loop_id INTEGER NOT NULL,"        /* → control_structures.id */
    "  var_location TEXT NOT NULL,"       /* rax / [rbp-0x20] / ecx */
    "  initial_value INTEGER,"
    "  step INTEGER,"                    /* 步长 +1 / -1 / +4 */
    "  bound_value INTEGER,"             /* 上界/下界 */
    "  comparison TEXT,"                 /* < / <= / > / >= / == / != */
    "  base_addr INTEGER);"              /* 数组基址 (如果用于数组索引) */
    "CREATE INDEX IF NOT EXISTS idx_liv_loop ON loop_induction_vars(loop_id);"

    /* 4e. 结构体布局: [reg+0x10] [reg+0x18] → struct field */
    "CREATE TABLE IF NOT EXISTS struct_layouts("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  base_reg TEXT NOT NULL,"          /* 基址寄存器/变量 rdi / var_30 */
    "  base_desc TEXT,"                  /* 描述 first_arg / global_ptr */
    "  field_offset INTEGER NOT NULL,"   /* 字段偏移 (字节) */
    "  field_size INTEGER,"              /* 字段大小 (字节) */
    "  field_name TEXT,"                 /* 推断名 field_0x10 / 用户重命名 */
    "  field_type TEXT,"                 /* 推断类型 int* / char[32] */
    "  access_count INTEGER DEFAULT 0,"
    "  first_access INTEGER,"
    "  containing_function INTEGER);"    /* 发现位置 (NULL=跨函数) */
    "CREATE INDEX IF NOT EXISTS idx_sl_base ON struct_layouts(base_reg, field_offset);";

/* 索引统一创建 (数据导入后调用) */
static const char *INDEX_SQL =
    "CREATE INDEX IF NOT EXISTS idx_sym_addr ON symbols(address);"
    "CREATE INDEX IF NOT EXISTS idx_sym_name ON symbols(name);"
    "CREATE INDEX IF NOT EXISTS idx_str_value ON strings(value);"
    "CREATE INDEX IF NOT EXISTS idx_bb_func ON basic_blocks(function_addr);"
    "CREATE INDEX IF NOT EXISTS idx_cfg_from ON cfg_edges(from_addr);"
    "CREATE INDEX IF NOT EXISTS idx_cfg_to   ON cfg_edges(to_addr);"
    "CREATE INDEX IF NOT EXISTS idx_xref_from ON xrefs(from_addr);"
    "CREATE INDEX IF NOT EXISTS idx_xref_to   ON xrefs(to_addr);"
    "CREATE INDEX IF NOT EXISTS idx_reg_rip  ON reg_snapshots(rip);"
    "CREATE INDEX IF NOT EXISTS idx_reg_step ON reg_snapshots(step_num);"
    "CREATE INDEX IF NOT EXISTS idx_vuln_addr ON vuln_candidates(address);"
    "CREATE INDEX IF NOT EXISTS idx_taint_addr ON taint_sources(address);"
    "CREATE INDEX IF NOT EXISTS idx_ir_addr ON ir_stmts(address);"
    "CREATE INDEX IF NOT EXISTS idx_ir_dst ON ir_stmts(dst);"
    "CREATE INDEX IF NOT EXISTS idx_ir_type ON ir_stmts(op_type);"
    "CREATE INDEX IF NOT EXISTS idx_ir_def ON ir_stmts(def_insn_addr);"
    /* Phase 4 新表索引 */
    "CREATE INDEX IF NOT EXISTS idx_ctrl_func ON control_structures(function_addr);"
    "CREATE INDEX IF NOT EXISTS idx_dt_conf ON data_types(insn_addr, confidence);"
    "CREATE INDEX IF NOT EXISTS idx_liv_varloc ON loop_induction_vars(loop_id);"
    "CREATE INDEX IF NOT EXISTS idx_struct_base ON struct_layouts(base_reg);"

    /* Phase 5: Crash Reports (Fuzz auto-triage) */
    "CREATE TABLE IF NOT EXISTS crash_reports("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER DEFAULT (strftime('%s','now')),"
    "  fault_addr INTEGER,"
    "  signal INTEGER,"
    "  rip_snapshot INTEGER,"
    "  input_blob BLOB,"
    "  input_size INTEGER,"
    "  crash_type TEXT,"
    "  exploitability TEXT);"
    "CREATE INDEX IF NOT EXISTS idx_cr_addr ON crash_reports(fault_addr);";

/* ── 公开: 生命周期 ──────────────────────────────────────────────── */

AnalysisDB *db_open(const char *path) {
    AnalysisDB *db = calloc(1, sizeof(AnalysisDB));
    if (!db) return NULL;

    const char *dp = path ? path : ":memory:";
    if (sqlite3_open(dp, &db->conn) != SQLITE_OK) {
        set_error(db, "open: %s", sqlite3_errmsg(db->conn));
        free(db); return NULL;
    }

    if (path) {
        sqlite3_exec(db->conn, "PRAGMA journal_mode=OFF",  NULL,NULL,NULL);
        sqlite3_exec(db->conn, "PRAGMA synchronous=OFF",   NULL,NULL,NULL);
        sqlite3_exec(db->conn, "PRAGMA mmap_size=268435456",NULL,NULL,NULL);
        sqlite3_exec(db->conn, "PRAGMA cache_size=-32000", NULL,NULL,NULL);
    }

    /* Schema 版本检查: 不匹配则自动重建 */
    sqlite3_exec(db->conn,
        "CREATE TABLE IF NOT EXISTS _meta(key TEXT PRIMARY KEY, value TEXT)", NULL,NULL,NULL);
    sqlite3_stmt *vs = NULL;
    int need_rebuild = 0;
    sqlite3_prepare_v2(db->conn, "SELECT value FROM _meta WHERE key='schema_version'",
                       -1, &vs, NULL);
    if (vs && sqlite3_step(vs) == SQLITE_ROW) {
        int ver = atoi((const char *)sqlite3_column_text(vs, 0));
        if (ver != DB_SCHEMA_VERSION) need_rebuild = 1;
    } else {
        need_rebuild = 1; /* 没有版本号 = 旧DB */
    }
    if (vs) sqlite3_finalize(vs);

    if (need_rebuild) {
        /* 删除所有旧表, 重建 */
        sqlite3_exec(db->conn,
            "DROP TABLE IF EXISTS sections;"
            "DROP TABLE IF EXISTS segments;"
            "DROP TABLE IF EXISTS symbols;"
            "DROP TABLE IF EXISTS instructions;"
            "DROP TABLE IF EXISTS strings;"
            "DROP TABLE IF EXISTS functions;"
            "DROP TABLE IF EXISTS basic_blocks;"
            "DROP TABLE IF EXISTS cfg_edges;"
            "DROP TABLE IF EXISTS xrefs;"
            "DROP TABLE IF EXISTS reg_snapshots;"
            "DROP TABLE IF EXISTS mem_snapshots;"
            "DROP TABLE IF EXISTS vuln_candidates;"
            "DROP TABLE IF EXISTS taint_sources;"
            "DROP TABLE IF EXISTS heap_sessions;"
            "DROP TABLE IF EXISTS heap_chunks;"
            "DROP TABLE IF EXISTS heap_links;"
            "DROP TABLE IF EXISTS heap_anomalies;"
            "DROP TABLE IF EXISTS ir_stmts;"
            "DROP TABLE IF EXISTS trace_sessions;"
            "DROP TABLE IF EXISTS trace_blocks;"
            "DROP TABLE IF EXISTS heap_events;"
            "DROP TABLE IF EXISTS value_defs;"
            "DROP TABLE IF EXISTS call_args;"
            "DROP TABLE IF EXISTS memory_regions;"
            "DROP TABLE IF EXISTS taint_propagation;"
            "DROP TABLE IF EXISTS type_hints;"
            "DROP TABLE IF EXISTS stack_vars;"
            "DROP TABLE IF EXISTS data_types;"
            "DROP TABLE IF EXISTS crash_reports;"
            "DROP TABLE IF EXISTS control_structures;"
            "DROP TABLE IF EXISTS loop_induction_vars;"
            "DROP TABLE IF EXISTS struct_layouts;",
            NULL, NULL, NULL);
        /* 重新写入版本号 */
        char ver_sql[64];
        snprintf(ver_sql, sizeof(ver_sql),
            "INSERT OR REPLACE INTO _meta VALUES('schema_version','%d')",
            DB_SCHEMA_VERSION);
        sqlite3_exec(db->conn, ver_sql, NULL, NULL, NULL);
    }

    if (exec_sql(db, TABLE_SQL) != 0) { db_close(db); return NULL; }
    return db;
}

/* 索引批量创建 (数据导入后调用, 毫秒级) */
void db_build_indexes(AnalysisDB *db) {
    if (!db || !db->conn) return;
    exec_sql(db, INDEX_SQL);
}

void db_close(AnalysisDB *db) {
    if (!db) return;
    if (db->conn) sqlite3_close(db->conn);
    free(db);
}

void *db_conn(AnalysisDB *db) { return db ? db->conn : NULL; }

/* ── 公开: 全量导入 ──────────────────────────────────────────────── */

static const char *edge_type_of_mnemonic(const char *m) {
    if (!m) return NULL;
    if (!strcmp(m, "jmp"))  return "jump";
    if (m[0] == 'j' && strcmp(m, "jmp") && strcmp(m, "jrcxz"))
        return "conditional";
    if (!strcmp(m, "call")) return "call";
    if (!strcmp(m, "ret") || !strcmp(m, "retn")) return "ret";
    if (!strcmp(m, "loop") || !strcmp(m, "loope") || !strcmp(m, "loopne"))
        return "conditional";
    return NULL;
}

static uint64_t extract_target_from_insn(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;
    cs_detail *d = insn->detail;
    for (int i = 0; i < d->x86.op_count; i++) {
        if (d->x86.operands[i].type == X86_OP_IMM)
            return (uint64_t)d->x86.operands[i].imm;
    }
    return 0;
}

int db_import_all(AnalysisDB *db, Elf64_Ctx *ctx) {
    if (!db || !ctx) return -1;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)ctx->map;
    int phnum = (int)eh->e_phnum, shnum = (int)eh->e_shnum;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(ctx->map + eh->e_phoff);

    sqlite3 *c = db->conn;

    /* ── 1. sections ── */
    {
        sqlite3_exec(c, "BEGIN", NULL,NULL,NULL);
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO sections(shdr_idx,name,addr,offset,size,type,flags)"
            " VALUES(?,?,?,?,?,?,?)", -1, &st, NULL);
        for (int i = 0; i < shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            if (!sh) continue;
            const char *n = elf_section_name(ctx, i);
            sqlite3_reset(st);
            sqlite3_bind_int(st,   1, i);
            sqlite3_bind_text(st,  2, n ? n : "", -1, SQLITE_STATIC);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)sh->sh_addr);
            sqlite3_bind_int64(st, 4, (sqlite3_int64)sh->sh_offset);
            sqlite3_bind_int64(st, 5, (sqlite3_int64)sh->sh_size);
            sqlite3_bind_int(st,   6, (int)sh->sh_type);
            sqlite3_bind_int64(st, 7, (sqlite3_int64)sh->sh_flags);
            sqlite3_step(st);
        }
        sqlite3_finalize(st);
        sqlite3_exec(c, "COMMIT", NULL,NULL,NULL);
    }

    /* ── 2. segments ── */
    {
        sqlite3_exec(c, "BEGIN", NULL,NULL,NULL);
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO segments(vaddr,memsz,type,flags)"
            " VALUES(?,?,?,?)", -1, &st, NULL);
        for (int i = 0; i < phnum; i++) {
            const char *t = elf_p_type_str(phdrs[i].p_type);
            char fb[8]; elf_p_flags_str(phdrs[i].p_flags, fb, sizeof(fb));
            sqlite3_reset(st);
            sqlite3_bind_int64(st, 1, (sqlite3_int64)phdrs[i].p_vaddr);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)phdrs[i].p_memsz);
            sqlite3_bind_text(st,  3, t ? t : "?", -1, SQLITE_STATIC);
            sqlite3_bind_text(st,  4, fb, -1, SQLITE_STATIC);
            sqlite3_step(st);
        }
        sqlite3_finalize(st);
        sqlite3_exec(c, "COMMIT", NULL,NULL,NULL);
    }

    /* ── 3. symbols (不跳过 st_value==0 的导入函数!) ── */
    {
        sqlite3_exec(c, "BEGIN", NULL,NULL,NULL);
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO symbols(address,name,size,type,bind,table_name)"
            " VALUES(?,?,?,?,?,?)", -1, &st, NULL);
        for (int pass = 0; pass < 2; pass++) {
            Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
            const char *tname = (pass == 0) ? ".symtab" : ".dynsym";
            for (int si = 0; si < shnum; si++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, si);
                if (!sh || sh->sh_type != want || sh->sh_size == 0) continue;
                Elf64_Shdr *stsh = elf_get_shdr(ctx, sh->sh_link);
                if (!stsh) continue;
                Elf64_Sym *raw = (Elf64_Sym *)(ctx->map + sh->sh_offset);
                int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
                for (int j = 0; j < nsym; j++) {
                    /* 跳过空名称 */
                    if (raw[j].st_name == 0) continue;
                    const char *sn = elf_strtab_get(ctx, stsh->sh_offset, raw[j].st_name);
                    if (!sn || !sn[0]) continue;
                    /* 去掉 @@ 版本后缀 */
                    char name[256]; snprintf(name, sizeof(name), "%s", sn);
                    char *at = strchr(name, '@');
                    if (at) *at = '\0';

                    sqlite3_reset(st);
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)raw[j].st_value);
                    sqlite3_bind_text(st,  2, name, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(st, 3, (sqlite3_int64)raw[j].st_size);
                    sqlite3_bind_text(st,  4, elf_st_type_str(raw[j].st_info), -1, SQLITE_STATIC);
                    sqlite3_bind_text(st,  5, elf_st_bind_str(raw[j].st_info), -1, SQLITE_STATIC);
                    sqlite3_bind_text(st,  6, tname, -1, SQLITE_STATIC);
                    sqlite3_step(st);
                }
            }
        }
        sqlite3_finalize(st);
        sqlite3_exec(c, "COMMIT", NULL,NULL,NULL);
    }

    /* ── 4. strings ── */
    {
        sqlite3_exec(c, "BEGIN", NULL,NULL,NULL);
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO strings(address,value,length,section)"
            " VALUES(?,?,?,?)", -1, &st, NULL);
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_size == 0) continue;
            if (sh->sh_flags & SHF_EXECINSTR) continue;
            const char *sn = elf_section_name(ctx, si);
            const uint8_t *d = ctx->map + sh->sh_offset;
            size_t sz = sh->sh_size;
            for (size_t i = 0; i < sz; ) {
                while (i < sz && !isprint(d[i]) && d[i]!='\t') i++;
                if (i >= sz) break;
                size_t start = i;
                while (i < sz && (isprint(d[i]) || d[i]=='\t')) i++;
                size_t len = i - start;
                if (len >= 4) {  /* 最少 4 个字符 */
                    char val[256]; size_t cp = len < 255 ? len : 255;
                    memcpy(val, d + start, cp); val[cp] = '\0';
                    uint64_t addr = sh->sh_addr + (uint64_t)start;
                    sqlite3_reset(st);
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
                    sqlite3_bind_text(st,  2, val, -1, SQLITE_STATIC);
                    sqlite3_bind_int(st,   3, (int)len);
                    sqlite3_bind_text(st,  4, sn ? sn : "", -1, SQLITE_STATIC);
                    sqlite3_step(st);
                }
            }
        }
        sqlite3_finalize(st);
        sqlite3_exec(c, "COMMIT", NULL,NULL,NULL);
    }

    /* ── 5,6,7,8,9: instructions + functions + basic_blocks + cfg_edges + xrefs ── */
    disasm_ctx *dctx = disasm_open();
    if (!dctx) { set_error(db, "Capstone failed"); return -1; }

    sqlite3_exec(c, "BEGIN", NULL,NULL,NULL);

    /* 预编译语句 */
    sqlite3_stmt *s_insn=NULL, *s_bb=NULL, *s_cfg=NULL, *s_xref=NULL, *s_ir=NULL;
    sqlite3_stmt *s_vdef=NULL, *s_carg=NULL;
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO instructions(address,bytes,mnemonic,op_str,size,section)"
        " VALUES(?,?,?,?,?,?)", -1, &s_insn, NULL);
    sqlite3_prepare_v2(c,
        "INSERT INTO ir_stmts(address,op_type,dst,src,mem_base,mem_disp,imm_value)"
        " VALUES(?,?,?,?,?,?,?)", -1, &s_ir, NULL);
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO basic_blocks(start_addr,end_addr,function_addr,insn_count)"
        " VALUES(?,?,?,?)", -1, &s_bb, NULL);
    sqlite3_prepare_v2(c,
        "INSERT OR IGNORE INTO cfg_edges(from_addr,to_addr,edge_type)"
        " VALUES(?,?,?)", -1, &s_cfg, NULL);
    sqlite3_prepare_v2(c,
        "INSERT INTO xrefs(from_addr,to_addr,ref_type,detail)"
        " VALUES(?,?,?,?)", -1, &s_xref, NULL);
    sqlite3_prepare_v2(c,
        "INSERT INTO value_defs(def_addr,def_type,target,source_desc,related_addr)"
        " VALUES(?,?,?,?,?)", -1, &s_vdef, NULL);
    sqlite3_prepare_v2(c,
        "INSERT INTO call_args(call_addr,arg_index,arg_role,val_def_addr,is_tainted)"
        " VALUES(?,?,?,?,0)", -1, &s_carg, NULL);

    /* 临时存储: 函数和 BB 信息 (堆分配, 避免 ~2.6MB 栈压力) */
    #define MAX_TEMP 16384
    typedef struct { uint64_t start, end; int insn_cnt; } BbTemp;
    typedef struct { uint64_t start, end; char name[128]; int bb_cnt; } FuncTemp;
    BbTemp  *bbs   = calloc(MAX_TEMP, sizeof(BbTemp));
    FuncTemp *funcs = calloc(MAX_TEMP, sizeof(FuncTemp));
    if (!bbs || !funcs) { free(bbs); free(funcs); goto import_done; }
    int nbb = 0, nfunc = 0;
    uint64_t cur_func_start = 0, cur_func_end = 0;
    char     cur_func_name[128] = "";
    uint64_t cur_bb_start = 0, cur_bb_end = 0;
    int      cur_bb_insns = 0;

    int total_insn = 0;
    uint64_t prev_addr = 0;
    const char *prev_mnemonic = NULL;

    for (int si = 0; si < shnum; si++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, si);
        if (!sh || sh->sh_size == 0 || !(sh->sh_flags & SHF_EXECINSTR)) continue;
        const char *sn = elf_section_name(ctx, si);
        /* 跳过 PLT 节 (步骤10已单独处理, 反汇编无价值) */
        if (sn && (!strcmp(sn,".plt")||!strcmp(sn,".plt.sec")||!strcmp(sn,".plt.got")))
            continue;
        const uint8_t *code = ctx->map + sh->sh_offset;
        size_t sz = sh->sh_size;
        uint64_t addr = sh->sh_addr;

        /* 查找节首地址对应的符号名 (作为第一个函数名) */
        const char *entry_name = NULL;
        for (int pass = 0; pass < 2 && !entry_name; pass++) {
            Elf64_Word w = (pass==0)?SHT_SYMTAB:SHT_DYNSYM;
            for (int ii=0;ii<shnum&&!entry_name;ii++){
                Elf64_Shdr *ss=elf_get_shdr(ctx,ii);
                if(!ss||ss->sh_type!=w||ss->sh_size==0)continue;
                Elf64_Shdr *st=elf_get_shdr(ctx,ss->sh_link);
                if(!st)continue;
                Elf64_Sym *rs=(Elf64_Sym*)(ctx->map+ss->sh_offset);
                int ns=(int)(ss->sh_size/sizeof(Elf64_Sym));
                for(int jj=0;jj<ns;jj++){
                    if(rs[jj].st_value==addr&&ELF64_ST_TYPE(rs[jj].st_info)==STT_FUNC){
                        entry_name=elf_strtab_get(ctx,st->sh_offset,rs[jj].st_name);
                        break;
                    }
                }
            }
        }

        /* 开始新函数 */
        if (nfunc < MAX_TEMP) {
            FuncTemp *f = &funcs[nfunc++];
            f->start = addr; f->end = addr; f->bb_cnt = 0;
            snprintf(f->name, sizeof(f->name), "%s",
                     entry_name ? entry_name : "sub_unknown");
        }
        cur_func_start = addr;
        snprintf(cur_func_name, sizeof(cur_func_name), "%s",
                 entry_name ? entry_name : "sub_unknown");

        /* 开始新 BB */
        cur_bb_start = addr; cur_bb_insns = 0;

        while (sz > 0 && disasm_next(dctx, &code, &sz, &addr)) {
            cs_insn *insn = disasm_insn(dctx);
            if (!insn) continue;

            /* ── INSERT instruction ── */
            sqlite3_reset(s_insn);
            sqlite3_bind_int64(s_insn, 1, (sqlite3_int64)insn->address);
            sqlite3_bind_blob(s_insn,  2, insn->bytes, (int)insn->size, SQLITE_STATIC);
            sqlite3_bind_text(s_insn,  3, insn->mnemonic, -1, SQLITE_STATIC);
            sqlite3_bind_text(s_insn,  4, insn->op_str, -1, SQLITE_STATIC);
            sqlite3_bind_int(s_insn,   5, (int)insn->size);
            sqlite3_bind_text(s_insn,  6, sn ? sn : "", -1, SQLITE_STATIC);
            sqlite3_step(s_insn);
            total_insn++;

            /* ── IR 语义提取 (Capstone detail → ir_stmts) ── */
            if (s_ir && insn->detail) {
                cs_detail *d = insn->detail;
                /* reg_read */
                for (int ri = 0; ri < d->regs_read_count && ri < 16; ri++) {
                    sqlite3_reset(s_ir);
                    sqlite3_bind_int64(s_ir, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_text(s_ir,  2, "reg_read", -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_ir,  3, cs_reg_name(disasm_handle(dctx), d->regs_read[ri]), -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_ir,  4, insn->mnemonic, -1, SQLITE_STATIC);
                    sqlite3_bind_null(s_ir,  5); sqlite3_bind_int(s_ir, 6, 0);
                    sqlite3_bind_int(s_ir,  7, 0);
                    sqlite3_step(s_ir);
                }
                /* reg_write */
                for (int wi = 0; wi < d->regs_write_count && wi < 16; wi++) {
                    sqlite3_reset(s_ir);
                    sqlite3_bind_int64(s_ir, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_text(s_ir,  2, "reg_write", -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_ir,  3, cs_reg_name(disasm_handle(dctx), d->regs_write[wi]), -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_ir,  4, insn->mnemonic, -1, SQLITE_STATIC);
                    sqlite3_bind_null(s_ir,  5); sqlite3_bind_int(s_ir, 6, 0);
                    sqlite3_bind_int(s_ir,  7, 0);
                    sqlite3_step(s_ir);
                }
                /* memory + immediate operands */
                for (int oi = 0; oi < d->x86.op_count && oi < 6; oi++) {
                    cs_x86_op *op = &d->x86.operands[oi];
                    if (op->type == X86_OP_MEM) {
                        const char *base = cs_reg_name(disasm_handle(dctx), op->mem.base);
                        const char *idx  = cs_reg_name(disasm_handle(dctx), op->mem.index);
                        char src_buf[64] = "";
                        if (idx && op->mem.index != X86_REG_INVALID)
                            snprintf(src_buf,sizeof(src_buf),"%s+%s*%d", base?base:"?", idx, op->mem.scale);
                        else
                            snprintf(src_buf,sizeof(src_buf),"%s", base?base:"?");
                        sqlite3_reset(s_ir);
                        sqlite3_bind_int64(s_ir, 1, (sqlite3_int64)insn->address);
                        sqlite3_bind_text(s_ir,  2, "mem_access", -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_ir,  3, NULL, -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_ir,  4, src_buf, -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_ir,  5, base, -1, SQLITE_STATIC);
                        sqlite3_bind_int64(s_ir,  6, (sqlite3_int64)op->mem.disp);
                        sqlite3_bind_int(s_ir,  7, 0);
                        sqlite3_step(s_ir);
                    } else if (op->type == X86_OP_IMM) {
                        sqlite3_reset(s_ir);
                        sqlite3_bind_int64(s_ir, 1, (sqlite3_int64)insn->address);
                        sqlite3_bind_text(s_ir,  2, "immediate", -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_ir,  3, NULL, -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_ir,  4, insn->mnemonic, -1, SQLITE_STATIC);
                        sqlite3_bind_null(s_ir,  5);
                        sqlite3_bind_int(s_ir,  6, 0);
                        sqlite3_bind_int64(s_ir,  7, (sqlite3_int64)op->imm);
                        sqlite3_step(s_ir);
                    }
                }
            }

            /* ── Phase 3: value_defs 分类 ── */
            if (s_vdef && insn->detail) {
                cs_detail *d = insn->detail;
                /* 立即数 → IMMEDIATE */
                for (int oi = 0; oi < d->x86.op_count && oi < 3; oi++) {
                    if (d->x86.operands[oi].type == X86_OP_IMM) {
                        const char *rn = NULL;
                        if (d->x86.op_count >= 1 && d->x86.operands[0].type == X86_OP_REG)
                            rn = cs_reg_name(disasm_handle(dctx), d->x86.operands[0].reg);
                        sqlite3_reset(s_vdef);
                        sqlite3_bind_int64(s_vdef, 1, (sqlite3_int64)insn->address);
                        sqlite3_bind_text(s_vdef, 2, "IMMEDIATE", -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_vdef, 3, rn, -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_vdef, 4, insn->mnemonic, -1, SQLITE_STATIC);
                        sqlite3_bind_int64(s_vdef, 5, (sqlite3_int64)d->x86.operands[oi].imm);
                        sqlite3_step(s_vdef);
                    }
                }
                /* call 指令 → CALL_RET 或 SOURCE_TAINTED 或 call_args */
                if (insn->id == X86_INS_CALL) {
                    /* 记录 rax 来自函数返回 */
                    sqlite3_reset(s_vdef);
                    sqlite3_bind_int64(s_vdef, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_text(s_vdef, 2, "CALL_RET", -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_vdef, 3, "rax", -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_vdef, 4, insn->op_str, -1, SQLITE_STATIC);
                    sqlite3_bind_int64(s_vdef, 5, 0);
                    sqlite3_step(s_vdef);

                    /* 分类 call 参数角色 */
                    if (s_carg) {
                        for (int ai = 0; ai < 6; ai++) {
                            const char *role = "UNKNOWN";
                            /* 基于函数名启发式分类 */
                            if (strstr(insn->op_str, "strcpy") || strstr(insn->op_str, "strcat"))
                                role = (ai == 0) ? "DST_BUFFER" : (ai == 1) ? "SRC_STRING" : "UNKNOWN";
                            else if (strstr(insn->op_str, "memcpy") || strstr(insn->op_str, "memmove"))
                                role = (ai == 0) ? "DST_BUFFER" : (ai == 1) ? "SRC_BUFFER" : (ai == 2) ? "SIZE" : "UNKNOWN";
                            else if (strstr(insn->op_str, "read") || strstr(insn->op_str, "recv"))
                                role = (ai == 0) ? "FD" : (ai == 1) ? "DST_BUFFER" : (ai == 2) ? "SIZE" : "UNKNOWN";
                            else if (strstr(insn->op_str, "malloc") || strstr(insn->op_str, "calloc"))
                                role = (ai == 0) ? "SIZE" : "UNKNOWN";
                            else if (strstr(insn->op_str, "printf") || strstr(insn->op_str, "sprintf"))
                                role = (ai == 0) ? "FMT_STRING" : "UNKNOWN";
                            else if (strstr(insn->op_str, "system") || strstr(insn->op_str, "popen"))
                                role = (ai == 0) ? "CMD_PATH" : "UNKNOWN";

                            if (ai < 6 && strcmp(role, "UNKNOWN")) {
                                sqlite3_reset(s_carg);
                                sqlite3_bind_int64(s_carg, 1, (sqlite3_int64)insn->address);
                                sqlite3_bind_int(s_carg,   2, ai);
                                sqlite3_bind_text(s_carg,  3, role, -1, SQLITE_STATIC);
                                sqlite3_bind_int64(s_carg, 4, (sqlite3_int64)insn->address);
                                sqlite3_step(s_carg);
                            }
                        }
                    }
                }
                /* reg_write → REG_COPY (如果是 mov 寄存器到寄存器) */
                if (insn->id == X86_INS_MOV && d->x86.op_count >= 2 &&
                    d->x86.operands[0].type == X86_OP_REG &&
                    d->x86.operands[1].type == X86_OP_REG) {
                    sqlite3_reset(s_vdef);
                    sqlite3_bind_int64(s_vdef, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_text(s_vdef, 2, "REG_COPY", -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_vdef, 3,
                        cs_reg_name(disasm_handle(dctx), d->x86.operands[0].reg), -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_vdef, 4,
                        cs_reg_name(disasm_handle(dctx), d->x86.operands[1].reg), -1, SQLITE_STATIC);
                    sqlite3_bind_int64(s_vdef, 5, 0);
                    sqlite3_step(s_vdef);
                }
                /* mem_access with rbp/rsp → MEM_LOAD_STACK */
                for (int oi = 0; oi < d->x86.op_count && oi < 3; oi++) {
                    if (d->x86.operands[oi].type == X86_OP_MEM &&
                        (d->x86.operands[oi].mem.base == X86_REG_RBP ||
                         d->x86.operands[oi].mem.base == X86_REG_RSP)) {
                        sqlite3_reset(s_vdef);
                        sqlite3_bind_int64(s_vdef, 1, (sqlite3_int64)insn->address);
                        sqlite3_bind_text(s_vdef, 2, "MEM_LOAD_STACK", -1, SQLITE_STATIC);
                        char desc[64]; snprintf(desc, sizeof(desc), "%s%+ld",
                            d->x86.operands[oi].mem.base == X86_REG_RBP ? "rbp" : "rsp",
                            (long)d->x86.operands[oi].mem.disp);
                        sqlite3_bind_text(s_vdef, 3, desc, -1, SQLITE_STATIC);
                        sqlite3_bind_text(s_vdef, 4, insn->mnemonic, -1, SQLITE_STATIC);
                        sqlite3_bind_int64(s_vdef, 5, 0);
                        sqlite3_step(s_vdef);
                    }
                }
            }

            /* ── XREF: JMP/CALL targets ── */
            const char *etype = edge_type_of_mnemonic(insn->mnemonic);
            if (etype) {
                uint64_t tgt = extract_target_from_insn(insn);
                if (tgt > 0 && tgt < 0x7FFFFFFFFFFFULL) {
                    sqlite3_reset(s_xref);
                    sqlite3_bind_int64(s_xref, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_int64(s_xref, 2, (sqlite3_int64)tgt);
                    sqlite3_bind_text(s_xref, 3, etype, -1, SQLITE_STATIC);
                    sqlite3_bind_text(s_xref, 4, insn->op_str, -1, SQLITE_STATIC);
                    sqlite3_step(s_xref);

                    /* CFG edge */
                    sqlite3_reset(s_cfg);
                    sqlite3_bind_int64(s_cfg, 1, (sqlite3_int64)insn->address);
                    sqlite3_bind_int64(s_cfg, 2, (sqlite3_int64)tgt);
                    sqlite3_bind_text(s_cfg,  3, etype, -1, SQLITE_STATIC);
                    sqlite3_step(s_cfg);
                }
            }

            /* ── XREF: 只存有价值的引用 (JMP/CALL — 上面已处理, DATA — 只存大立即数) ── */
            if (insn->detail) {
                cs_detail *d = insn->detail;
                /* 跳过 REG_R/REG_W (capstone内部ID, 无分析价值, 且数量巨大拖慢导入) */
                for (int i = 0; i < d->x86.op_count; i++) {
                    cs_x86_op *op = &d->x86.operands[i];
                    if (op->type == X86_OP_IMM) {
                        uint64_t imm = (uint64_t)op->imm;
                        if (imm > 0x1000 && imm < 0x7FFFFFFFFFFFULL) {
                            sqlite3_reset(s_xref);
                            sqlite3_bind_int64(s_xref, 1, (sqlite3_int64)insn->address);
                            sqlite3_bind_int64(s_xref, 2, (sqlite3_int64)imm);
                            sqlite3_bind_text(s_xref, 3, "DATA", -1, SQLITE_STATIC);
                            sqlite3_bind_text(s_xref, 4, insn->op_str, -1, SQLITE_STATIC);
                            sqlite3_step(s_xref);
                        }
                    }
                }
            }

            /* ── CFG: fallthrough ── */
            if (prev_addr && prev_mnemonic) {
                const char *pet = edge_type_of_mnemonic(prev_mnemonic);
                if (!pet || !strcmp(pet, "conditional")) {
                    sqlite3_reset(s_cfg);
                    sqlite3_bind_int64(s_cfg, 1, (sqlite3_int64)prev_addr);
                    sqlite3_bind_int64(s_cfg, 2, (sqlite3_int64)insn->address);
                    sqlite3_bind_text(s_cfg,  3, "fallthrough", -1, SQLITE_STATIC);
                    sqlite3_step(s_cfg);
                }
            }

            /* ── BB 边界检测 ── */
            int is_bb_boundary = 0;
            if (etype && (strcmp(etype, "ret") != 0)) is_bb_boundary = 1;
            if (!strcmp(insn->mnemonic, "ret") || !strcmp(insn->mnemonic, "retn"))
                is_bb_boundary = 1;

            cur_bb_end = insn->address + insn->size;
            cur_bb_insns++;

            if (is_bb_boundary && cur_bb_insns > 0 && nbb < MAX_TEMP) {
                BbTemp *bb = &bbs[nbb++];
                bb->start = cur_bb_start;
                bb->end   = cur_bb_end;
                bb->insn_cnt = cur_bb_insns;
                /* 下一个 BB */
                cur_bb_start = insn->address + insn->size;
                cur_bb_insns = 0;
            }

            /* ── 函数边界检测 (遇到新符号表条目) ── */
            const char *sym_here = NULL;
            for (int pass = 0; pass < 2 && !sym_here; pass++) {
                Elf64_Word w = (pass==0)?SHT_SYMTAB:SHT_DYNSYM;
                for (int ii=0;ii<shnum&&!sym_here;ii++){
                    Elf64_Shdr *ss=elf_get_shdr(ctx,ii);
                    if(!ss||ss->sh_type!=w||ss->sh_size==0)continue;
                    Elf64_Shdr *st=elf_get_shdr(ctx,ss->sh_link);
                    if(!st)continue;
                    Elf64_Sym *rs=(Elf64_Sym*)(ctx->map+ss->sh_offset);
                    int ns=(int)(ss->sh_size/sizeof(Elf64_Sym));
                    for(int jj=0;jj<ns;jj++){
                        if(rs[jj].st_value==(insn->address+insn->size)&&
                           ELF64_ST_TYPE(rs[jj].st_info)==STT_FUNC){
                            sym_here=elf_strtab_get(ctx,st->sh_offset,rs[jj].st_name);
                            break;
                        }
                    }
                }
            }
            if (sym_here && nfunc < MAX_TEMP) {
                /* 结束当前函数 */
                funcs[nfunc-1].end = insn->address + insn->size;
                /* 开始新函数 */
                FuncTemp *f = &funcs[nfunc++];
                f->start = insn->address + insn->size;
                f->end   = insn->address + insn->size;
                f->bb_cnt = 0;
                snprintf(f->name, sizeof(f->name), "%s", sym_here ? sym_here : "sub_unknown");
            }

            prev_addr     = insn->address;
            prev_mnemonic = insn->mnemonic;
        }

        /* 结束最后一个 BB 和函数 */
        if (cur_bb_insns > 0 && nbb < MAX_TEMP) {
            BbTemp *bb = &bbs[nbb++];
            bb->start = cur_bb_start; bb->end = cur_bb_end;
            bb->insn_cnt = cur_bb_insns;
        }
        if (nfunc > 0) funcs[nfunc-1].end = prev_addr + (uint64_t)(prev_mnemonic ? 4 : 0);
    }

    /* ── 写 functions 表 ── */
    {
        sqlite3_stmt *sf = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO functions(start_addr,end_addr,name,bb_count)"
            " VALUES(?,?,?,?)", -1, &sf, NULL);
        for (int i = 0; i < nfunc; i++) {
            if (funcs[i].end <= funcs[i].start) funcs[i].end = funcs[i].start + 1;
            /* 计算此函数的 BB 数 */
            int bcnt = 0;
            for (int j = 0; j < nbb; j++)
                if (bbs[j].start >= funcs[i].start && bbs[j].start < funcs[i].end)
                    bcnt++;
            funcs[i].bb_cnt = bcnt;
            sqlite3_reset(sf);
            sqlite3_bind_int64(sf, 1, (sqlite3_int64)funcs[i].start);
            sqlite3_bind_int64(sf, 2, (sqlite3_int64)funcs[i].end);
            sqlite3_bind_text(sf,  3, funcs[i].name, -1, SQLITE_STATIC);
            sqlite3_bind_int(sf,   4, funcs[i].bb_cnt);
            sqlite3_step(sf);
        }
        sqlite3_finalize(sf);
    }

    /* ── 写 basic_blocks 表 + BB→function 关联 ── */
    for (int i = 0; i < nbb; i++) {
        uint64_t fa = 0;
        for (int j = 0; j < nfunc; j++)
            if (bbs[i].start >= funcs[j].start && bbs[i].start < funcs[j].end)
                { fa = funcs[j].start; break; }
        sqlite3_reset(s_bb);
        sqlite3_bind_int64(s_bb, 1, (sqlite3_int64)bbs[i].start);
        sqlite3_bind_int64(s_bb, 2, (sqlite3_int64)bbs[i].end);
        sqlite3_bind_int64(s_bb, 3, (sqlite3_int64)fa);
        sqlite3_bind_int(s_bb,   4, bbs[i].insn_cnt);
        sqlite3_step(s_bb);
    }

    /* ── 清理 ── */
    sqlite3_finalize(s_insn);
    sqlite3_finalize(s_bb);
    sqlite3_finalize(s_cfg);
    sqlite3_finalize(s_xref);
    if (s_ir)   sqlite3_finalize(s_ir);
    if (s_vdef) sqlite3_finalize(s_vdef);
    if (s_carg) sqlite3_finalize(s_carg);
    sqlite3_exec(c, "COMMIT", NULL,NULL,NULL);
    disasm_close(dctx);

    /* ── 10: PLT stub → 符号名解析 (两种策略: 字节扫描 → 回退到大小计算) ── */
    {
        /* 收集所有 .rela.plt 条目: GOT地址 → 符号名 */
        typedef struct { uint64_t got; char name[128]; } plt_map_t;
        plt_map_t *pmap = NULL; int npmap = 0;
        for (int si = 0; si < shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || sh->sh_type != SHT_RELA || sh->sh_size == 0) continue;
            const char *sn = elf_section_name(ctx, si);
            if (!sn || !strstr(sn, ".rela.plt")) continue;
            Elf64_Shdr *ds = elf_get_shdr(ctx, sh->sh_link);
            if (!ds || ds->sh_type != SHT_DYNSYM) continue;
            Elf64_Shdr *dst = elf_get_shdr(ctx, ds->sh_link);
            if (!dst) continue;
            Elf64_Rela *rela = (Elf64_Rela *)(ctx->map + sh->sh_offset);
            Elf64_Sym  *syms = (Elf64_Sym *)(ctx->map + ds->sh_offset);
            int nr = (int)(sh->sh_size / sizeof(Elf64_Rela));
            free(pmap);  /* 释放前一迭代的分配 (多个 .rela.plt 不常见但安全) */
            pmap = malloc((size_t)nr * sizeof(plt_map_t));
            if (!pmap) continue;
            for (int ri = 0; ri < nr; ri++) {
                uint32_t sym_idx = (uint32_t)(rela[ri].r_info >> 32);
                if (sym_idx >= ds->sh_size / sizeof(Elf64_Sym)) continue;
                const char *raw = elf_strtab_get(ctx, dst->sh_offset,
                                                  syms[sym_idx].st_name);
                if (!raw || !raw[0]) continue;
                pmap[npmap].got = rela[ri].r_offset;
                snprintf(pmap[npmap].name, sizeof(pmap[npmap].name), "%s", raw);
                { char *at = strchr(pmap[npmap].name, '@'); if(at)*at='\0'; }
                npmap++;
            }
            break;
        }
        if (!pmap) goto skip_plt;

        /* 扫描所有 PLT 节, 找 jmp [GOT] (ff 25 xx xx xx xx) → 匹配 GOT → 写入 PLT地址→符号 */
        sqlite3_stmt *ps = NULL;
        sqlite3_prepare_v2(c,
            "INSERT OR IGNORE INTO symbols(address,name,size,type,bind,table_name)"
            " VALUES(?,?,0,'FUNC','GLOBAL','.plt')", -1, &ps, NULL);

        for (int si = 0; si < shnum && ps; si++) {
            Elf64_Shdr *sh = elf_get_shdr(ctx, si);
            if (!sh || !(sh->sh_flags & SHF_EXECINSTR) || sh->sh_size < 6) continue;
            const char *sn = elf_section_name(ctx, si);
            if (!sn || (strcmp(sn, ".plt") && strcmp(sn, ".plt.sec")
                        && strcmp(sn, ".plt.got"))) continue;
            const uint8_t *d = ctx->map + sh->sh_offset;
            size_t sz = sh->sh_size;
            for (size_t off = 0; off + 6 <= sz; off++) {
                /* 跳过 endbr64 (f3 0f 1e fa) */
                size_t jmp_off = off;
                if (off+4<=sz && d[off]==0xf3 && d[off+1]==0x0f
                    && d[off+2]==0x1e && d[off+3]==0xfa) jmp_off=off+4;
                /* 匹配 jmp [rip+disp32]: ff 25 xx xx xx xx */
                if (jmp_off+6>sz || d[jmp_off]!=0xff || d[jmp_off+1]!=0x25) continue;
                int32_t disp = *(int32_t *)(d + jmp_off + 2);
                uint64_t rip = sh->sh_addr + (uint64_t)jmp_off + 6;
                uint64_t got = (uint64_t)((int64_t)rip + (int64_t)disp);
                /* 查 .rela.plt 映射 */
                for (int mi = 0; mi < npmap; mi++) {
                    if (pmap[mi].got == got && ps) {
                        uint64_t plt_addr = sh->sh_addr + (uint64_t)off;
                        sqlite3_reset(ps);
                        sqlite3_bind_int64(ps, 1, (sqlite3_int64)plt_addr);
                        sqlite3_bind_text(ps,  2, pmap[mi].name, -1, SQLITE_STATIC);
                        sqlite3_step(ps);
                        break;
                    }
                }
                off = jmp_off + 5; /* 跳过当前 jmp, 循环++后从下一条开始 */
            }
        }
        int plt_count = 0; /* 统计步骤10成功写入的PLT符号数 */
        if (ps) {
            sqlite3_finalize(ps);
            /* 统计已写入数量 */
            sqlite3_stmt *cnt = NULL;
            sqlite3_prepare_v2(c, "SELECT COUNT(*) FROM symbols WHERE table_name='.plt'",
                               -1, &cnt, NULL);
            if (cnt && sqlite3_step(cnt) == SQLITE_ROW) plt_count = sqlite3_column_int(cnt, 0);
            if (cnt) sqlite3_finalize(cnt);
        }
        free(pmap);

        /* 如果字节扫描没找到任何PLT stub, 用大小计算回退方案 */
        if (plt_count == 0) {
            for (int si = 0; si < shnum; si++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, si);
                if (!sh || sh->sh_type != SHT_RELA || sh->sh_size == 0) continue;
                const char *sn = elf_section_name(ctx, si);
                if (!sn || !strstr(sn, ".rela.plt")) continue;
                Elf64_Shdr *ds = elf_get_shdr(ctx, sh->sh_link);
                if (!ds || ds->sh_type != SHT_DYNSYM) continue;
                Elf64_Shdr *dst = elf_get_shdr(ctx, ds->sh_link);
                if (!dst) continue;
                int nr = (int)(sh->sh_size / sizeof(Elf64_Rela));
                if (nr == 0) continue;

                /* 找 .plt 节计算条目大小 */
                Elf64_Shdr *psh = NULL; int header = 16;
                for (int pi = 0; pi < shnum; pi++) {
                    const char *pn = elf_section_name(ctx, pi);
                    if (!pn) continue;
                    if (!strcmp(pn, ".plt.sec")) { psh = elf_get_shdr(ctx, pi); header = 0; break; }
                    if (!strcmp(pn, ".plt") && !psh) { psh = elf_get_shdr(ctx, pi); header = 16; }
                }
                size_t entry_sz = 16; /* 默认 */
                if (psh && nr > 0) {
                    size_t content_sz = psh->sh_size - (size_t)header;
                    entry_sz = content_sz / (size_t)nr;
                    if (entry_sz < 8) entry_sz = 8;
                    if (entry_sz > 32) entry_sz = 16; /* 异常值回退 */
                }

                Elf64_Rela *rela = (Elf64_Rela *)(ctx->map + sh->sh_offset);
                Elf64_Sym  *syms = (Elf64_Sym *)(ctx->map + ds->sh_offset);
                sqlite3_stmt *q = NULL;
                sqlite3_prepare_v2(c,
                    "INSERT OR IGNORE INTO symbols(address,name,size,type,bind,table_name)"
                    " VALUES(?,?,0,'FUNC','GLOBAL','.plt')", -1, &q, NULL);
                for (int ri = 0; ri < nr && q; ri++) {
                    uint32_t sym_idx = (uint32_t)(rela[ri].r_info >> 32);
                    if (sym_idx >= ds->sh_size / sizeof(Elf64_Sym)) continue;
                    const char *raw = elf_strtab_get(ctx, dst->sh_offset, syms[sym_idx].st_name);
                    if (!raw || !raw[0]) continue;
                    char nm[128]; snprintf(nm,sizeof(nm),"%s",raw);
                    char *at = strchr(nm,'@'); if(at)*at='\0';
                    uint64_t pa = psh ? psh->sh_addr + (uint64_t)header + (uint64_t)(ri * entry_sz) : rela[ri].r_offset;
                    sqlite3_reset(q);
                    sqlite3_bind_int64(q, 1, (sqlite3_int64)pa);
                    sqlite3_bind_text(q,  2, nm, -1, SQLITE_STATIC);
                    sqlite3_step(q);
                }
                if (q) sqlite3_finalize(q);
                break;
            }
        }
        skip_plt:;
    }

    /* ── 11: 漏洞模式扫描 ── */
    db_scan_vulns(db);

import_done:
    free(bbs);
    free(funcs);
    db->insn_count = total_insn;
    return total_insn;
}

/* ── 独立漏洞扫描 (兼容旧DB) ───────────────────────────────────── */
int db_scan_vulns(AnalysisDB *db) {
    if (!db || !db->conn) return -1;
    sqlite3 *c = db->conn;

    /* 两个表都非空则跳过 */
    sqlite3_stmt *ck = NULL; int has_vuln = 0, has_taint = 0;
    sqlite3_prepare_v2(c, "SELECT COUNT(*) FROM vuln_candidates", -1, &ck, NULL);
    if (ck && sqlite3_step(ck) == SQLITE_ROW && sqlite3_column_int(ck, 0) > 0) has_vuln = 1;
    if (ck) sqlite3_finalize(ck);
    sqlite3_prepare_v2(c, "SELECT COUNT(*) FROM taint_sources", -1, &ck, NULL);
    if (ck && sqlite3_step(ck) == SQLITE_ROW && sqlite3_column_int(ck, 0) > 0) has_taint = 1;
    if (ck) sqlite3_finalize(ck);
    if (has_vuln && has_taint) return 0;

    /* 单条SQL — 无循环, 无 snprintf 拼字符串 */
    if (!has_taint) {
        exec_sql(db,
            "INSERT OR IGNORE INTO taint_sources(address,source_func,target_reg,function_addr)"
            " SELECT i.address, s.name, 'rax',"
            "  (SELECT f.start_addr FROM functions f"
            "   WHERE f.start_addr<=i.address AND f.end_addr>i.address LIMIT 1)"
            " FROM instructions i"
            " JOIN xrefs x ON i.address=x.from_addr"
            " JOIN symbols s ON x.to_addr=s.address AND s.table_name='.plt'"
            " WHERE i.mnemonic='call' AND x.ref_type='call'"
            " AND s.name IN ('recv','recvfrom','recvmsg','recvmmsg',"
            "  'read','pread','readv','preadv','fread',"
            "  'fgets','gets','getenv','scanf','fscanf','sscanf',"
            "  'getline','getdelim','getchar','readline',"
            "  'accept','accept4',"
            "  'write','send','sendto','sendmsg','sendmmsg',"
            "  'connect','socket','bind','listen')");
    }

    if (!has_vuln) {
        exec_sql(db,
            "INSERT OR IGNORE INTO vuln_candidates"
            " (address,vuln_type,severity,sink_func,description,function_addr)"
            " SELECT i.address,"
            "  CASE s.name"
            "   WHEN 'strcpy' THEN 'stack_overflow'"
            "   WHEN 'strcat' THEN 'stack_overflow'"
            "   WHEN 'sprintf' THEN 'stack_overflow'"
            "   WHEN 'gets' THEN 'stack_overflow'"
            "   WHEN 'memcpy' THEN 'stack_overflow'"
            "   WHEN 'read' THEN 'stack_overflow'"
            "   WHEN 'system' THEN 'command_injection'"
            "   WHEN 'execve' THEN 'command_injection'"
            "   WHEN 'execvp' THEN 'command_injection'"
            "   WHEN 'popen' THEN 'command_injection'"
            "   WHEN 'printf' THEN 'format_string'"
            "   WHEN 'fprintf' THEN 'format_string'"
            "   WHEN 'mprotect' THEN 'arbitrary_code'"
            "   ELSE 'unknown' END,"
            "  CASE s.name"
            "   WHEN 'strcpy' THEN 'CRITICAL'"
            "   WHEN 'strcat' THEN 'CRITICAL'"
            "   WHEN 'sprintf' THEN 'CRITICAL'"
            "   WHEN 'gets' THEN 'CRITICAL'"
            "   WHEN 'system' THEN 'CRITICAL'"
            "   WHEN 'execve' THEN 'CRITICAL'"
            "   WHEN 'execvp' THEN 'CRITICAL'"
            "   WHEN 'memcpy' THEN 'HIGH'"
            "   WHEN 'popen' THEN 'HIGH'"
            "   WHEN 'printf' THEN 'HIGH'"
            "   WHEN 'fprintf' THEN 'HIGH'"
            "   WHEN 'mprotect' THEN 'HIGH'"
            "   WHEN 'read' THEN 'MEDIUM'"
            "   ELSE 'LOW' END,"
            "  s.name,"
            "  'Security risk — review call context.',"
            "  (SELECT f.start_addr FROM functions f"
            "   WHERE f.start_addr<=i.address AND f.end_addr>i.address LIMIT 1)"
            " FROM instructions i"
            " JOIN xrefs x ON i.address=x.from_addr"
            " JOIN symbols s ON x.to_addr=s.address AND s.table_name='.plt'"
            " WHERE i.mnemonic='call' AND x.ref_type='call'"
            " AND s.name IN ('strcpy','strcat','sprintf','gets','memcpy','read',"
            "  'system','execve','execvp','popen','printf','fprintf','mprotect')");
    }
    return 0;
}


/* ── 公开: 查询 ──────────────────────────────────────────────────── */

int db_query_insn(AnalysisDB *db, uint64_t addr, DbInsn *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT address,bytes,mnemonic,op_str,size,section"
        " FROM instructions WHERE address=?", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->address = (uint64_t)sqlite3_column_int64(st, 0);
        const void *b = sqlite3_column_blob(st, 1);
        int bs = sqlite3_column_bytes(st, 1);
        if (b && bs > 0 && bs <= 16) memcpy(out->bytes, b, (size_t)bs);
        snprintf(out->mnemonic, sizeof(out->mnemonic), "%s",
                 sqlite3_column_text(st, 2));
        snprintf(out->op_str, sizeof(out->op_str), "%s",
                 sqlite3_column_text(st, 3));
        out->size = sqlite3_column_int(st, 4);
        snprintf(out->section, sizeof(out->section), "%s",
                 sqlite3_column_text(st, 5));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_query_func(AnalysisDB *db, uint64_t addr, DbFunc *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT start_addr,end_addr,name,bb_count FROM functions"
        " WHERE start_addr<=? AND end_addr>? LIMIT 1", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)addr);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->start_addr = (uint64_t)sqlite3_column_int64(st, 0);
        out->end_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        snprintf(out->name, sizeof(out->name), "%s", sqlite3_column_text(st, 2));
        out->bb_count = sqlite3_column_int(st, 3);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_query_bb(AnalysisDB *db, uint64_t addr, DbBB *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT start_addr,end_addr,function_addr,insn_count FROM basic_blocks"
        " WHERE start_addr<=? AND end_addr>? LIMIT 1", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)addr);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->start_addr    = (uint64_t)sqlite3_column_int64(st, 0);
        out->end_addr      = (uint64_t)sqlite3_column_int64(st, 1);
        out->function_addr = (uint64_t)sqlite3_column_int64(st, 2);
        out->insn_count    = sqlite3_column_int(st, 3);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_query_cfg_from(AnalysisDB *db, uint64_t addr, DbCfgEdge *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT from_addr,to_addr,edge_type FROM cfg_edges WHERE from_addr=? LIMIT ?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].from_addr = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].to_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        snprintf(out[n].edge_type, sizeof(out[n].edge_type), "%s",
                 sqlite3_column_text(st, 2));
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_query_cfg_to(AnalysisDB *db, uint64_t addr, DbCfgEdge *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT from_addr,to_addr,edge_type FROM cfg_edges WHERE to_addr=? LIMIT ?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].from_addr = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].to_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        snprintf(out[n].edge_type, sizeof(out[n].edge_type), "%s",
                 sqlite3_column_text(st, 2));
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_query_xref_to(AnalysisDB *db, uint64_t addr, DbXref *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT from_addr,to_addr,ref_type,detail FROM xrefs WHERE to_addr=? LIMIT ?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].from_addr = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].to_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        snprintf(out[n].ref_type, sizeof(out[n].ref_type), "%s",
                 sqlite3_column_text(st, 2));
        const char *d = (const char*)sqlite3_column_text(st, 3);
        if (d) snprintf(out[n].detail, sizeof(out[n].detail), "%s", d);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_query_xref_from(AnalysisDB *db, uint64_t addr, DbXref *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT from_addr,to_addr,ref_type,detail FROM xrefs WHERE from_addr=? LIMIT ?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].from_addr = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].to_addr   = (uint64_t)sqlite3_column_int64(st, 1);
        snprintf(out[n].ref_type, sizeof(out[n].ref_type), "%s",
                 sqlite3_column_text(st, 2));
        const char *d = (const char*)sqlite3_column_text(st, 3);
        if (d) snprintf(out[n].detail, sizeof(out[n].detail), "%s", d);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_query_symbol_by_addr(AnalysisDB *db, uint64_t addr, DbSymbol *out) {
    if (!db || !out) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT address,name,size,type,bind,table_name FROM symbols"
        " WHERE address=? LIMIT 1", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->address = (uint64_t)sqlite3_column_int64(st, 0);
        snprintf(out->name, sizeof(out->name), "%s", sqlite3_column_text(st, 1));
        out->size = sqlite3_column_int(st, 2);
        snprintf(out->type, sizeof(out->type), "%s", sqlite3_column_text(st, 3));
        snprintf(out->bind, sizeof(out->bind), "%s", sqlite3_column_text(st, 4));
        snprintf(out->table_name, sizeof(out->table_name), "%s", sqlite3_column_text(st, 5));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_query_symbol_by_name(AnalysisDB *db, const char *name, DbSymbol *out) {
    if (!db || !name || !out) return -1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT address,name,size,type,bind,table_name FROM symbols"
        " WHERE name=? LIMIT 1", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->address = (uint64_t)sqlite3_column_int64(st, 0);
        snprintf(out->name, sizeof(out->name), "%s", sqlite3_column_text(st, 1));
        out->size = sqlite3_column_int(st, 2);
        snprintf(out->type, sizeof(out->type), "%s", sqlite3_column_text(st, 3));
        snprintf(out->bind, sizeof(out->bind), "%s", sqlite3_column_text(st, 4));
        snprintf(out->table_name, sizeof(out->table_name), "%s", sqlite3_column_text(st, 5));
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* ── 一键全查 ────────────────────────────────────────────────────── */

int db_query_addr_all(AnalysisDB *db, uint64_t addr,
                      const struct DebugState *ds, PanelData *pd,
                      int depth) {
    if (!db || !pd) return -1;
    char buf[600];

    /* ── 摘要行 ── */
    DbInsn insn; DbFunc func; DbSymbol sym;
    int has_insn = (db_query_insn(db, addr, &insn) == 0);
    int has_func = (db_query_func(db, addr, &func) == 0);
    int has_sym  = (db_query_symbol_by_addr(db, addr, &sym) == 0);

    /* 深度面包屑行 (始终在第一行, 固定) */
    snprintf(buf,sizeof(buf),"▸ Jump Depth: %d  [h]=back  [Enter]=follow  [Space]=search", depth);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);

    snprintf(buf,sizeof(buf),"▸ 0x%lx  %s %s  |  %s  [%s]",
        (unsigned long)addr,
        has_insn?insn.mnemonic:"?", has_insn?insn.op_str:"",
        has_func?func.name:(has_sym?sym.name:"?"),
        has_insn?insn.section:"?");
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    if (has_func)
        snprintf(buf,sizeof(buf),"   Func: %s  0x%lx─0x%lx  %d BBs  |  Size: %d",
            func.name,(unsigned long)func.start_addr,
            (unsigned long)func.end_addr,func.bb_count,
            has_sym?sym.size:0);
    else
        snprintf(buf,sizeof(buf),"   Func: (none)  |  Sym: %s [%s/%s]",
            has_sym?sym.name:"?",
            has_sym?sym.type:"?",has_sym?sym.bind:"?");
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);

    /* ── 反汇编上下文 (±10 行) ── */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"── Disassembly (±5) ──%s",
        depth>0?"  [h]=back":"  [h]=back to middle");
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);

    /* 向前找 10 条指令, 向后找 10 条 */
    uint64_t ctx_start = addr;
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT address,mnemonic,op_str FROM instructions"
            " WHERE address<=?1 AND section=(SELECT section FROM instructions WHERE address=?1)"
            " ORDER BY address DESC LIMIT 6", -1, &st, NULL);
        if(st){
            sqlite3_bind_int64(st,1,(sqlite3_int64)addr);
            int n=0;uint64_t addrs[11];
            while(sqlite3_step(st)==SQLITE_ROW&&n<11){
                addrs[n++]=(uint64_t)sqlite3_column_int64(st,0);}
            if(n>0)ctx_start=addrs[n-1]; /* 最早的一条 */
            sqlite3_finalize(st);
        }
    }
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT address,mnemonic,op_str FROM instructions"
            " WHERE address>=?1 AND section=(SELECT section FROM instructions WHERE address=?1)"
            " ORDER BY address LIMIT 12", -1, &st, NULL);
        if(st){
            sqlite3_bind_int64(st,1,(sqlite3_int64)ctx_start);
            int shown=0; int cursor_line = pd->count; /* 默认光标在第一行 */
            while(sqlite3_step(st)==SQLITE_ROW&&shown<22){
                uint64_t a=(uint64_t)sqlite3_column_int64(st,0);
                const char *mn=(const char*)sqlite3_column_text(st,1);
                const char *op=(const char*)sqlite3_column_text(st,2);
                snprintf(buf,sizeof(buf),"%s0x%lx  %-8s %s",
                    a==addr?">":" ",(unsigned long)a,mn?mn:"?",op?op:"");
                /* 目标地址行: 可选中, 高亮 + > 标记 */
                int sel = (a==addr)?1:0;
                fields_add(pd,buf,1,sel,DETAIL_NONE,(int)a);
                if(a==addr)cursor_line=pd->count-1;
                shown++;
            }
            pd->cursor=cursor_line; /* 光标定位到目标指令行 */
            sqlite3_finalize(st);
        }
    }

    /* ── CFG ── */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"── Control Flow ──",1,0,DETAIL_NONE,-1);
    {
        DbCfgEdge ce[16];int nc;
        nc=db_query_cfg_from(db,addr,ce,16);
        if(nc>0){for(int i=0;i<nc;i++){
            snprintf(buf,sizeof(buf),"→ 0x%lx  %s",(unsigned long)ce[i].to_addr,ce[i].edge_type);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);}}
        else fields_add(pd,"→ (terminal / fallthrough)",2,0,DETAIL_NONE,-1);
        nc=db_query_cfg_to(db,addr,ce,16);
        if(nc>0){for(int i=0;i<nc;i++){
            snprintf(buf,sizeof(buf),"← 0x%lx  %s",(unsigned long)ce[i].from_addr,ce[i].edge_type);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);}}
    }

    /* ── XREF ── */
    fields_add(pd,"── Cross References ──",1,0,DETAIL_NONE,-1);
    {
        DbXref xr[48];int nx;
        nx=db_query_xref_to(db,addr,xr,48);
        if(nx>0){
            snprintf(buf,sizeof(buf),"Referenced by (%d):",nx);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            for(int i=0;i<nx&&i<20;i++){
                snprintf(buf,sizeof(buf),"0x%lx  %-6s %s",
                    (unsigned long)xr[i].from_addr,xr[i].ref_type,xr[i].detail);
                fields_add(pd,buf,3,0,DETAIL_NONE,-1);}
        }
        nx=db_query_xref_from(db,addr,xr,48);
        if(nx>0){
            snprintf(buf,sizeof(buf),"References to (%d):",nx);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            for(int i=0;i<nx&&i<20;i++){
                snprintf(buf,sizeof(buf),"0x%lx  %-6s %s",
                    (unsigned long)xr[i].to_addr,xr[i].ref_type,xr[i].detail);
                fields_add(pd,buf,3,0,DETAIL_NONE,-1);}
        }
        if(nx==0){
            nx=db_query_xref_to(db,addr,xr,48);
            if(nx==0)fields_add(pd,"(no xrefs)",2,0,DETAIL_NONE,-1);
        }
    }

    /* ── 寄存器快照 ── */
    if (ds) {
        fields_add(pd,"── Registers ──",1,0,DETAIL_NONE,-1);
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT step_num,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,rip,eflags"
            " FROM reg_snapshots WHERE rip=? ORDER BY step_num LIMIT 8",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)addr);
            int nrs=0;
            while(sqlite3_step(st)==SQLITE_ROW&&nrs<8){
                snprintf(buf,sizeof(buf),"step%-3d  RAX=0x%lx RBX=0x%lx RCX=0x%lx RDX=0x%lx",
                    sqlite3_column_int(st,0),
                    (unsigned long)sqlite3_column_int64(st,1),
                    (unsigned long)sqlite3_column_int64(st,2),
                    (unsigned long)sqlite3_column_int64(st,3),
                    (unsigned long)sqlite3_column_int64(st,4));
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);
                snprintf(buf,sizeof(buf),"        RSI=0x%lx RDI=0x%lx RBP=0x%lx RSP=0x%lx EFL=0x%lx",
                    (unsigned long)sqlite3_column_int64(st,5),
                    (unsigned long)sqlite3_column_int64(st,6),
                    (unsigned long)sqlite3_column_int64(st,7),
                    (unsigned long)sqlite3_column_int64(st,8),
                    (unsigned long)sqlite3_column_int64(st,10));
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);
                nrs++;}
            sqlite3_finalize(st);}
    }

    /* ── 调用者/被调用者 ── */
    if(has_func){
        fields_add(pd,"── Callers ──",1,0,DETAIL_NONE,-1);
        uint64_t callers[32];
        int nc=db_query_func_callers(db,func.start_addr,callers,32);
        if(nc>0){
            for(int i=0;i<nc&&i<12;i++){
                DbInsn ci;char lb[64]="";
                if(db_query_insn(db,callers[i],&ci)==0)
                    snprintf(lb,sizeof(lb),"  %s %s",ci.mnemonic,ci.op_str);
                snprintf(buf,sizeof(buf),"0x%lx%s",(unsigned long)callers[i],lb);
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);}
        }else fields_add(pd,"(none found)",2,0,DETAIL_NONE,-1);

        fields_add(pd,"── Callees ──",1,0,DETAIL_NONE,-1);
        uint64_t callees[32];
        nc=db_query_func_callees(db,func.start_addr,callees,32);
        if(nc>0){
            for(int i=0;i<nc&&i<12;i++){
                DbSymbol cs;
                if(db_query_symbol_by_addr(db,callees[i],&cs)==0)
                    snprintf(buf,sizeof(buf),"0x%lx  %s",(unsigned long)callees[i],cs.name);
                else
                    snprintf(buf,sizeof(buf),"0x%lx",(unsigned long)callees[i]);
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);}
        }else fields_add(pd,"(none)",2,0,DETAIL_NONE,-1);
    }

    /* ── Strategy 3: Exploitability Assessment ─────────────────── */
    {
        char ex[256]; int has_ex = 0;
        /* 栈帧大小 */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT address, op_str FROM instructions "
            "WHERE address BETWEEN ?1 AND ?1+20 AND mnemonic='sub' AND op_str LIKE '%rsp%' LIMIT 1",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)(has_func ? func.start_addr : addr));
            if (sqlite3_step(st) == SQLITE_ROW) {
                uint64_t fa = (uint64_t)sqlite3_column_int64(st, 0);
                const char *op = (const char*)sqlite3_column_text(st, 1);
                int fsz = 0;
                if (op) { const char *c2 = strchr(op, ','); if (c2) {
                    c2++; while (*c2 == ' ') c2++;
                    fsz = (strncmp(c2,"0x",2)==0) ? (int)strtol(c2,NULL,16) : atoi(c2); }}
                if (fsz > 0) {
                    if (!has_ex) { fields_add(pd,"",0,0,DETAIL_NONE,-1);
                        fields_add(pd,"── Exploitability ──",1,0,DETAIL_NONE,-1); has_ex=1; }
                    snprintf(ex, sizeof(ex), "Stack frame: 0x%x (%d) bytes  sub rsp @ 0x%lx", fsz, fsz, (unsigned long)fa);
                    fields_add(pd, ex, 2, 0, DETAIL_NONE, -1);
                }
            }
            sqlite3_finalize(st);
        }
        /* canary */
        sqlite3_prepare_v2(db->conn,
            "SELECT 1 FROM symbols WHERE name LIKE '%stack_chk%' LIMIT 1",
            -1, &st, NULL);
        if (st) {
            int has_canary = (sqlite3_step(st) == SQLITE_ROW);
            sqlite3_finalize(st);
            if (has_canary) {
                if (!has_ex) { fields_add(pd,"",0,0,DETAIL_NONE,-1);
                    fields_add(pd,"── Exploitability ──",1,0,DETAIL_NONE,-1); has_ex=1; }
                fields_add(pd, "Canary: YES — need leak before overwrite", 2, 0, DETAIL_NONE, -1);
            } else {
                if (!has_ex) { fields_add(pd,"",0,0,DETAIL_NONE,-1);
                    fields_add(pd,"── Exploitability ──",1,0,DETAIL_NONE,-1); has_ex=1; }
                fields_add(pd, "Canary: NO — direct RIP overwrite possible", 2, 0, DETAIL_NONE, -1);
            }
        }
        /* ROP gadget: pop rdi adjacent to ret */
        {
            sqlite3_stmt *gs = NULL;
            sqlite3_prepare_v2(db->conn,
                "SELECT i1.address FROM instructions i1 WHERE i1.mnemonic='pop' "
                "AND i1.op_str='rdi' AND i1.address+i1.size IN "
                "(SELECT address FROM instructions WHERE mnemonic='ret') LIMIT 1",
                -1, &gs, NULL);
            if (gs) {
                if (sqlite3_step(gs) == SQLITE_ROW) {
                    if (!has_ex) { fields_add(pd,"",0,0,DETAIL_NONE,-1);
                        fields_add(pd,"── Exploitability ──",1,0,DETAIL_NONE,-1); has_ex=1; }
                    snprintf(ex, sizeof(ex), "Gadget: pop rdi; ret @ 0x%lx",
                        (unsigned long)sqlite3_column_int64(gs,0));
                    fields_add(pd, ex, 2, 0, DETAIL_NONE, -1);
                }
                sqlite3_finalize(gs);
            }
        }
        /* system@plt */
        {
            sqlite3_stmt *gs = NULL;
            sqlite3_prepare_v2(db->conn,
                "SELECT address FROM symbols WHERE name='system' LIMIT 1", -1, &gs, NULL);
            if (gs) {
                if (sqlite3_step(gs) == SQLITE_ROW) {
                    snprintf(ex, sizeof(ex), "system@plt: 0x%lx", (unsigned long)sqlite3_column_int64(gs,0));
                    fields_add(pd, ex, 2, 0, DETAIL_NONE, -1);
                }
                sqlite3_finalize(gs);
            }
        }
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"[h]back [Enter]follow address [Space]search",1,0,DETAIL_NONE,-1);
    return pd->count;
}

/* ── 函数级查询 ──────────────────────────────────────────────────── */

int db_query_func_bbs(AnalysisDB *db, uint64_t func_addr, DbBB *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT start_addr,end_addr,function_addr,insn_count FROM basic_blocks"
        " WHERE function_addr=? ORDER BY start_addr LIMIT ?", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].start_addr    = (uint64_t)sqlite3_column_int64(st, 0);
        out[n].end_addr      = (uint64_t)sqlite3_column_int64(st, 1);
        out[n].function_addr = (uint64_t)sqlite3_column_int64(st, 2);
        out[n].insn_count    = sqlite3_column_int(st, 3);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_query_func_callers(AnalysisDB *db, uint64_t func_addr,
                          uint64_t *callers, int max) {
    if (!db || !callers || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT DISTINCT from_addr FROM xrefs"
        " WHERE to_addr=? AND ref_type='call' LIMIT ?", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max)
        callers[n++] = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

int db_query_func_callees(AnalysisDB *db, uint64_t func_addr,
                          uint64_t *callees, int max) {
    if (!db || !callees || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT DISTINCT to_addr FROM xrefs"
        " WHERE from_addr BETWEEN ? AND (SELECT end_addr FROM functions WHERE start_addr=?)"
        " AND ref_type='call' LIMIT ?", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)func_addr);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)func_addr);
    sqlite3_bind_int(st, 3, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max)
        callees[n++] = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* ── 动态数据写入 ────────────────────────────────────────────────── */

int db_query_reg_at_insn(AnalysisDB *db, uint64_t addr, DbRegSnap *out, int max) {
    if (!db || !out || max <= 0) return -1;
    int n = 0;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT step_num,rip,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,"
        "  r8,r9,r10,r11,r12,r13,r14,r15,eflags,cs,ds,es,fs,gs,ss"
        " FROM reg_snapshots WHERE rip=? ORDER BY step_num LIMIT ?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    sqlite3_bind_int(st, 2, max);
    while (sqlite3_step(st) == SQLITE_ROW && n < max) {
        out[n].step_num = sqlite3_column_int(st, 0);
        out[n].rip      = (uint64_t)sqlite3_column_int64(st, 1);
        for (int i = 0; i < 22; i++)
            out[n].regs[i] = (uint64_t)sqlite3_column_int64(st, 2 + i);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int db_insert_reg_snapshot(AnalysisDB *db, const struct DebugState *ds,
                           int step_num) {
    if (!db || !ds || !ds->attached) return -1;
    struct timeval tv; gettimeofday(&tv, NULL);
    int64_t ts = (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    const char *sql =
        "INSERT INTO reg_snapshots"
        " (timestamp,step_num,rip,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,"
        "  r8,r9,r10,r11,r12,r13,r14,r15,eflags,cs,ds,es,fs,gs,ss)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn, sql, -1, &st, NULL);
    if (!st) return -1;

    const struct user_regs_struct *r = &ds->regs;
    int idx = 1;
    sqlite3_bind_int64(st, idx++, ts);
    sqlite3_bind_int(st,    idx++, step_num);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rip);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rax);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rbx);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rcx);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rdx);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rsi);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rdi);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rbp);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->rsp);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r8);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r9);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r10);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r11);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r12);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r13);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r14);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->r15);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->eflags);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->cs);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->ds);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->es);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->fs);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->gs);
    sqlite3_bind_int64(st, idx++, (sqlite3_int64)r->ss);

    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) { db->snap_count++; return 0; }
    return -1;
}

/* ── CFG 可视化 ────────────────────────────────────────────────── */

int db_render_cfg_graph(AnalysisDB *db, uint64_t addr, PanelData *pd) {
    if (!db || !pd) return -1;
    char buf[512];

    /* 找包含 addr 的函数 */
    DbFunc func;
    if (db_query_func(db, addr, &func) != 0) {
        fields_add(pd,"(not in a known function)",0,0,DETAIL_NONE,-1);
        return -1;
    }

    snprintf(buf,sizeof(buf),"▸ CFG: %s  0x%lx-0x%lx  %d BBs",
             func.name,(unsigned long)func.start_addr,
             (unsigned long)func.end_addr,func.bb_count);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 获取所有 BBs */
    DbBB bbs[128];
    int nbb = db_query_func_bbs(db, func.start_addr, bbs, 128);
    if (nbb == 0) { fields_add(pd,"(no basic blocks)",1,0,DETAIL_NONE,-1); return -1; }

    /* 为每个 BB 收集出边 */
    typedef struct { uint64_t targets[4]; int n; } bb_edges_t;
    bb_edges_t edges[128] = {0};

    for (int i = 0; i < nbb && i < 128; i++) {
        /* 找出边的最后一条指令的 cfg_edges */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT to_addr,edge_type FROM cfg_edges"
            " WHERE from_addr>=?1 AND from_addr<?2"
            " ORDER BY from_addr",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)bbs[i].start_addr);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)bbs[i].end_addr);
            while (sqlite3_step(st) == SQLITE_ROW && edges[i].n < 4) {
                edges[i].targets[edges[i].n++] =
                    (uint64_t)sqlite3_column_int64(st, 0);
            }
            sqlite3_finalize(st);
        }
    }

    /* ── ASCII 图渲染 ── */
    #define BB_W 22  /* 每个 BB 框的宽度 */

    /* 为每个 BB 找目标BB的索引 */
    int bb_targets[128][4] = {{0}};
    int bb_ntargets[128] = {0};
    for (int i = 0; i < nbb; i++) {
        for (int j = 0; j < edges[i].n && j < 4; j++) {
            uint64_t tgt = edges[i].targets[j];
            for (int k = 0; k < nbb; k++) {
                if (tgt >= bbs[k].start_addr && tgt < bbs[k].end_addr) {
                    bb_targets[i][bb_ntargets[i]++] = k;
                    break;
                }
            }
        }
    }

    /* 简单垂直布局: 按地址排序的 BBs, 每行一个, 箭头标注 */
    for (int i = 0; i < nbb; i++) {
        /* BB 标签 */
        char addr_str[20];
        snprintf(addr_str,sizeof(addr_str),"0x%lx",(unsigned long)bbs[i].start_addr);

        /* 入边箭头 */
        int has_in = 0;
        for (int j = 0; j < nbb && !has_in; j++)
            for (int t = 0; t < bb_ntargets[j]; t++)
                if (bb_targets[j][t] == i) has_in = 1;

        /* 出边标注 */
        char out_mark[16] = "";
        int is_call = 0, is_jmp = 0;
        for (int j = 0; j < edges[i].n; j++) {
            /* 检查边类型 */
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(db->conn,
                "SELECT edge_type FROM cfg_edges WHERE from_addr>=?1 AND from_addr<?2 AND to_addr=?3 LIMIT 1",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_int64(st, 1, (sqlite3_int64)bbs[i].start_addr);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)bbs[i].end_addr);
                sqlite3_bind_int64(st, 3, (sqlite3_int64)edges[i].targets[j]);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *et = (const char*)sqlite3_column_text(st, 0);
                    if (et && !strcmp(et, "call")) is_call = 1;
                    if (et && !strcmp(et, "jump")) is_jmp = 1;
                }
                sqlite3_finalize(st);
            }
        }
        if (is_call) snprintf(out_mark,sizeof(out_mark),"→[call]");
        else if (bb_ntargets[i] > 0) snprintf(out_mark,sizeof(out_mark),"→%d",bb_ntargets[i]);

        /* 绘制 BB 框 */
        int is_entry = (bbs[i].start_addr == func.start_addr);
        char marker = bbs[i].start_addr <= addr && addr < bbs[i].end_addr ? '>' : ' ';

        snprintf(buf,sizeof(buf),"%c\xe2\x94\x8c\xe2\x94\x80 BB#%d (%dins) \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x90  %s  %s%s",
                 marker, i, bbs[i].insn_count, addr_str, out_mark, is_entry?" [ENTRY]":"");
        fields_add(pd,buf,1,1,DETAIL_NONE,(int)bbs[i].start_addr);

        /* BB 内容: 首尾指令 */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db->conn,
            "SELECT mnemonic,op_str FROM instructions"
            " WHERE address BETWEEN ?1 AND ?2 ORDER BY address LIMIT 3",
            -1, &st, NULL);
        if (st) {
            sqlite3_bind_int64(st, 1, (sqlite3_int64)bbs[i].start_addr);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)bbs[i].end_addr);
            int shown = 0;
            while (sqlite3_step(st) == SQLITE_ROW && shown < 3) {
                const char *m = (const char*)sqlite3_column_text(st, 0);
                const char *o = (const char*)sqlite3_column_text(st, 1);
                snprintf(buf,sizeof(buf),"\xe2\x94\x82 %-8s %-40s \xe2\x94\x82",
                         m?m:"?", o?o:"");
                fields_add(pd,buf,2,1,DETAIL_NONE,-1);
                shown++;
            }
            sqlite3_finalize(st);
        }

        /* BB 底边 + 出边目标 */
        snprintf(buf,sizeof(buf),"\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80");
        fields_add(pd,buf,1,0,DETAIL_NONE,-1);

        /* 出边箭头指向的 BB */
        for (int t = 0; t < bb_ntargets[i]; t++) {
            int ti = bb_targets[i][t];
            snprintf(buf,sizeof(buf),"  \xe2\x86\xb3 BB#%d (0x%lx)",
                     ti, (unsigned long)bbs[ti].start_addr);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        if (bb_ntargets[i] == 0 && i + 1 < nbb) {
            /* fallthrough 到下一个 BB */
            snprintf(buf,sizeof(buf),"  \xe2\x86\x93 fallthrough to BB#%d", i+1);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        fields_add(pd,"",0,0,DETAIL_NONE,-1);
    }

    snprintf(buf,sizeof(buf),"%d BBs, %d edges  [V]=graph [Enter]=jump [h]=back",
             nbb, nbb > 0 ? bb_ntargets[0] : 0);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    return 0;
}

/* ── IR 语义数据流 ─────────────────────────────────────────────── */

int db_dataflow_query(AnalysisDB *db, uint64_t addr, PanelData *pd) {
    if (!db || !pd) return -1;
    char buf[512]; sqlite3 *c = (sqlite3 *)db_conn(db);
    sqlite3_stmt *st = NULL;

    /* 当前指令 */
    sqlite3_prepare_v2(c,
        "SELECT mnemonic,op_str FROM instructions WHERE address=?",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(buf,sizeof(buf),"DataFlow @ 0x%lx  %s %s",
            (unsigned long)addr,
            (const char*)sqlite3_column_text(st,0),
            (const char*)sqlite3_column_text(st,1));
        fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    }
    sqlite3_finalize(st);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 读寄存器: 谁向这些寄存器写了值? */
    fields_add(pd,"-- Registers Read (defs) --",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(c,
        "SELECT i2.address,i2.mnemonic,i2.op_str,i2.address-?1 as dist"
        " FROM ir_stmts ir1"
        " JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write'"
        " JOIN instructions i2 ON ir2.address=i2.address"
        " WHERE ir1.address=?1 AND ir1.op_type='reg_read'"
        " AND ir2.address<?1"
        " ORDER BY ir2.address DESC LIMIT 8",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 8) {
            uint64_t da = (uint64_t)sqlite3_column_int64(st, 0);
            const char *m = (const char*)sqlite3_column_text(st, 1);
            const char *o = (const char*)sqlite3_column_text(st, 2);
            int dist = sqlite3_column_int(st, 3);
            snprintf(buf,sizeof(buf),"0x%lx  %-8s %-30s  (-%d)",
                (unsigned long)da, m?m:"?", o?o:"", dist);
            fields_add(pd,buf,2,1,DETAIL_NONE,(int)da);
            n++;
        }
        sqlite3_finalize(st);
        if (n == 0) fields_add(pd,"(no reg_read data — DB import needed)",2,0,DETAIL_NONE,-1);
    }

    /* 写寄存器: 哪些指令会读这里写的值? */
    fields_add(pd,"-- Registers Written (uses) --",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(c,
        "SELECT i2.address,i2.mnemonic,i2.op_str,i2.address-?1 as dist"
        " FROM ir_stmts ir1"
        " JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_read'"
        " JOIN instructions i2 ON ir2.address=i2.address"
        " WHERE ir1.address=?1 AND ir1.op_type='reg_write'"
        " AND ir2.address>?1"
        " ORDER BY ir2.address LIMIT 8",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 8) {
            uint64_t da = (uint64_t)sqlite3_column_int64(st, 0);
            const char *m = (const char*)sqlite3_column_text(st, 1);
            const char *o = (const char*)sqlite3_column_text(st, 2);
            int dist = sqlite3_column_int(st, 3);
            snprintf(buf,sizeof(buf),"0x%lx  %-8s %-30s  (+%d)",
                (unsigned long)da, m?m:"?", o?o:"", dist);
            fields_add(pd,buf,2,1,DETAIL_NONE,(int)da);
            n++;
        }
        sqlite3_finalize(st);
        if (n == 0) fields_add(pd,"(no reg_write data)",2,0,DETAIL_NONE,-1);
    }

    /* 内存操作 */
    fields_add(pd,"-- Memory Access --",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(c,
        "SELECT op_type,src,mem_base,mem_disp FROM ir_stmts"
        " WHERE address=? AND op_type='mem_access' LIMIT 4",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW && n < 4) {
            const char *t = (const char*)sqlite3_column_text(st, 0);
            const char *s = (const char*)sqlite3_column_text(st, 1);
            const char *b = (const char*)sqlite3_column_text(st, 2);
            int d = sqlite3_column_int(st, 3);
            snprintf(buf,sizeof(buf),"%s  [%s+%d]  src=%s", t?t:"?", b?b:"?", d, s?s:"?");
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            n++;
        }
        sqlite3_finalize(st);
    }

    /* 立即数 */
    sqlite3_prepare_v2(c,
        "SELECT imm_value FROM ir_stmts"
        " WHERE address=? AND op_type='immediate' LIMIT 4",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        while (sqlite3_step(st) == SQLITE_ROW) {
            int64_t imm = sqlite3_column_int64(st, 0);
            snprintf(buf,sizeof(buf),"immediate: 0x%lx (%ld)",
                (unsigned long)imm, (long)imm);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"[d]=dataflow [Enter]=jump [f]=trace args [h]=back",1,0,DETAIL_NONE,-1);
    return 0;
}

/* ── 反向数据流追踪 ────────────────────────────────────────────── */

int db_trace_args(AnalysisDB *db, uint64_t call_addr, PanelData *pd) {
    if (!db || !pd) return -1;
    char buf[512];

    /* 查找被调用函数名 */
    char callee[128] = "?";
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT s.name FROM xrefs x JOIN symbols s ON x.to_addr=s.address"
        " WHERE x.from_addr=? AND x.ref_type='call' LIMIT 1",
        -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(callee, sizeof(callee), "%s",
                     (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }

    /* 查找所在函数 */
    sqlite3_prepare_v2(db->conn,
        "SELECT start_addr,name FROM functions"
        " WHERE start_addr<=?1 AND end_addr>?1 LIMIT 1",
        -1, &st, NULL);
    char func_name[128] = "?";
    uint64_t func_start = 0;
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);
        if (sqlite3_step(st) == SQLITE_ROW) {
            func_start = (uint64_t)sqlite3_column_int64(st, 0);
            snprintf(func_name, sizeof(func_name), "%s",
                     (const char *)sqlite3_column_text(st, 1));
        }
        sqlite3_finalize(st);
    }

    /* 标题 */
    snprintf(buf,sizeof(buf),"▸ Data Flow: call %s @ 0x%lx  [%s]",
             callee, (unsigned long)call_addr, func_name);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* x86-64 调用约定:
     *   用户函数 (System V ABI): rdi, rsi, rdx, rcx, r8, r9
     *   系统调用 (Linux ABI):    rdi, rsi, rdx, r10, r8, r9  (syscall 破坏 rcx)
     *   这里两者都查, 以覆盖两种场景 */
    static const char *arg_regs[] = {"rdi","rsi","rdx","rcx","r8","r9","r10",
                                      "edi","esi","edx","ecx","r8d","r9d","r10d", NULL};
    static const char *arg_names[] = {"Arg1","Arg2","Arg3","Arg4","Arg5","Arg6","Arg4(sys)"};

    /* 向前查最多 25 条指令, 找每个参数寄存器的最后一次写入 */
    sqlite3_prepare_v2(db->conn,
        "SELECT address, mnemonic, op_str FROM instructions"
        " WHERE address<=?1 AND address>=?1-160"
        " AND section=(SELECT section FROM instructions WHERE address=?1)"
        " ORDER BY address DESC LIMIT 30",
        -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);

    /* 收集前序指令 */
    uint64_t prev_addrs[30]; char prev_mn[30][32], prev_op[30][160];
    int nprev = 0;
    while (sqlite3_step(st) == SQLITE_ROW && nprev < 30) {
        prev_addrs[nprev] = (uint64_t)sqlite3_column_int64(st, 0);
        snprintf(prev_mn[nprev], sizeof(prev_mn[0]), "%s",
                 (const char *)sqlite3_column_text(st, 1));
        snprintf(prev_op[nprev], sizeof(prev_op[0]), "%s",
                 (const char *)sqlite3_column_text(st, 2));
        nprev++;
    }
    sqlite3_finalize(st);

    /* 对每个参数寄存器, 找最后一次写入 */
    int found_any = 0;
    for (int ai = 0; ai < 6; ai++) {
        int found = 0;
        for (int i = 0; i < nprev && !found; i++) {
            /* 跳过 call 指令本身 */
            if (prev_addrs[i] == call_addr) continue;
            /* 检查是否写入了参数寄存器 */
            const char *op = prev_op[i];
            /* 简单的操作数解析: 第一个 token 是目标 */
            int writes_to_arg = 0;
            for (int r = 0; arg_regs[r] && !writes_to_arg; r++) {
                /* 检查目标寄存器 */
                if (!strncmp(op, arg_regs[r], strlen(arg_regs[r]))) {
                    /* 确认后面是逗号或空格 (不是寄存器名的一部分, 例如 rdi vs rdib) */
                    const char *after = op + strlen(arg_regs[r]);
                    if (*after == ',' || *after == ' ' || *after == '\0')
                        writes_to_arg = 1;
                }
            }
            if (writes_to_arg) {
                /* 分析源操作数的性质 */
                const char *src = "?";
                int is_tainted = 0, is_stack = 0, is_imm = 0;
                const char *comma = strchr(op, ',');
                if (comma) {
                    src = comma + 1;
                    while (*src == ' ') src++;
                    /* 检测污点: 源来自 taint 函数调用 */
                    if (strstr(src, "rax") || strstr(src, "eax")) {
                        /* RAX 可能是调用返回值 → 查前面是否有 taint 调用 */
                        for (int j = i+1; j < nprev && !is_tainted; j++) {
                            if (!strcmp(prev_mn[j], "call")) {
                                /* 检查这个 call 是否调用了 taint 函数 */
                                sqlite3_stmt *ts = NULL;
                                sqlite3_prepare_v2(db->conn,
                                    "SELECT s.name FROM xrefs x JOIN symbols s"
                                    " ON x.to_addr=s.address"
                                    " WHERE x.from_addr=? AND x.ref_type='call'"
                                    " AND s.name IN ('read','recv','fgets','getenv',"
                                    " 'recvfrom','scanf','fread','gets') LIMIT 1",
                                    -1, &ts, NULL);
                                if (ts) {
                                    sqlite3_bind_int64(ts, 1, (sqlite3_int64)prev_addrs[j]);
                                    is_tainted = (sqlite3_step(ts) == SQLITE_ROW);
                                    sqlite3_finalize(ts);
                                }
                            }
                        }
                    }
                    if (strstr(src, "rsp") || strstr(src, "rbp"))
                        is_stack = 1;
                    if (*src == '0' || (*src >= '0' && *src <= '9')
                        || *src == '-' || *src == '+')
                        is_imm = 1;
                }

                const char *marker = is_tainted ? "\xe2\x86\x93 TAINTED" :
                                     is_stack  ? "[stack]" :
                                     is_imm    ? "[const]" : "[reg]";
                snprintf(buf,sizeof(buf),"%s (R%cI): %s %s  @ 0x%lx  %s",
                    arg_names[ai], ai==0?'D':'S', prev_mn[i], prev_op[i],
                    (unsigned long)prev_addrs[i], marker);
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)prev_addrs[i]);
                found = 1; found_any = 1;
            }
        }
        if (!found) {
            snprintf(buf,sizeof(buf),"%s: (not set in this basic block)",arg_names[ai]);
            fields_add(pd,buf,1,0,DETAIL_NONE,-1);
        }
    }

    /* ── 显示 call 前后的反汇编上下文 ── */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"\xe2\x94\x8c\xe2\x94\x80 Context (\xc2\xb15) \xe2\x94\x80\xe2\x94\x80",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(db->conn,
        "SELECT address,mnemonic,op_str FROM instructions"
        " WHERE address>=?1-32 AND address<=?1+32"
        " AND section=(SELECT section FROM instructions WHERE address=?1)"
        " ORDER BY address", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)call_addr);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
            const char *m = (const char *)sqlite3_column_text(st, 1);
            const char *o = (const char *)sqlite3_column_text(st, 2);
            snprintf(buf,sizeof(buf),"%s0x%lx  %-8s %s",
                a==call_addr?">":" ",(unsigned long)a,m?m:"?",o?o:"");
            fields_add(pd,buf,1,a==call_addr?1:0,DETAIL_NONE,(int)a);
        }
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"\xe2\x86\x93 TAINTED = from user input   [f]=trace args  [Enter]=jump  [h]=back",1,0,DETAIL_NONE,-1);
    return found_any ? 0 : -1;
}

/* ── 漏洞查询 ────────────────────────────────────────────────────── */

int db_vuln_count(AnalysisDB *db) {
    if (!db) return -1;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn, "SELECT COUNT(*) FROM vuln_candidates", -1, &st, NULL);
    if (!st) return -1;
    int c = 0;
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

int db_vuln_query(AnalysisDB *db, PanelData *pd) {
    if (!db || !pd) return -1;
    char buf[512];
    int total = db_vuln_count(db);

    snprintf(buf,sizeof(buf),"=== Vulnerability Scan ===  %d candidates", total);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"[Enter]=detail  [h]=back",1,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 按严重程度分组统计 */
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT severity, COUNT(*) FROM vuln_candidates"
        " GROUP BY severity ORDER BY"
        " CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1"
        " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END",
        -1, &st, NULL);
    if (st) {
        fields_add(pd,"── Summary ──",1,0,DETAIL_NONE,-1);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *sev = (const char *)sqlite3_column_text(st, 0);
            int cnt = sqlite3_column_int(st, 1);
            const char *icon = !strcmp(sev,"CRITICAL")?"\xf0\x9f\x94\xb4":
                               !strcmp(sev,"HIGH")?"\xf0\x9f\x9f\xa1":
                               !strcmp(sev,"MEDIUM")?"\xf0\x9f\x9f\xa2":"\xe2\x9a\xaa";
            snprintf(buf,sizeof(buf),"%s %-10s: %d", icon, sev, cnt);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
        }
        sqlite3_finalize(st);
    }
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 按地址显示 (带函数名和类型) */
    sqlite3_prepare_v2(db->conn,
        "SELECT v.address,v.vuln_type,v.severity,v.sink_func,v.description,"
        " COALESCE(f.name,'???') as fname"
        " FROM vuln_candidates v LEFT JOIN functions f ON v.function_addr=f.start_addr"
        " ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1"
        " WHEN 'MEDIUM' THEN 2 ELSE 3 END, v.address",
        -1, &st, NULL);
    if (st) {
        fields_add(pd,"── Candidates ──",1,0,DETAIL_NONE,-1);

        /* 列头 */
        snprintf(buf,sizeof(buf),"%-6s %-18s %-12s %s","Sev","Address","Type","Function");
        fields_add(pd,buf,1,0,DETAIL_NONE,-1);
        fields_add(pd,"────── ────────────────── ──────────── ──────────",1,0,DETAIL_NONE,-1);

        int n = 0;
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t addr = (uint64_t)sqlite3_column_int64(st, 0);
            const char *t = (const char *)sqlite3_column_text(st, 1);
            const char *s = (const char *)sqlite3_column_text(st, 2);
            const char *fn = (const char *)sqlite3_column_text(st, 3);
            const char *fname = (const char *)sqlite3_column_text(st, 5);
            const char *icon = !strcmp(s,"CRITICAL")?"\xf0\x9f\x94\xb4":
                               !strcmp(s,"HIGH")?"\xf0\x9f\x9f\xa1":
                               !strcmp(s,"MEDIUM")?"\xf0\x9f\x9f\xa2":"\xe2\x9a\xaa";
            snprintf(buf,sizeof(buf),"%s 0x%lx %-12s %s",
                icon,(unsigned long)addr,t?t:"?",fname?fname:"?");
            fields_add(pd,buf,1,1,DETAIL_NONE,(int)addr);
            n++;
        }
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"CRITICAL=fix now  HIGH=exploitable  MEDIUM=review  [Enter]=detail",1,0,DETAIL_NONE,-1);
    return total;
}

int db_vuln_detail(AnalysisDB *db, uint64_t addr, PanelData *pd) {
    if (!db || !pd) return -1;
    char buf[600];
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn,
        "SELECT v.vuln_type,v.severity,v.sink_func,v.description,"
        " COALESCE(f.name,'???') as fname, v.function_addr"
        " FROM vuln_candidates v LEFT JOIN functions f ON v.function_addr=f.start_addr"
        " WHERE v.address=?", -1, &st, NULL);
    if (!st) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }

    const char *type = (const char *)sqlite3_column_text(st, 0);
    const char *sev  = (const char *)sqlite3_column_text(st, 1);
    const char *sink = (const char *)sqlite3_column_text(st, 2);
    const char *desc = (const char *)sqlite3_column_text(st, 3);
    const char *fname= (const char *)sqlite3_column_text(st, 4);
    uint64_t faddr   = (uint64_t)sqlite3_column_int64(st, 5);
    sqlite3_finalize(st);

    /* 标题 */
    snprintf(buf,sizeof(buf),"\xe2\x9a\xa0 Vuln @ 0x%lx  %s  [%s]",
        (unsigned long)addr, sev?sev:"?", type?type:"?");
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"   Sink: %s  |  Func: %s (0x%lx)",
        sink?sink:"?",fname?fname:"?",(unsigned long)faddr);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 描述 */
    if (desc) { snprintf(buf,sizeof(buf),"   %s",desc); fields_add(pd,buf,1,0,DETAIL_NONE,-1); }
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 反汇编上下文 */
    fields_add(pd,"\xe2\x94\x8c\xe2\x94\x80\xe2\x94\x80 Disassembly Context \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80",1,0,DETAIL_NONE,-1);
    sqlite3_prepare_v2(db->conn,
        "SELECT address,mnemonic,op_str FROM instructions"
        " WHERE address>=?1-16 AND address<=?1+16"
        " AND section=(SELECT section FROM instructions WHERE address=?1)"
        " ORDER BY address", -1, &st, NULL);
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t a = (uint64_t)sqlite3_column_int64(st, 0);
            const char *m = (const char *)sqlite3_column_text(st, 1);
            const char *o = (const char *)sqlite3_column_text(st, 2);
            snprintf(buf,sizeof(buf),"%s0x%lx  %-8s %s",
                a==addr?">":" ",(unsigned long)a,m?m:"?",o?o:"");
            int sel = (a==addr)?1:0;
            fields_add(pd,buf,1,sel,DETAIL_NONE,(int)a);
        }
        sqlite3_finalize(st);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 Data Flow \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80",1,0,DETAIL_NONE,-1);

    /* 查找该地址前后指令中可能的 taint 源引用 */
    sqlite3_prepare_v2(db->conn,
        "SELECT t.address,t.source_func FROM taint_sources t"
        " WHERE t.address BETWEEN ?1-256 AND ?1+16", -1, &st, NULL);
    int has_taint = 0;
    if (st) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)addr);
        while (sqlite3_step(st) == SQLITE_ROW) {
            uint64_t ta = (uint64_t)sqlite3_column_int64(st, 0);
            const char *tf = (const char *)sqlite3_column_text(st, 1);
            snprintf(buf,sizeof(buf),"\xe2\x86\x93 Taint source: %s @ 0x%lx", tf, (unsigned long)ta);
            fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            has_taint++;
        }
        sqlite3_finalize(st);
    }
    if (!has_taint) fields_add(pd,"   (no taint source identified nearby)",2,0,DETAIL_NONE,-1);

    /* 调用者 → Sink 路径 */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"\xe2\x94\x8c\xe2\x94\x80 Callers of containing function \xe2\x94\x80\xe2\x94\x80",1,0,DETAIL_NONE,-1);
    if (faddr) {
        uint64_t callers[16];
        int nc = db_query_func_callers(db, faddr, callers, 16);
        if (nc > 0) {
            for (int i = 0; i < nc && i < 8; i++) {
                DbInsn ci;
                if (db_query_insn(db, callers[i], &ci) == 0)
                    snprintf(buf,sizeof(buf),"0x%lx  %s %s",
                        (unsigned long)callers[i],ci.mnemonic,ci.op_str);
                else
                    snprintf(buf,sizeof(buf),"0x%lx",(unsigned long)callers[i]);
                fields_add(pd,buf,2,0,DETAIL_NONE,-1);
            }
        } else fields_add(pd,"   (none)",2,0,DETAIL_NONE,-1);
    }

    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    fields_add(pd,"[h]=back [Enter]=jump to addr",1,0,DETAIL_NONE,-1);
    return 0;
}

int db_taint_for_addr(AnalysisDB *db, uint64_t addr, PanelData *pd) {
    if (!db || !pd) return -1;
    // Simplified: just show taint sources in the function
    return 0;
}

/* ── 工具: 解析 hex 查询 ──────────────────────────────────────────── */
static int parse_hex_query(const char *q, uint64_t *out)
{
    if (!q || !out) return -1;
    const char *p = q;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (!isxdigit((unsigned char)*p)) return -1;
    char *end = NULL;
    *out = strtoull(p, &end, 16);
    if (end == p) return -1;
    while (*end) { if (!isspace((unsigned char)*end)) return -1; end++; }
    return 0;
}

/* ── 全局搜索 ────────────────────────────────────────────────────── */

/* ── Query template executor (Strategy 2) ──────────────────────── */

static int db_query_template(sqlite3 *c, const char *q, int *total, PanelData *pd)
{
    char buf[640], sql[1024];
    sqlite3_stmt *st = NULL;
    int n = 0, start = *total;

    /* callers:NAME — 谁调用了这个函数 */
    if (strncmp(q, "callers:", 8) == 0) {
        snprintf(sql, sizeof(sql),
            "SELECT x.from_addr, f.name "
            "FROM xrefs x JOIN functions f ON f.start<=x.from AND f.end>x.from "
            "JOIN symbols s ON x.to_addr=s.address "
            "WHERE s.name='%s' AND x.ref_type='call' ORDER BY x.from_addr LIMIT 50",
            q + 8);
    }
    /* callees:ADDR — 这个函数调用了谁 */
    else if (strncmp(q, "callees:", 8) == 0) {
        uint64_t addr = strtoull(q + 8, NULL, 16);
        snprintf(sql, sizeof(sql),
            "SELECT x.to_addr, COALESCE(s.name,'?') FROM xrefs x "
            "LEFT JOIN symbols s ON x.to_addr=s.address "
            "WHERE x.from_addr BETWEEN (SELECT start_addr FROM functions "
            " WHERE start<=%lu AND end>%lu LIMIT 1) AND "
            "(SELECT end_addr FROM functions WHERE start<=%lu AND end>%lu LIMIT 1) "
            "AND x.ref_type='call' ORDER BY x.to_addr LIMIT 30",
            (unsigned long)addr, (unsigned long)addr,
            (unsigned long)addr, (unsigned long)addr);
    }
    /* xrefs_to:ADDR */
    else if (strncmp(q, "xrefs_to:", 9) == 0) {
        uint64_t addr = strtoull(q + 9, NULL, 16);
        snprintf(sql, sizeof(sql),
            "SELECT x.from_addr, x.ref_type FROM xrefs x "
            "WHERE x.to_addr=%lu ORDER BY x.from_addr LIMIT 40",
            (unsigned long)addr);
    }
    /* largest funcs */
    else if (strcmp(q, "largest") == 0 || strcmp(q, "largest funcs") == 0) {
        snprintf(sql, sizeof(sql),
            "SELECT start_addr, name, (end_addr-start_addr) AS sz, bb_count "
            "FROM functions ORDER BY sz DESC LIMIT 30");
    }
    /* most called */
    else if (strcmp(q, "most called") == 0 || strcmp(q, "hot") == 0) {
        snprintf(sql, sizeof(sql),
            "SELECT x.to_addr, COALESCE(s.name,'?'), COUNT(*) AS cnt "
            "FROM xrefs x LEFT JOIN symbols s ON x.to_addr=s.address "
            "WHERE x.ref_type='call' GROUP BY x.to_addr ORDER BY cnt DESC LIMIT 30");
    }
    /* dangerous calls */
    else if (strcmp(q, "dangerous") == 0 || strncmp(q, "danger", 6) == 0) {
        snprintf(sql, sizeof(sql),
            "SELECT i.address, s.name, f.name FROM instructions i "
            "JOIN xrefs x ON i.address=x.from_addr "
            "JOIN symbols s ON x.to_addr=s.address "
            "LEFT JOIN functions f ON f.start<=i.address AND f.end>i.address "
            "WHERE x.ref_type='call' AND s.name IN "
            "('strcpy','strcat','sprintf','gets','system','execve','popen',"
            "'memcpy','read','recv','printf','mprotect','dlopen') "
            "ORDER BY i.address LIMIT 50");
    }
    /* source→sink: recv→strcpy */
    else if (strchr(q, 0xe2) || strstr(q, "->")) {
        char src[64]="", snk[64]="";
        const char *arrow = strstr(q, "->") ? strstr(q, "->") : strstr(q, "\xe2\x86\x92");
        if (arrow) {
            size_t sl = (size_t)(arrow - q); if (sl > 60) sl = 60;
            memcpy(src, q, sl); src[sl] = 0;
            snprintf(snk, sizeof(snk), "%s", arrow + (strstr(q,"->")?2:3));
        }
        if (src[0] && snk[0]) {
            snprintf(sql, sizeof(sql),
                "SELECT DISTINCT f.start_addr, f.name FROM xrefs xs "
                "JOIN symbols ss ON xs.to_addr=ss.address AND ss.name='%s' "
                "JOIN instructions isrc ON xs.from_addr=isrc.address "
                "JOIN functions f ON f.start<=isrc.address AND f.end>isrc.address "
                "WHERE EXISTS (SELECT 1 FROM xrefs xk "
                " JOIN symbols sk ON xk.to_addr=sk.address AND sk.name='%s' "
                " JOIN instructions isnk ON xk.from_addr=isnk.address "
                " WHERE isnk.address BETWEEN f.start AND f.end) LIMIT 30",
                src, snk);
        } else return 0;
    }
    else return 0; /* 不是模板查询 */

    if (sqlite3_prepare_v2(c, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    while (sqlite3_step(st) == SQLITE_ROW && n < 200) {
        uint64_t a1 = (uint64_t)sqlite3_column_int64(st, 0);
        const char *t1 = (const char*)sqlite3_column_text(st, 1);
        int has_c3 = (sqlite3_column_count(st) >= 3);
        const char *t2 = has_c3 ? (const char*)sqlite3_column_text(st, 2) : NULL;
        int has_c4 = (sqlite3_column_count(st) >= 4);
        int c3 = has_c4 ? sqlite3_column_int(st, 3) : 0;

        (*total)++; n++;
        if (has_c4)
            snprintf(buf, sizeof(buf), "[%d] 0x%lx  %-40s  (%d calls)",
                *total, (unsigned long)a1, t1 ? t1 : "?", c3);
        else if (has_c3 && t2)
            snprintf(buf, sizeof(buf), "[%d] 0x%lx  → 0x...  %s",
                *total, (unsigned long)a1, t2);
        else
            snprintf(buf, sizeof(buf), "[%d] 0x%lx  %s",
                *total, (unsigned long)a1, t1 ? t1 : "?");
        fields_add(pd, buf, 1, 1, DETAIL_NONE, (int)(a1 & 0x7FFFFFFF));
    }
    sqlite3_finalize(st);
    if (n > 0) {
        snprintf(buf, sizeof(buf), "── %d result(s) for \"%s\"", n, q);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }
    return n;
}

int db_search(AnalysisDB *db, const char *query, PanelData *pd) {
    if (!db || !query || !pd) return -1;
    sqlite3 *c = db->conn;
    char buf[640], like[320];
    snprintf(like, sizeof(like), "%%%s%%", query);
    int total = 0;   /* 全局序号 */

    /* ── Strategy 2: 查询模板 (语法: callers:X / xrefs_to:ADDR / largest / most called / dangerous / src→snk) ── */
    fields_add(pd, "=== Search ===", 0, 0, DETAIL_NONE, -1);
    int tpl = db_query_template(c, query, &total, pd);
    if (tpl > 0) {
        snprintf(buf, sizeof(buf), "%d total results  [Enter]=details  [Space]=new search", total);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        return total;
    }

    /* 尝试解析为 hex 地址 / 立即数 */
    uint64_t hex_val = 0;
    int is_hex = (parse_hex_query(query, &hex_val) == 0);

    snprintf(buf,sizeof(buf),"=== Search: \"%s\" ===", query);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);

    /* ================================================================ */
    /* P0: 地址精确匹配 (instructions / symbols / strings / functions)   */
    /* ================================================================ */
    if (is_hex) {
        sqlite3_stmt *st=NULL; int n=0;

        /* 0a. instructions.address */
        sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str FROM instructions WHERE address=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  addr-insn  %s %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),sqlite3_column_text(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0b. symbols.address */
        sqlite3_prepare_v2(c,
            "SELECT address,name,type,bind FROM symbols WHERE address=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  addr-sym   %s [%s/%s]",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),
                    sqlite3_column_text(st,2),sqlite3_column_text(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0c. strings.address */
        sqlite3_prepare_v2(c,
            "SELECT address,value FROM strings WHERE address=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  addr-str   \"%s\"",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0d. functions.start_addr (also match range: addr in [start, end)) */
        sqlite3_prepare_v2(c,
            "SELECT start_addr,end_addr,name,bb_count FROM functions"
            " WHERE start_addr=? OR (start_addr<=? AND end_addr>?)",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            sqlite3_bind_int64(st,2,(sqlite3_int64)hex_val);
            sqlite3_bind_int64(st,3,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  addr-func  %s  %d BBs [0x%lx-0x%lx]",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,2),sqlite3_column_int(st,3),
                    (unsigned long)sqlite3_column_int64(st,0),
                    (unsigned long)sqlite3_column_int64(st,1));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0e. trace_blocks.bb_addr (debug) */
        sqlite3_prepare_v2(c,
            "SELECT session_id,bb_addr,exec_count FROM trace_blocks WHERE bb_addr=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  trace-bb   session=%d exec=%d",
                    total,(unsigned long)sqlite3_column_int64(st,1),
                    sqlite3_column_int(st,0),sqlite3_column_int(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0f. reg_snapshots.rip (debug) */
        sqlite3_prepare_v2(c,
            "SELECT step_num,rip FROM reg_snapshots WHERE rip=?",
            -1,&st,NULL);
        if(st){sqlite3_bind_int64(st,1,(sqlite3_int64)hex_val);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  reg-snap   step=%d",
                    total,(unsigned long)sqlite3_column_int64(st,1),
                    sqlite3_column_int(st,0));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)hex_val);n++;}
            sqlite3_finalize(st);}

        /* 0g. 立即数: ir_stmts.imm_value */
        {
            sqlite3_stmt *st2=NULL; int m=0;
            sqlite3_prepare_v2(c,
                "SELECT address,op_type,dst,imm_value FROM ir_stmts WHERE imm_value=?",
                -1,&st2,NULL);
            if(st2){sqlite3_bind_int64(st2,1,(sqlite3_int64)hex_val);
                while(sqlite3_step(st2)==SQLITE_ROW){total++;
                    snprintf(buf,sizeof(buf),"[%d] 0x%lx  imm       %s dst=%s val=0x%llx",
                        total,(unsigned long)sqlite3_column_int64(st2,0),
                        sqlite3_column_text(st2,1),sqlite3_column_text(st2,2),
                        (unsigned long long)sqlite3_column_int64(st2,3));
                    fields_add(pd,buf,1,1,DETAIL_NONE,
                        (int)sqlite3_column_int64(st2,0));m++;}
                if(m>0){snprintf(buf,sizeof(buf),"── %d immediate value match(es)",m);
                    fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
                sqlite3_finalize(st2);}
        }

        if(n>0){snprintf(buf,sizeof(buf),"── %d address match(es)",n);
            fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
    }

    /* ================================================================ */
    /* 1. Instructions — mnemonic exact match                           */
    /* ================================================================ */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str FROM instructions"
            " WHERE mnemonic=?", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,query,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){
                total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  insn      %-8s %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),sqlite3_column_text(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d exact mnemonic matches",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 2. Instructions — fuzzy ──────────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str FROM instructions"
            " WHERE mnemonic LIKE ?1 OR op_str LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){
                total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  insn      %-8s %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),sqlite3_column_text(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d fuzzy insn matches",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 3. Symbols ───────────────────────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,name,type,bind FROM symbols"
            " WHERE name LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){
                total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  sym       %-32s [%s/%s]",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),
                    sqlite3_column_text(st,2),sqlite3_column_text(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d symbol matches",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 4. Strings ───────────────────────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,value FROM strings"
            " WHERE value LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){
                total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  str       \"%s\"",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d string matches",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 5. Functions.name ────────────────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT start_addr,end_addr,name,bb_count FROM functions"
            " WHERE name LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){
                total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  func      %s  %d BBs",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,2),sqlite3_column_int(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d function matches",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 6. Sections / Segments ───────────────────────────────────── */
    {
        sqlite3_stmt *st=NULL; int n=0;

        /* 6a. sections.name */
        sqlite3_prepare_v2(c,
            "SELECT shdr_idx,name,addr,size,type,flags FROM sections"
            " WHERE name LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  section   %-24s  size=0x%lx type=%d",
                    total,(unsigned long)sqlite3_column_int64(st,2),
                    sqlite3_column_text(st,1),
                    (unsigned long)sqlite3_column_int64(st,3),
                    sqlite3_column_int(st,4));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int(st,0));n++;}
            sqlite3_finalize(st);}

        /* 6b. segments.type / flags */
        sqlite3_prepare_v2(c,
            "SELECT id,vaddr,memsz,type,flags FROM segments"
            " WHERE type LIKE ?1 OR flags LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  segment    %-8s %-8s  memsz=0x%lx",
                    total,(unsigned long)sqlite3_column_int64(st,1),
                    sqlite3_column_text(st,3),sqlite3_column_text(st,4),
                    (unsigned long)sqlite3_column_int64(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    sqlite3_column_int(st,0));n++;}
            sqlite3_finalize(st);}

        if(n>0){snprintf(buf,sizeof(buf),"── %d section/segment match(es)",n);
            fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
    }

    /* ── 7. IR statements (op_type) ───────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,op_type,dst,src,imm_value FROM ir_stmts"
            " WHERE op_type LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  ir-%-6s  dst=%-8s src=%s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    (const char*)sqlite3_column_text(st,1),
                    sqlite3_column_text(st,2)
                        ?(const char*)sqlite3_column_text(st,2):"-",
                    sqlite3_column_text(st,3)
                        ?(const char*)sqlite3_column_text(st,3):"-");
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d IR statement match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 8. Value definitions (def_type / target / source_desc) ───── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT def_addr,def_type,target,source_desc FROM value_defs"
            " WHERE def_type LIKE ?1 OR target LIKE ?1 OR source_desc LIKE ?1",
            -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  valdef    %-14s  %-12s  %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    (const char*)sqlite3_column_text(st,1),
                    sqlite3_column_text(st,2)
                        ?(const char*)sqlite3_column_text(st,2):"-",
                    sqlite3_column_text(st,3)
                        ?(const char*)sqlite3_column_text(st,3):"");
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d value-def match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 9. Call argument roles (arg_role) ────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT call_addr,arg_index,arg_role FROM call_args"
            " WHERE arg_role LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  call-arg  arg%d=%-14s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_int(st,1),sqlite3_column_text(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d call-arg match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 10. Taint sources (source_func / target_reg) ─────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,source_func,target_reg,function_addr FROM taint_sources"
            " WHERE source_func LIKE ?1 OR target_reg LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  taint     %-16s  reg=%-6s  func=0x%lx",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    (const char*)sqlite3_column_text(st,1),
                    sqlite3_column_text(st,2)
                        ?(const char*)sqlite3_column_text(st,2):"-",
                    (unsigned long)sqlite3_column_int64(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d taint source match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 11. Vulnerability candidates ─────────────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,vuln_type,severity,sink_func,description FROM vuln_candidates"
            " WHERE vuln_type LIKE ?1 OR sink_func LIKE ?1"
            " OR severity LIKE ?1 OR description LIKE ?1",
            -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  VULN     %-8s %-16s  %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,2),   /* severity */
                    sqlite3_column_text(st,3),   /* sink_func */
                    sqlite3_column_text(st,1));  /* vuln_type */
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d vulnerability match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 12. Instruction size exact match (when query is a small int) ── */
    if (is_hex && hex_val > 0 && hex_val <= 16) {
        int sz = (int)hex_val;
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str,size FROM instructions WHERE size=?",
            -1, &st, NULL);
        if(st){sqlite3_bind_int(st,1,sz);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  size=%-5d %-8s %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_int(st,3),
                    sqlite3_column_text(st,1),sqlite3_column_text(st,2));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d size-%d instruction(s)",n,sz);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 13. Heap chunks (debug — state LIKE) ─────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT addr,size,state,allocator FROM heap_chunks"
            " WHERE state LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  heap-chk  %-10s  size=0x%lx alloc=%s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    (const char*)sqlite3_column_text(st,2),
                    (unsigned long)sqlite3_column_int64(st,1),
                    sqlite3_column_text(st,3)
                        ?(const char*)sqlite3_column_text(st,3):"");
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d heap chunk match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 14. Heap anomalies (debug — type / desc) ──────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT chunk_addr,anomaly_type,severity,description FROM heap_anomalies"
            " WHERE anomaly_type LIKE ?1 OR description LIKE ?1"
            " OR severity LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  heap-ANOM %-8s %-14s  %s",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    (const char*)sqlite3_column_text(st,2),
                    (const char*)sqlite3_column_text(st,1),
                    sqlite3_column_text(st,3)
                        ?(const char*)sqlite3_column_text(st,3):"");
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d heap anomaly match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 15. Heap events (debug — event_type) ──────────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT chunk_addr,event_type,size,return_addr FROM heap_events"
            " WHERE event_type LIKE ?1", -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] 0x%lx  heap-evt  %-14s  size=0x%lx caller=0x%lx",
                    total,(unsigned long)sqlite3_column_int64(st,0),
                    sqlite3_column_text(st,1),
                    (unsigned long)sqlite3_column_int64(st,2),
                    (unsigned long)sqlite3_column_int64(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    (int)sqlite3_column_int64(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d heap event match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── 16. Trace sessions (debug — pid / backend) ────────────────── */
    {
        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT id,pid,backend,bb_count FROM trace_sessions"
            " WHERE CAST(pid AS TEXT) LIKE ?1 OR backend LIKE ?1",
            -1, &st, NULL);
        if(st){sqlite3_bind_text(st,1,like,-1,SQLITE_STATIC);
            int n=0;
            while(sqlite3_step(st)==SQLITE_ROW){total++;
                snprintf(buf,sizeof(buf),"[%d] #%d     trace-ses  pid=%d backend=%s %d BBs",
                    total,sqlite3_column_int(st,0),
                    sqlite3_column_int(st,1),
                    sqlite3_column_text(st,2)
                        ?(const char*)sqlite3_column_text(st,2):"",
                    sqlite3_column_int(st,3));
                fields_add(pd,buf,1,1,DETAIL_NONE,
                    sqlite3_column_int(st,0));n++;}
            if(n>0){snprintf(buf,sizeof(buf),"── %d trace session match(es)",n);
                fields_add(pd,buf,1,0,DETAIL_NONE,-1);}
            sqlite3_finalize(st);}
    }

    /* ── Footer ───────────────────────────────────────────────────── */
    if (total==0) fields_add(pd,"(no matches)",1,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"%d total results  [Enter]=details  [Space]=new search",total);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    return total;
}

/* ── Strategy 1: Crash Auto-Triage ─────────────────────────────── */

int db_crash_triage(AnalysisDB *db, const struct DebugState *ds,
                    uint64_t fault_addr, int signal,
                    uint64_t *regs, PanelData *pd)
{
    if (!db || !pd) return -1;
    char buf[512];
    fields_add(pd, "=== Crash Auto-Triage ===", 0, 0, DETAIL_NONE, -1);

    /* 崩溃类型判定 */
    if (signal == SIGSEGV) {
        if (fault_addr > 0x1000 && fault_addr < 0x7FFFFFFFFFFFULL)
            snprintf(buf, sizeof(buf), "SIGSEGV @ 0x%lx — invalid memory access", (unsigned long)fault_addr);
        else if (fault_addr == 0x4141414141414141ULL || fault_addr == 0x4242424242424242ULL)
            snprintf(buf, sizeof(buf), "SIGSEGV @ 0x%lx — RIP control confirmed (user value)", (unsigned long)fault_addr);
        else if (fault_addr < 0x1000)
            snprintf(buf, sizeof(buf), "SIGSEGV @ 0x%lx — NULL/guard page dereference", (unsigned long)fault_addr);
        else
            snprintf(buf, sizeof(buf), "SIGSEGV @ 0x%lx", (unsigned long)fault_addr);
    } else if (signal == SIGABRT)
        snprintf(buf, sizeof(buf), "SIGABRT — abort() or assert() failure");
    else if (signal == SIGILL)
        snprintf(buf, sizeof(buf), "SIGILL — illegal instruction (possible ROP/JOP failure)");
    else if (signal == SIGBUS)
        snprintf(buf, sizeof(buf), "SIGBUS — unaligned access or mmap failure");
    else if (signal == SIGFPE)
        snprintf(buf, sizeof(buf), "SIGFPE — arithmetic exception (div-by-zero?)");
    else
        snprintf(buf, sizeof(buf), "Signal %d @ 0x%lx", signal, (unsigned long)fault_addr);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 寄存器溯源 (对 RDI, RSI, RDX, RAX) */
    if (regs && db) {
        sqlite3 *c = db->conn;
        static const char *rnames[] = {"rdi","rsi","rdx","rax","rcx","r8","r9",NULL};
        /* struct user_regs_struct 索引: r15=0..r12=3,rbp=4,rbx=5,r11=6,r10=7,r9=8,r8=9,rax=10,rcx=11,rdx=12,rsi=13,rdi=14 */
        static int ridx[] = {14,13,12,10,11,9,8};
        fields_add(pd, "── Register Source Trace ──", 1, 0, DETAIL_NONE, -1);
        for (int ri = 0; rnames[ri]; ri++) {
            uint64_t rv = regs[ridx[ri]];
            if (rv < 0x1000) {
                snprintf(buf, sizeof(buf), "%s = 0x%lx (small — no trace)", rnames[ri], (unsigned long)rv);
                fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
                continue;
            }
            /* 检查是否是用户可控值 (0x4141.. / 0x4242..) */
            int controlled = (rv == 0x4141414141414141ULL || rv == 0x4242424242424242ULL ||
                              (rv & 0xFFFFFFFF00000000ULL) == 0x4141414100000000ULL);
            /* 追踪最近定义 */
            sqlite3_stmt *st = NULL;
            sqlite3_prepare_v2(c,
                "SELECT ir2.address, i2.mnemonic, i2.op_str, ?1-ir2.address "
                "FROM ir_stmts ir1 JOIN ir_stmts ir2 ON ir1.dst=ir2.dst AND ir2.op_type='reg_write' "
                "JOIN instructions i2 ON ir2.address=i2.address "
                "WHERE ir1.address=?1 AND ir1.op_type='reg_read' AND ir1.dst=?2 "
                "AND ir2.address<?1 ORDER BY ir2.address DESC LIMIT 1",
                -1, &st, NULL);
            if (st) {
                sqlite3_bind_int64(st, 1, (sqlite3_int64)fault_addr);
                sqlite3_bind_text(st, 2, rnames[ri], -1, SQLITE_STATIC);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    uint64_t def_a = (uint64_t)sqlite3_column_int64(st, 0);
                    const char *mn = (const char*)sqlite3_column_text(st, 1);
                    const char *op = (const char*)sqlite3_column_text(st, 2);
                    int dist = sqlite3_column_int(st, 3);
                    snprintf(buf, sizeof(buf), "%s = 0x%lx ← %s %s @ 0x%lx (-%d)%s",
                        rnames[ri], (unsigned long)rv,
                        mn ? mn : "?", op ? op : "?", (unsigned long)def_a, dist,
                        controlled ? " [USER-CTRL]" : "");
                } else {
                    snprintf(buf, sizeof(buf), "%s = 0x%lx (no local def — likely arg)%s",
                        rnames[ri], (unsigned long)rv, controlled ? " [USER-CTRL]" : "");
                }
                sqlite3_finalize(st);
            }
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
    }

    /* 调用核心导航 */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "── Disassembly Context ──", 1, 0, DETAIL_NONE, -1);
    return db_query_addr_all(db, fault_addr, ds, pd, 0);
}

/* ── 工具 ────────────────────────────────────────────────────────── */

int db_insn_count(AnalysisDB *db) {
    if (!db) return -1;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn, "SELECT COUNT(*) FROM instructions", -1, &st, NULL);
    if (!st) return -1;
    int c = 0;
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

int db_snapshot_count(AnalysisDB *db) {
    if (!db) return -1;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn, "SELECT COUNT(*) FROM reg_snapshots", -1, &st, NULL);
    if (!st) return -1;
    int c = 0;
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

int db_func_count(AnalysisDB *db) {
    if (!db) return -1;
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(db->conn, "SELECT COUNT(*) FROM functions", -1, &st, NULL);
    if (!st) return -1;
    int c = 0;
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

int db_export(AnalysisDB *db, const char *path) {
    if (!db || !path) return -1;
    sqlite3 *fd = NULL;
    if (sqlite3_open(path, &fd) != SQLITE_OK) return -1;
    sqlite3_backup *bk = sqlite3_backup_init(fd, "main", db->conn, "main");
    if (!bk) { sqlite3_close(fd); return -1; }
    sqlite3_backup_step(bk, -1);
    sqlite3_backup_finish(bk);
    sqlite3_close(fd);
    return 0;
}
