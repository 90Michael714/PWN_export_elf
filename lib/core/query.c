/*
 * query.c — 分析数据总线实现
 *
 * query_open 时建立索引:
 *   1. 符号表 → 按地址排序数组 (二分查找 query_symbol)
 *   2. 节信息 → 地址范围数组 (query_section)
 *   3. GOT 条目 → 地址映射 (query_got)
 *
 * Capstone handle 惰性初始化, 全局复用。
 * 所有查询只读, 无锁设计 (调用者负责不并发修改 QueryDB)。
 */

#include "core/query.h"
#include "disasm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================== */
/* 内部数据结构                                                       */
/* ================================================================== */

#define MAX_SYMS    65536
#define MAX_SECTIONS 128
#define MAX_GOT      4096

/* 符号索引条目 (按地址排序) */
typedef struct {
    uint64_t addr;
    uint32_t str_off;       /* 字符串表偏移 */
    uint16_t shndx;
    uint8_t  info;          /* st_info (bind+type) */
    uint8_t  table_id;      /* 0=symtab, 1=dynsym */
} SymEntry;

/* 节信息条目 */
typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
    int      shdr_idx;
} SecEntry;

/* GOT 条目 */
typedef struct {
    uint64_t got_addr;
    uint32_t sym_name_off;  /* 字符串表偏移 */
} GotEntry;

struct QueryDB {
    Elf64_Ctx    *ctx;
    char         *strtab;         /* dynstr 或 strtab 全部内容 */
    size_t        strtab_size;
    Elf64_Off     strtab_offset;

    /* 符号索引 */
    SymEntry     *syms;
    int           nsyms;
    int           syms_cap;

    /* 节索引 */
    SecEntry      secs[MAX_SECTIONS];
    int           nsecs;

    /* GOT 索引 */
    GotEntry      gots[MAX_GOT];
    int           ngots;

    /* Capstone 缓存 */
    disasm_ctx   *disasm;
};

/* ================================================================== */
/* 辅助: 符号排序 (按地址升序)                                        */
/* ================================================================== */

static int sym_cmp(const void *a, const void *b) {
    const SymEntry *sa = a, *sb = b;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return 1;
    return 0;
}

/* ================================================================== */
/* 索引构建                                                           */
/* ================================================================== */

static void index_sections(QueryDB *db)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr*)db->ctx->map;
    db->nsecs = 0;
    for (int i = 0; i < eh->e_shnum && db->nsecs < MAX_SECTIONS; i++) {
        Elf64_Shdr *sh = elf_get_shdr(db->ctx, i);
        if (!sh || sh->sh_size == 0) continue;
        SecEntry *se = &db->secs[db->nsecs++];
        se->start   = sh->sh_addr;
        se->end     = sh->sh_addr + sh->sh_size;
        se->flags   = sh->sh_flags;
        se->shdr_idx = i;
    }
}

static void index_symbols(QueryDB *db)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr*)db->ctx->map;
    db->nsyms = 0;
    db->syms_cap = 4096;
    db->syms = malloc((size_t)db->syms_cap * sizeof(SymEntry));

    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_SYMTAB : SHT_DYNSYM;
        for (int i = 0; i < eh->e_shnum; i++) {
            Elf64_Shdr *sh = elf_get_shdr(db->ctx, i);
            if (!sh || sh->sh_type != want || sh->sh_size == 0) continue;
            Elf64_Shdr *strsh = elf_get_shdr(db->ctx, sh->sh_link);
            if (!strsh || strsh->sh_size == 0) continue;

            /* 记住字符串表 */
            if (!db->strtab) {
                db->strtab = (char*)(db->ctx->map + strsh->sh_offset);
                db->strtab_size = strsh->sh_size;
                db->strtab_offset = strsh->sh_offset;
            }

            Elf64_Sym *raw = (Elf64_Sym*)(db->ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym && db->nsyms < MAX_SYMS; j++) {
                if (raw[j].st_value == 0) continue;
                if (db->nsyms >= db->syms_cap) {
                    db->syms_cap *= 2;
                    db->syms = realloc(db->syms, (size_t)db->syms_cap * sizeof(SymEntry));
                }
                SymEntry *se = &db->syms[db->nsyms++];
                se->addr     = raw[j].st_value;
                se->str_off  = raw[j].st_name;
                se->shndx    = raw[j].st_shndx;
                se->info     = raw[j].st_info;
                se->table_id = (uint8_t)pass;
            }
        }
    }

    /* 按地址排序 */
    qsort(db->syms, (size_t)db->nsyms, sizeof(SymEntry), sym_cmp);
}

static void index_got(QueryDB *db)
{
    db->ngots = 0;
    Elf64_Ehdr *eh = (Elf64_Ehdr*)db->ctx->map;

    /* 找 .rela.plt → GOT 地址映射 */
    for (int i = 0; i < eh->e_shnum && db->ngots < MAX_GOT; i++) {
        Elf64_Shdr *sh = elf_get_shdr(db->ctx, i);
        if (!sh || sh->sh_type != SHT_RELA || sh->sh_size == 0) continue;
        const char *sn = elf_section_name(db->ctx, i);
        if (!sn || !strstr(sn, ".rela.plt")) continue;

        /* 找关联的 .dynsym */
        Elf64_Shdr *ds = elf_get_shdr(db->ctx, sh->sh_link);
        if (!ds || ds->sh_type != SHT_DYNSYM) continue;
        Elf64_Shdr *dstr = elf_get_shdr(db->ctx, ds->sh_link);
        if (!dstr) continue;

        Elf64_Rela *rela = (Elf64_Rela*)(db->ctx->map + sh->sh_offset);
        Elf64_Sym  *syms = (Elf64_Sym*)(db->ctx->map + ds->sh_offset);
        int nr = (int)(sh->sh_size / sizeof(Elf64_Rela));

        for (int r = 0; r < nr && db->ngots < MAX_GOT; r++) {
            uint32_t si = (uint32_t)(rela[r].r_info >> 32);
            if (si >= ds->sh_size / sizeof(Elf64_Sym)) continue;
            db->gots[db->ngots].got_addr = rela[r].r_offset;
            db->gots[db->ngots].sym_name_off = syms[si].st_name;
            db->ngots++;
        }
    }
}

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

QueryDB* query_open(Elf64_Ctx *ctx)
{
    if (!ctx || !ctx->map) return NULL;
    QueryDB *db = calloc(1, sizeof(QueryDB));
    if (!db) return NULL;
    db->ctx = ctx;

    index_sections(db);
    index_symbols(db);
    index_got(db);
    return db;
}

void query_close(QueryDB *db)
{
    if (!db) return;
    if (db->disasm) disasm_close(db->disasm);
    free(db->syms);
    free(db);
}

/* ── 反汇编 (惰性初始化 Capstone) ──────────────────────────────── */

int query_disasm(QueryDB *db, uint64_t addr, char *mnemonic, size_t msz,
                 char *ops, size_t osz)
{
    if (!db || !mnemonic || !ops) return -1;

    /* 惰性初始化 Capstone */
    if (!db->disasm) {
        db->disasm = disasm_open();
        if (!db->disasm) return -1;
    }

    /* 从 ELF 文件中找到包含该地址的节 */
    uint8_t code[16];
    const uint8_t *src = NULL;
    size_t len = 0;

    for (int i = 0; i < db->nsecs; i++) {
        if (addr >= db->secs[i].start && addr < db->secs[i].end) {
            Elf64_Shdr *sh = elf_get_shdr(db->ctx, db->secs[i].shdr_idx);
            uint64_t off = addr - sh->sh_addr;
            if (off + 15 < sh->sh_size) {
                src = db->ctx->map + sh->sh_offset + off;
                len = sh->sh_size - off;
                if (len > 15) len = 15;
            }
            break;
        }
    }

    if (!src || len == 0) {
        snprintf(mnemonic, msz, "?");
        ops[0] = '\0';
        return -1;
    }

    /* 解码一条指令 */
    const uint8_t *cp = src;
    size_t cs = len;
    uint64_t ca = addr;
    if (disasm_next(db->disasm, &cp, &cs, &ca)) {
        cs_insn *in = disasm_insn(db->disasm);
        snprintf(mnemonic, msz, "%s", in->mnemonic);
        snprintf(ops, osz, "%s", in->op_str);
        return 0;
    }
    snprintf(mnemonic, msz, "?");
    ops[0] = '\0';
    return -1;
}

/* ── 符号查询 (二分查找) ──────────────────────────────────────── */

int query_symbol(QueryDB *db, uint64_t addr, char *name, size_t nsz,
                 int64_t *offset)
{
    if (!db || db->nsyms == 0) return -1;
    if (offset) *offset = 0;

    /* 二分查找: 找 <= addr 的最大符号 */
    int lo = 0, hi = db->nsyms - 1;
    int best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (db->syms[mid].addr <= addr) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    if (best < 0) return -1;

    SymEntry *se = &db->syms[best];
    if (db->strtab && se->str_off < db->strtab_size) {
        const char *sn = db->strtab + se->str_off;
        if (sn[0]) {
            strncpy(name, sn, nsz - 1);
            name[nsz - 1] = '\0';
            if (offset) *offset = (int64_t)(addr - se->addr);
            return 0;
        }
    }
    return -1;
}

int query_sym_by_name(QueryDB *db, const char *name, uint64_t *addr)
{
    if (!db || !name || !addr) return -1;
    /* 名字查询不依赖内存索引 (st_value==0 被过滤 + strtab 可能错位),
     * 直接扫描 .dynsym + .symtab 原始表, 保证准确。
     * 注意: .dynsym 中的导入函数名带版本后缀 (如 memcpy@@GLIBC_2.14),
     * 需要截断 '@' 后再比对。 */
    Elf64_Ehdr *eh = (Elf64_Ehdr *)db->ctx->map;
    for (int pass = 0; pass < 2; pass++) {
        Elf64_Word want = (pass == 0) ? SHT_DYNSYM : SHT_SYMTAB;
        for (int si = 0; si < eh->e_shnum; si++) {
            Elf64_Shdr *sh = elf_get_shdr(db->ctx, si);
            if (!sh || sh->sh_type != want || sh->sh_size == 0) continue;
            Elf64_Shdr *stsh = elf_get_shdr(db->ctx, sh->sh_link);
            if (!stsh) continue;
            Elf64_Sym *raw = (Elf64_Sym *)(db->ctx->map + sh->sh_offset);
            int nsym = (int)(sh->sh_size / sizeof(Elf64_Sym));
            for (int j = 0; j < nsym; j++) {
                const char *sn = elf_strtab_get(db->ctx,
                    stsh->sh_offset, raw[j].st_name);
                if (!sn) continue;
                /* 精确匹配 */
                if (!strcmp(sn, name)) {
                    *addr = raw[j].st_value;
                    return 0;
                }
                /* 版本后缀匹配: memcpy@@GLIBC_2.14 → 截断 @ 后比较 */
                const char *at = strchr(sn, '@');
                if (at) {
                    size_t base_len = (size_t)(at - sn);
                    if (strlen(name) == base_len &&
                        !strncmp(sn, name, base_len)) {
                        *addr = raw[j].st_value;
                        return 0;
                    }
                }
            }
        }
    }
    return -1;
}

int query_sym_count(QueryDB *db) { return db ? db->nsyms : 0; }

int query_sym_by_index(QueryDB *db, int idx, uint64_t *addr,
                       char *name, size_t nsz, unsigned char *info)
{
    if (!db || idx < 0 || idx >= db->nsyms) return -1;
    *addr = db->syms[idx].addr;
    *info = db->syms[idx].info;
    const char *sn = db->strtab + db->syms[idx].str_off;
    if (sn) { strncpy(name, sn, nsz - 1); name[nsz - 1] = '\0'; }
    return 0;
}

/* ── 节查询 ───────────────────────────────────────────────────── */

int query_section(QueryDB *db, uint64_t addr, const char **sec_name,
                  uint64_t *sh_flags)
{
    if (!db) return -1;
    for (int i = 0; i < db->nsecs; i++) {
        if (addr >= db->secs[i].start && addr < db->secs[i].end) {
            if (sec_name)
                *sec_name = elf_section_name(db->ctx, db->secs[i].shdr_idx);
            if (sh_flags) *sh_flags = db->secs[i].flags;
            return 0;
        }
    }
    return -1;
}

/* ── GOT 查询 ─────────────────────────────────────────────────── */

int query_got(QueryDB *db, uint64_t got_addr, const char **sym_name)
{
    if (!db || !sym_name) return -1;
    for (int i = 0; i < db->ngots; i++) {
        if (db->gots[i].got_addr == got_addr) {
            if (db->strtab && db->gots[i].sym_name_off < db->strtab_size)
                *sym_name = db->strtab + db->gots[i].sym_name_off;
            else
                *sym_name = "?";
            return 0;
        }
    }
    return -1;
}

/* ── 交叉引用 (预留) ──────────────────────────────────────────── */

int query_xrefs(QueryDB *db, uint64_t addr, uint64_t *refs, int max)
{
    (void)db; (void)addr; (void)refs; (void)max;
    return 0;  /* Phase 7 实现 */
}
