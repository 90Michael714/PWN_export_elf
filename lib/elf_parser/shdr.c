/*
 * shdr.c — Section Headers 解析
 *
 * parse_shdr_list:  左侧面板节列表
 * parse_shdr_detail: 中间面板 — 节概览 (ELF字段 + DB内容统计)
 *
 * 中间面板选中可选项 → 右侧面板显示 DB 查询详情
 * (通过 tui_input.c 中已有的 Enter 处理器)
 */

#include "elf_parser.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern AnalysisDB *g_active_db;

int parse_shdr_list(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;
    int shnum = ehdr->e_shnum;
    char flags_buf[32];

    fields_add(pd, "=== Section Headers ===", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        const char *name = elf_section_name(ctx, i);
        char buf[256];

        snprintf(buf, sizeof(buf), "[%02d] %-24s  %s  %s  size=0x%lX",
                 i, name,
                 elf_sh_type_str(sh->sh_type),
                 elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf)),
                 (unsigned long)sh->sh_size);
        fields_add(pd, buf, 0, 1, DETAIL_SHDR, i);
    }

    return pd->count;
}

int parse_shdr_detail(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    const char *name = elf_section_name(ctx, shdr_idx);
    char flags_buf[32];
    char buf[512];

    /* ── 标题 ── */
    snprintf(buf, sizeof(buf), "=== Section [%02d]: %s ===", shdr_idx, name);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* ── ELF 节头字段 ── */
    fields_add(pd, "── ELF Section Header ──", 0, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_name:      0x%08X (\"%s\")", sh->sh_name, name);
    fields_add(pd, buf, 1, 1, DETAIL_SHDR, shdr_idx);

    snprintf(buf, sizeof(buf), "sh_type:      0x%08X — %s",
             sh->sh_type, elf_sh_type_str(sh->sh_type));
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf));
    snprintf(buf, sizeof(buf), "sh_flags:     0x%lX (%s)",
             (unsigned long)sh->sh_flags, flags_buf);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addr:      0x%lX  (virtual address in memory)",
             (unsigned long)sh->sh_addr);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_offset:    0x%lX  (%lu bytes into file)",
             (unsigned long)sh->sh_offset, (unsigned long)sh->sh_offset);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_size:      0x%lX  (%lu bytes)",
             (unsigned long)sh->sh_size, (unsigned long)sh->sh_size);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_addralign: 0x%lX", (unsigned long)sh->sh_addralign);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (sh->sh_entsize > 0) {
        int entries = (int)(sh->sh_size / sh->sh_entsize);
        snprintf(buf, sizeof(buf), "sh_entsize:   %lu  →  %d entries",
                 (unsigned long)sh->sh_entsize, entries);
    } else {
        snprintf(buf, sizeof(buf), "sh_entsize:   %lu  (no fixed-size entries)",
                 (unsigned long)sh->sh_entsize);
    }
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    snprintf(buf, sizeof(buf), "sh_link:      %d  sh_info: %d", sh->sh_link, sh->sh_info);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* ── sh_link/sh_info 解读 ── */
    switch (sh->sh_type) {
        case SHT_SYMTAB: case SHT_DYNSYM:
            snprintf(buf, sizeof(buf), "→ link=[%d]=strtab, info=[%d]=1st non-local",
                     sh->sh_link, sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_RELA: case SHT_REL:
            snprintf(buf, sizeof(buf), "→ link=[%d]=symtab, info=[%d]=target section",
                     sh->sh_link, sh->sh_info);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_DYNAMIC:
            snprintf(buf, sizeof(buf), "→ link=[%d]=dynstr", sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
        case SHT_HASH: case SHT_GNU_HASH:
            snprintf(buf, sizeof(buf), "→ link=[%d]=dynsym", sh->sh_link);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1); break;
    }

    /* ═════════════════════════════════════════════════════════════
     * DB 内容统计 (如果有 DB)
     * ═════════════════════════════════════════════════════════════ */
    if (g_active_db && sh->sh_addr > 0 && sh->sh_size > 0) {
        sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
        if (c) {
            uint64_t low = sh->sh_addr, high = sh->sh_addr + sh->sh_size;

            fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
            fields_add(pd, "── Section Contents (from analysis DB) ──", 0, 0, DETAIL_NONE, -1);

            /* 指令数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM instructions WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int ic = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Instructions:  %d", ic);
                        fields_add(pd, buf, 1, ic > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 函数数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM functions WHERE start_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int fc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Functions:     %d", fc);
                        fields_add(pd, buf, 1, fc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 符号数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM symbols WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int sc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Symbols:       %d", sc);
                        fields_add(pd, buf, 1, sc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 字符串数 (.rodata 等) */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM strings WHERE address BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int strc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Strings:       %d", strc);
                        fields_add(pd, buf, 1, strc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 基本块数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM basic_blocks WHERE start_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int bbc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  Basic Blocks:  %d", bbc);
                        fields_add(pd, buf, 1, bbc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 交叉引用数 */
            {
                sqlite3_stmt *st = NULL;
                sqlite3_prepare_v2(c,
                    "SELECT COUNT(*) FROM xrefs WHERE from_addr BETWEEN ?1 AND ?2",
                    -1, &st, NULL);
                if (st) {
                    sqlite3_bind_int64(st, 1, (sqlite3_int64)low);
                    sqlite3_bind_int64(st, 2, (sqlite3_int64)high);
                    if (sqlite3_step(st) == SQLITE_ROW) {
                        int xrc = sqlite3_column_int(st, 0);
                        snprintf(buf, sizeof(buf), "  XRefs (out):   %d", xrc);
                        fields_add(pd, buf, 1, xrc > 0 ? 1 : 0, DETAIL_NONE, -1);
                    }
                    sqlite3_finalize(st);
                }
            }

            /* 字节范围 */
            snprintf(buf, sizeof(buf), "  Address range: 0x%lx — 0x%lx  (%lu bytes)",
                     (unsigned long)low, (unsigned long)high, (unsigned long)sh->sh_size);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    } else if (sh->sh_addr > 0 && sh->sh_size > 0) {
        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        snprintf(buf, sizeof(buf), "(DB not available — import ELF first for content stats)");
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }

    /* ── 底部: 常用操作提示 ── */
    if (sh->sh_type == SHT_PROGBITS && (sh->sh_flags & 4 /* SHF_EXECINSTR */)) {
        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        fields_add(pd, "→ Use Code Analysis → Disasm for full disassembly", 1, 0, DETAIL_NONE, -1);
    }

    return pd->count;
}

/*
 * parse_shdr_detail_full — 增强版: 头字段 + DB统计 + 实际内容
 *
 * 在 parse_shdr_detail 的基础上, 进一步展示:
 *   DB 有数据 → 查询列出指令/符号/字符串 (前 500 条)
 *   无 DB 数据 → 从 mmap 读取原始字节 hexdump
 */
int parse_shdr_detail_full(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    /* 先显示头字段 + DB 统计 */
    parse_shdr_detail(ctx, shdr_idx, pd);

    /* 再显示详细内容 (指令/符号/字符串/hexdump) */
    parse_shdr_detail_right(ctx, shdr_idx, pd);
    return pd->count;
}

/*
 * parse_shdr_detail_right — 节详细内容 (指令/符号/字符串/hexdump)
 *
 * 从 DB 或 mmap 读取节的详细内容, 用于填充右面板。
 * 不包括 ELF 节头字段 (那些由 parse_shdr_detail 处理)。
 */
int parse_shdr_detail_right(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    char buf[512];

    if (!sh || sh->sh_size == 0) return pd->count;

    uint64_t low  = sh->sh_addr;
    uint64_t high = sh->sh_addr + sh->sh_size;

    /* 标题 */
    const char *name = elf_section_name(ctx, shdr_idx);
    snprintf(buf, sizeof(buf), "=== Section [%02d]: %s — Contents ===", shdr_idx, name);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* DB 内容展示 */
    if (g_active_db && low > 0) {
        sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
        if (c) {
            int shown = 0;

            /* 指令 */
            { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
                "SELECT COUNT(*) FROM instructions WHERE address BETWEEN ?1 AND ?2",
                -1,&st,NULL);
              if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)low); sqlite3_bind_int64(st,2,(sqlite3_int64)high);
                if(sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_int(st,0)>0){
                    sqlite3_stmt *is=NULL; sqlite3_prepare_v2(c,
                        "SELECT address,mnemonic,op_str FROM instructions "
                        "WHERE address BETWEEN ?1 AND ?2 ORDER BY address LIMIT 500",
                        -1,&is,NULL);
                    if(is){ sqlite3_bind_int64(is,1,(sqlite3_int64)low); sqlite3_bind_int64(is,2,(sqlite3_int64)high);
                      while(sqlite3_step(is)==SQLITE_ROW){
                        if(!shown){fields_add(pd,"",0,0,DETAIL_NONE,-1);
                         fields_add(pd,"── Instructions ────────────────────────────",0,0,DETAIL_NONE,-1); shown=1;}
                        uint64_t ia=(uint64_t)sqlite3_column_int64(is,0);
                        const char *mn=(const char*)sqlite3_column_text(is,1);
                        const char *op=(const char*)sqlite3_column_text(is,2);
                        snprintf(buf,sizeof(buf),"  0x%lx: %-8s %s",(unsigned long)ia,mn?mn:"?",op?op:"");
                        fields_add(pd,buf,1,1,DETAIL_NONE,(int)(ia&0x7FFFFFFF)); }
                      sqlite3_finalize(is); } }
                sqlite3_finalize(st); } }

            /* 符号 */
            { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
                "SELECT address,name,type,bind,size FROM symbols "
                "WHERE address BETWEEN ?1 AND ?2 ORDER BY address LIMIT 500",
                -1,&st,NULL);
              if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)low); sqlite3_bind_int64(st,2,(sqlite3_int64)high); int n=0;
                while(sqlite3_step(st)==SQLITE_ROW&&n<500){
                    if(!shown){fields_add(pd,"",0,0,DETAIL_NONE,-1);
                     fields_add(pd,"── Symbols ────────────────────────",0,0,DETAIL_NONE,-1); shown=1;}
                    uint64_t sa=(uint64_t)sqlite3_column_int64(st,0);
                    const char *nm=(const char*)sqlite3_column_text(st,1);
                    const char *tp=(const char*)sqlite3_column_text(st,2);
                    const char *bd=(const char*)sqlite3_column_text(st,3);
                    int sz=sqlite3_column_int(st,4);
                    snprintf(buf,sizeof(buf),"  0x%lx %-32s %-6s %-6s %5d",(unsigned long)sa,nm?nm:"?",tp?tp:"?",bd?bd:"",sz);
                    fields_add(pd,buf,1,1,DETAIL_NONE,(int)(sa&0x7FFFFFFF)); n++; }
                sqlite3_finalize(st); } }

            /* 字符串 */
            { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
                "SELECT address,value,length FROM strings "
                "WHERE address BETWEEN ?1 AND ?2 ORDER BY address LIMIT 500",
                -1,&st,NULL);
              if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)low); sqlite3_bind_int64(st,2,(sqlite3_int64)high); int n=0;
                while(sqlite3_step(st)==SQLITE_ROW&&n<500){
                    if(!shown){fields_add(pd,"",0,0,DETAIL_NONE,-1);
                     fields_add(pd,"── Strings ─────────────────────────",0,0,DETAIL_NONE,-1); shown=1;}
                    uint64_t sa=(uint64_t)sqlite3_column_int64(st,0);
                    const char *val=(const char*)sqlite3_column_text(st,1);
                    int len=sqlite3_column_int(st,2);
                    char pv[48]=""; if(val){int pp=0; for(const char *s=val;*s&&pp<44;s++){
                        if(*s=='\n'){pv[pp++]='\\';pv[pp++]='n';}
                        else if((unsigned char)*s>=32&&(unsigned char)*s<127)pv[pp++]=*s;} pv[pp]=0;}
                    snprintf(buf,sizeof(buf),"  0x%lx \"%s\"%s (%dB)",(unsigned long)sa,pv,(val&&(int)strlen(val)>44)?"...":"",len);
                    fields_add(pd,buf,1,1,DETAIL_NONE,(int)(sa&0x7FFFFFFF)); n++; }
                sqlite3_finalize(st); } }

            if (shown) return pd->count;
        }
    }

    /* mmap hexdump (DB 中无数据时) */
    if (sh->sh_offset > 0 && sh->sh_size > 0 && sh->sh_size < 0x100000) {
        const uint8_t *data = ctx->map + sh->sh_offset;
        size_t dump_sz = sh->sh_size < 4096 ? sh->sh_size : 4096;
        fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
        snprintf(buf, sizeof(buf), "── Raw Hexdump (first %zu of %lu B) ──", dump_sz, (unsigned long)sh->sh_size);
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        for (size_t off = 0; off < dump_sz; off += 16) {
            char hx[100]; int hp = 0;
            hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, "  0x%04zx  ", off);
            for (int b = 0; b < 16; b++) {
                if (off + b < dump_sz) hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, "%02x ", data[off + b]);
                else hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, "   ");
            }
            hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, " ");
            for (int b = 0; b < 16 && off + b < dump_sz; b++) {
                uint8_t c = data[off + b];
                hp += snprintf(hx + hp, sizeof(hx) - (size_t)hp, "%c", (c >= 32 && c < 127) ? (char)c : '.');
            }
            fields_add(pd, hx, 1, 0, DETAIL_NONE, -1);
        }
    }
    return pd->count;
}
