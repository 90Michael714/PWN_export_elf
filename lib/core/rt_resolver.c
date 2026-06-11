/*
 * rt_resolver.c — 运行时感知分析引擎实现
 *
 * 利用 ptrace 附加进程后的运行时状态, 将静态 ELF 分析与运行时内存
 * 布局交叉对比, 产生运行时增强的分析结果存入 DB。
 *
 * 依赖: debug_worker.h (ptrace), db.h (SQLite), elf_parser.h (ELF读写)
 */

#include "core/rt_resolver.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include "elf_parser.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── 内部: 建运行时表 ───────────────────────────────────────────── */
static int ensure_rt_tables(AnalysisDB *adb)
{
    sqlite3 *c = (sqlite3 *)db_conn(adb);
    if (!c) return -1;
    sqlite3_exec(c,
        "CREATE TABLE IF NOT EXISTS rt_addresses("
        "  shdr_idx INTEGER, section TEXT,"
        "  file_vaddr INTEGER, rt_addr INTEGER,"
        "  aslr_delta INTEGER, pid INTEGER);"
        "CREATE TABLE IF NOT EXISTS rt_got("
        "  got_idx INTEGER, got_addr INTEGER, rt_value INTEGER,"
        "  lib_name TEXT, symbol_name TEXT, symbol_offset INTEGER);"
        "CREATE TABLE IF NOT EXISTS rt_indirect("
        "  call_addr INTEGER, mnemonic TEXT, target_reg TEXT,"
        "  rt_target INTEGER, rt_symbol TEXT, confidence REAL);"
        "CREATE TABLE IF NOT EXISTS rt_data_refs("
        "  insn_addr INTEGER, rt_target INTEGER,"
        "  content_blob BLOB, content_str TEXT, content_type TEXT);",
        NULL, NULL, NULL);
    return 0;
}

/* ── public: 从磁盘 ELF 读符号 ─────────────────────────────────── */
int rt_read_elf_syms(const char *path, rt_sym_t *out, int max)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    uint8_t e_ident[16];
    if (fread(e_ident, 1, 16, fp) != 16) { fclose(fp); return 0; }
    if (e_ident[0]!=0x7f||e_ident[1]!='E'||e_ident[2]!='L'||e_ident[3]!='F'
        || e_ident[4]!=2) { fclose(fp); return 0; } /* ELF64 check */

    Elf64_Ehdr eh;
    rewind(fp);
    if (fread(&eh, sizeof(eh), 1, fp) != 1) { fclose(fp); return 0; }

    Elf64_Shdr sh;
    int doff=0, dsize=0, soff=0, ssize=0;
    for (int i=0; i<(int)eh.e_shnum; i++) {
        fseek(fp, (long)(eh.e_shoff+i*eh.e_shentsize), SEEK_SET);
        if (fread(&sh,sizeof(sh),1,fp)!=1) break;
        if (sh.sh_type==SHT_DYNSYM){soff=(int)sh.sh_offset;ssize=(int)sh.sh_size;}
        else if (sh.sh_type==SHT_STRTAB&&(int)sh.sh_size>dsize)
            {doff=(int)sh.sh_offset;dsize=(int)sh.sh_size;}
    }
    if (!soff||!doff){fclose(fp);return 0;}

    char *strs=malloc((size_t)dsize);
    Elf64_Sym *syms=malloc((size_t)ssize);
    if (!strs||!syms){free(strs);free(syms);fclose(fp);return 0;}
    fseek(fp,doff,SEEK_SET);(void)!fread(strs,(size_t)dsize,1,fp);
    fseek(fp,soff,SEEK_SET);(void)!fread(syms,(size_t)ssize,1,fp);
    fclose(fp);

    int n=0, ns=ssize/(int)sizeof(Elf64_Sym);
    for (int i=0;i<ns&&n<max;i++){
        if (ELF64_ST_TYPE(syms[i].st_info)!=STT_FUNC) continue;
        if (!syms[i].st_value) continue;
        const char *nm=strs+syms[i].st_name;
        if (!nm[0]) continue;
        strncpy(out[n].name,nm,127);
        out[n].off=syms[i].st_value;
        out[n].sz=syms[i].st_size;
        n++;
    }
    free(strs);free(syms);
    return n;
}

/* ── Phase 1: 节地址映射 ──────────────────────────────────────── */
int rt_resolve_addresses(struct DebugState *ds, Elf64_Ctx *elf,
                         AnalysisDB *adb, PanelData *pd)
{
    if (!ds||!elf||!adb) return -1;
    ensure_rt_tables(adb);
    sqlite3 *c=(sqlite3*)db_conn(adb);
    if (!c) return -1;

    Elf64_Ehdr *eh=(Elf64_Ehdr*)elf->map;
    vmmap_entry_t entries[256];
    int nents=256;
    if (vmmap_read(ds,entries,&nents)!=0){if(pd)fields_add(pd,"(cannot read maps)",0,0,DETAIL_NONE,-1);return -1;}

    /* 找主程序可执行段基址, 计算 ASLR 偏移 */
    uint64_t exe_base=0, aslr_delta=0;
    for (int i=0;i<nents;i++){
        if (entries[i].perms[2]=='x'&&entries[i].path[0]
            &&!strstr(entries[i].path,".so")){
            exe_base=entries[i].start;break;
        }
    }
    if (exe_base){
        Elf64_Phdr *ph=(Elf64_Phdr*)(elf->map+eh->e_phoff);
        for (int p=0;p<(int)eh->e_phnum;p++){
            if (ph[p].p_type==PT_LOAD&&(ph[p].p_flags&PF_X)){
                aslr_delta=exe_base-ph[p].p_vaddr;break;
            }
        }
    }

    sqlite3_exec(c,"DELETE FROM rt_addresses",NULL,NULL,NULL);
    sqlite3_stmt *st=NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO rt_addresses(shdr_idx,section,file_vaddr,rt_addr,aslr_delta,pid)"
        " VALUES(?,?,?,?,?,?)",-1,&st,NULL);

    char buf[256]; int n=0;
    if (pd){fields_add(pd,"=== Runtime Address Resolution ===",0,0,DETAIL_NONE,-1);
        snprintf(buf,sizeof(buf),"PID:%d  ASLR delta: 0x%lx", ds->pid,(unsigned long)aslr_delta);
        fields_add(pd,buf,0,0,DETAIL_NONE,-1);fields_add(pd,"",0,0,DETAIL_NONE,-1);}

    for (int i=0;i<eh->e_shnum;i++){
        Elf64_Shdr *sh=elf_get_shdr(elf,i);
        if (!sh||sh->sh_addr==0||sh->sh_size==0) continue;
        const char *sn=elf_section_name(elf,i);
        uint64_t rt_addr=sh->sh_addr+aslr_delta;

        if (st){
            sqlite3_reset(st);
            sqlite3_bind_int(st,1,i);
            sqlite3_bind_text(st,2,sn?sn:"",-1,SQLITE_STATIC);
            sqlite3_bind_int64(st,3,(sqlite3_int64)sh->sh_addr);
            sqlite3_bind_int64(st,4,(sqlite3_int64)rt_addr);
            sqlite3_bind_int64(st,5,(sqlite3_int64)aslr_delta);
            sqlite3_bind_int(st,6,ds->pid);
            sqlite3_step(st);
        }
        if (pd){snprintf(buf,sizeof(buf),"[%2d] %-20s 0x%lx -> 0x%lx",
            i,sn?sn:"?",(unsigned long)sh->sh_addr,(unsigned long)rt_addr);
            fields_add(pd,buf,0,0,DETAIL_NONE,-1);}
        n++;
    }
    if (st) sqlite3_finalize(st);
    if (pd){snprintf(buf,sizeof(buf),"%d sections mapped",n);
        fields_add(pd,"",0,0,DETAIL_NONE,-1);fields_add(pd,buf,0,0,DETAIL_NONE,-1);}
    return n;
}

/* ── Phase 2: GOT 运行时解析 ──────────────────────────────────── */
int rt_resolve_got(struct DebugState *ds, Elf64_Ctx *elf,
                   AnalysisDB *adb, PanelData *pd)
{
    if (!ds||!elf||!adb) return -1;
    ensure_rt_tables(adb);
    sqlite3 *c=(sqlite3*)db_conn(adb);
    if (!c) return -1;
    Elf64_Ehdr *eh=(Elf64_Ehdr*)elf->map;

    /* 定位 .got.plt 和 .rela.plt */
    Elf64_Shdr *got_sec=NULL, *rela_sec=NULL, *dynsym_sec=NULL, *dynstr_sec=NULL;
    for (int i=0;i<eh->e_shnum;i++){
        const char *n=elf_section_name(elf,i);
        if (!n) continue;
        Elf64_Shdr *sh=elf_get_shdr(elf,i);
        if (!sh||sh->sh_size==0) continue;
        if (!strcmp(n,".got.plt")) got_sec=sh;
        else if (!strcmp(n,".got")&&!got_sec) got_sec=sh;
        else if (!strcmp(n,".rela.plt")) rela_sec=sh;
        else if (sh->sh_type==SHT_DYNSYM) dynsym_sec=sh;
    }
    if (dynsym_sec) dynstr_sec=elf_get_shdr(elf,dynsym_sec->sh_link);
    if (!got_sec){if(pd)fields_add(pd,"(no GOT section)",0,0,DETAIL_NONE,-1);return -1;}

    /* 计算 ASLR 偏移 */
    vmmap_entry_t entries[256]; int nents=256; uint64_t aslr_delta=0;
    vmmap_read(ds,entries,&nents);
    for (int i=0;i<nents;i++){
        if (entries[i].perms[2]=='x'&&entries[i].path[0]&&!strstr(entries[i].path,".so")){
            Elf64_Phdr *ph=(Elf64_Phdr*)(elf->map+eh->e_phoff);
            for (int p=0;p<(int)eh->e_phnum;p++)
                if (ph[p].p_type==PT_LOAD&&(ph[p].p_flags&PF_X))
                    {aslr_delta=entries[i].start-ph[p].p_vaddr;break;}
            break;
        }
    }

    /* 收集 maps 中的库映射 */
    typedef struct {uint64_t base;char path[256];} lib_t;
    lib_t libs[32]; int nlibs=0;
    for (int i=0;i<nents&&nlibs<32;i++){
        if (entries[i].path[0]&&entries[i].path[0]=='/'&&entries[i].perms[2]=='x'){
            int dup=0; for (int j=0;j<nlibs;j++)
                if (!strcmp(libs[j].path,entries[i].path)){dup=1;break;}
            if (!dup){libs[nlibs].base=entries[i].start;
                strncpy(libs[nlibs].path,entries[i].path,255);nlibs++;}
        }
    }

    int gc=(int)(got_sec->sh_size/sizeof(Elf64_Addr));
    uint64_t got_rt=got_sec->sh_addr+aslr_delta;
    uint64_t got_file=got_sec->sh_addr;

    sqlite3_exec(c,"DELETE FROM rt_got",NULL,NULL,NULL);
    sqlite3_stmt *st=NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO rt_got(got_idx,got_addr,rt_value,lib_name,symbol_name,symbol_offset)"
        " VALUES(?,?,?,?,?,?)",-1,&st,NULL);

    char buf[512]; int resolved=0;
    if (pd){fields_add(pd,"=== Runtime GOT/PLT Resolution ===",0,0,DETAIL_NONE,-1);
        fields_add(pd,"",0,0,DETAIL_NONE,-1);}

    /* 符号表: 从 rela.plt 获取 */
    typedef struct {uint64_t got_off;char name[128];} slot_t;
    slot_t slots[512]; int nslots=0;
    if (rela_sec&&dynsym_sec&&dynstr_sec){
        Elf64_Rela *r=(Elf64_Rela*)(elf->map+rela_sec->sh_offset);
        int nr=(int)(rela_sec->sh_size/sizeof(Elf64_Rela));
        Elf64_Sym *s=(Elf64_Sym*)(elf->map+dynsym_sec->sh_offset);
        for (int i=0;i<nr&&nslots<512;i++){
            uint32_t si=(uint32_t)(r[i].r_info>>32);
            if (si*sizeof(Elf64_Sym)<dynsym_sec->sh_size){
                slots[nslots].got_off=r[i].r_offset;
                const char *nm=elf_strtab_get(elf,dynstr_sec->sh_offset,s[si].st_name);
                snprintf(slots[nslots].name,sizeof(slots[nslots].name),"%s",nm?nm:"?");
                nslots++;
            }
        }
    }

    for (int i=0;i<gc;i++){
        uint64_t ga=got_rt+(uint64_t)(i*sizeof(Elf64_Addr));
        uint64_t val=0;
        debug_readmem(ds,ga,&val,sizeof(val));
        uint64_t file_ga=got_file+(uint64_t)(i*sizeof(Elf64_Addr));

        const char *sn="?"; /* 符号名 */
        for (int s=0;s<nslots;s++) if (slots[s].got_off==file_ga){sn=slots[s].name;break;}

        /* 运行时值解析: 查 maps 归属 */
        char lib[64]="-",lbuf[64]; int64_t off=0; int found=0;
        if (val>0x1000){
            for (int m=0;m<nents;m++){
                if (val>=entries[m].start&&val<entries[m].end){
                    if (entries[m].path[0]){
                        char *sl=strrchr(entries[m].path,'/');
                        snprintf(lib,sizeof(lib),"%s",sl?sl+1:entries[m].path);
                    }else snprintf(lib,sizeof(lib),"[anon]");
                    off=(int64_t)(val-entries[m].start);

                    /* 在对应库中查符号表 */
                    if (entries[m].path[0]&&entries[m].path[0]=='/'){
                        rt_sym_t syms[4096];
                        int ns=rt_read_elf_syms(entries[m].path,syms,4096);
                        for (int s=0;s<ns;s++){
                            uint64_t sa=entries[m].start+syms[s].off;
                            if (val>=sa&&val<sa+syms[s].sz){
                                snprintf(lbuf,sizeof(lbuf),"%s+0x%lx",syms[s].name,(unsigned long)(val-sa));
                                snprintf(lib,sizeof(lib),"%s",lbuf);
                                found=1;break;
                            }
                        }
                        if (!found&&ns>0){
                            /* 找最近的符号 */
                            uint64_t best_off=UINT64_MAX; int best=-1;
                            for (int s=0;s<ns;s++){
                                uint64_t sa=entries[m].start+syms[s].off;
                                if (sa<=val&&(val-sa)<best_off){best_off=val-sa;best=s;}
                            }
                            if (best>=0&&best_off<0x10000){
                                snprintf(lib,sizeof(lib),"%s+0x%lx",syms[best].name,(unsigned long)best_off);
                            }
                        }
                    }
                    break;
                }
            }
        }

        if (st){
            sqlite3_reset(st);
            sqlite3_bind_int(st,1,i);
            sqlite3_bind_int64(st,2,(sqlite3_int64)ga);
            sqlite3_bind_int64(st,3,(sqlite3_int64)val);
            sqlite3_bind_text(st,4,lib,-1,SQLITE_STATIC);
            sqlite3_bind_text(st,5,sn,-1,SQLITE_STATIC);
            sqlite3_bind_int64(st,6,off);
            sqlite3_step(st);
        }

        if (pd&&val>0x1000){
            snprintf(buf,sizeof(buf),"GOT[%d] %s -> 0x%lx  %s",
                i,sn,(unsigned long)val,lib);
            fields_add(pd,buf,0,0,DETAIL_NONE,-1);resolved++;
        }
    }
    if (st) sqlite3_finalize(st);
    if (pd){snprintf(buf,sizeof(buf),"%d/%d GOT entries resolved",resolved,gc);
        fields_add(pd,"",0,0,DETAIL_NONE,-1);fields_add(pd,buf,0,0,DETAIL_NONE,-1);}
    return resolved;
}

/* ── Phase 3: 间接调用目标解析 ────────────────────────────────── */
int rt_resolve_indirect_calls(struct DebugState *ds, AnalysisDB *adb, PanelData *pd)
{
    if (!ds||!adb) return -1;
    ensure_rt_tables(adb);
    sqlite3 *c=(sqlite3*)db_conn(adb);
    if (!c) return -1;

    /* 查 instructions 表中所有间接调用 (call reg 或 call [reg]) */
    sqlite3_stmt *q=NULL;
    sqlite3_prepare_v2(c,
        "SELECT address,mnemonic,op_str FROM instructions "
        "WHERE mnemonic='call' AND (op_str LIKE '%r%' OR op_str LIKE '%[%')"
        " AND op_str NOT LIKE '0x%' ORDER BY address",-1,&q,NULL);
    if (!q){if(pd)fields_add(pd,"(DB query failed)",0,0,DETAIL_NONE,-1);return -1;}

    sqlite3_exec(c,"DELETE FROM rt_indirect",NULL,NULL,NULL);
    sqlite3_stmt *ins=NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO rt_indirect(call_addr,mnemonic,target_reg,rt_target,rt_symbol,confidence)"
        " VALUES(?,?,?,?,?,?)",-1,&ins,NULL);

    vmmap_entry_t entries[256]; int nents=256;
    vmmap_read(ds,entries,&nents);

    char buf[512]; int n=0;
    if (pd){fields_add(pd,"=== Indirect Call Resolution ===",0,0,DETAIL_NONE,-1);
        fields_add(pd,"",0,0,DETAIL_NONE,-1);}

    while (sqlite3_step(q)==SQLITE_ROW){
        uint64_t addr=(uint64_t)sqlite3_column_int64(q,0);
        const char *mn=(const char*)sqlite3_column_text(q,1);
        const char *op=(const char*)sqlite3_column_text(q,2);

        /* 查找最近的寄存器快照 */
        sqlite3_stmt *rs=NULL; uint64_t rt_target=0; double conf=0.0;
        sqlite3_prepare_v2(c,
            "SELECT rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8,r9,r10,r11,r12,r13,r14,r15,rip"
            " FROM reg_snapshots ORDER BY ABS(rip-?) LIMIT 1",-1,&rs,NULL);
        if (rs){
            sqlite3_bind_int64(rs,1,(sqlite3_int64)addr);
            if (sqlite3_step(rs)==SQLITE_ROW){
                uint64_t regs[17];
                for (int r=0;r<17;r++) regs[r]=(uint64_t)sqlite3_column_int64(rs,r);
                /* 匹配操作数中的寄存器 */
                const char *rn[]={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                    "r8","r9","r10","r11","r12","r13","r14","r15",NULL};
                for (int r=0;rn[r];r++)
                    if (strstr(op,rn[r])){rt_target=regs[r];conf=0.8;break;}
                if (!rt_target&&strstr(op,"[rip")){
                    rt_target=regs[16];conf=0.9;
                }
            }
            sqlite3_finalize(rs);
        }

        /* 查找目标符号 */
        char sym[128]="?";
        if (rt_target>0x1000){
            for (int m=0;m<nents;m++){
                if (rt_target>=entries[m].start&&rt_target<entries[m].end){
                    if (entries[m].path[0]&&entries[m].path[0]=='/'){
                        rt_sym_t syms[4096];
                        int ns=rt_read_elf_syms(entries[m].path,syms,4096);
                        for (int s=0;s<ns;s++){
                            uint64_t sa=entries[m].start+syms[s].off;
                            if (rt_target>=sa&&rt_target<sa+syms[s].sz){
                                snprintf(sym,sizeof(sym),"%s",syms[s].name);conf=1.0;break;
                            }
                        }
                    }
                    break;
                }
            }
        }

        if (ins){
            sqlite3_reset(ins);
            sqlite3_bind_int64(ins,1,(sqlite3_int64)addr);
            sqlite3_bind_text(ins,2,mn?mn:"call",-1,SQLITE_STATIC);
            sqlite3_bind_text(ins,3,op?op:"",-1,SQLITE_STATIC);
            sqlite3_bind_int64(ins,4,(sqlite3_int64)rt_target);
            sqlite3_bind_text(ins,5,sym,-1,SQLITE_STATIC);
            sqlite3_bind_double(ins,6,conf);
            sqlite3_step(ins);
        }

        if (pd&&rt_target>0x1000&&conf>=0.7){
            snprintf(buf,sizeof(buf),"0x%lx  call %s  -> 0x%lx  %s  [conf:%.0f%%]",
                (unsigned long)addr,op?op:"?",(unsigned long)rt_target,sym,conf*100);
            fields_add(pd,buf,0,0,DETAIL_NONE,-1);n++;
        }
    }
    sqlite3_finalize(q);
    if (ins) sqlite3_finalize(ins);
    if (pd&&n==0) fields_add(pd,"(no register snapshots available — step first)",0,0,DETAIL_NONE,-1);
    return n;
}

/* ── Phase 4: 数据引用运行时内容 ──────────────────────────────── */
int rt_resolve_data_refs(struct DebugState *ds, Elf64_Ctx *elf,
                         AnalysisDB *adb, PanelData *pd)
{
    if (!ds||!adb) return -1;
    ensure_rt_tables(adb);
    sqlite3 *c=(sqlite3*)db_conn(adb);
    if (!c) return -1;

    /* 查 RIP-relative 引用 */
    sqlite3_stmt *q=NULL;
    sqlite3_prepare_v2(c,
        "SELECT address,op_str FROM instructions WHERE op_str LIKE '%[rip%'"
        " ORDER BY address LIMIT 500",-1,&q,NULL);
    if (!q){if(pd)fields_add(pd,"(DB query failed)",0,0,DETAIL_NONE,-1);return -1;}

    sqlite3_exec(c,"DELETE FROM rt_data_refs",NULL,NULL,NULL);
    sqlite3_stmt *ins=NULL;
    sqlite3_prepare_v2(c,
        "INSERT INTO rt_data_refs(insn_addr,rt_target,content_str,content_type)"
        " VALUES(?,?,?,?)",-1,&ins,NULL);

    char buf[512]; int n=0;
    if (pd){fields_add(pd,"=== Data Reference Resolution ===",0,0,DETAIL_NONE,-1);
        fields_add(pd,"",0,0,DETAIL_NONE,-1);}

    while (sqlite3_step(q)==SQLITE_ROW){
        uint64_t iaddr=(uint64_t)sqlite3_column_int64(q,0);
        const char *op=(const char*)sqlite3_column_text(q,1);
        if (!op) continue;

        /* 从 reg_snapshots 找最近的 RIP */
        sqlite3_stmt *rs=NULL; uint64_t rip=0;
        sqlite3_prepare_v2(c,
            "SELECT rip FROM reg_snapshots ORDER BY ABS(rip-?) LIMIT 1",-1,&rs,NULL);
        if (rs){
            sqlite3_bind_int64(rs,1,(sqlite3_int64)iaddr);
            if (sqlite3_step(rs)==SQLITE_ROW) rip=(uint64_t)sqlite3_column_int64(rs,0);
            sqlite3_finalize(rs);
        }
        if (!rip) continue;

        /* 解析 displacement: lea reg, [rip + 0x1234] */
        const char *plus=strstr(op,"+");
        if (!plus) plus=strstr(op,"-");
        if (!plus) continue;
        int64_t disp=strtoll(plus,NULL,0);
        uint64_t target=rip+disp;

        /* 读目标内存 */
        uint8_t mem[32];
        int nr=debug_readmem(ds,target,mem,sizeof(mem));
        if (nr<=0) continue;

        /* 判断类型 */
        char ctype[16]="unknown",cstr[128]="";
        int printable=1;
        for (int i=0;i<nr&&i<32;i++){
            if (mem[i]==0){
                if (i>0&&printable){snprintf(cstr,sizeof(cstr),"\"%s\"",(char*)mem);
                    snprintf(ctype,sizeof(ctype),"string");}
                break;
            }
            if (mem[i]<32||mem[i]>126) printable=0;
        }
        if (!cstr[0]&&nr>=8&&!printable){
            uint64_t *ptr=(uint64_t*)mem;
            if (*ptr>0x1000){snprintf(cstr,sizeof(cstr),"0x%lx",(unsigned long)*ptr);
                snprintf(ctype,sizeof(ctype),"func_ptr");}
            else{snprintf(cstr,sizeof(cstr),"0x%lx",(unsigned long)*ptr);
                snprintf(ctype,sizeof(ctype),"integer");}
        }

        if (ins){
            sqlite3_reset(ins);
            sqlite3_bind_int64(ins,1,(sqlite3_int64)iaddr);
            sqlite3_bind_int64(ins,2,(sqlite3_int64)target);
            sqlite3_bind_text(ins,3,cstr,-1,SQLITE_STATIC);
            sqlite3_bind_text(ins,4,ctype,-1,SQLITE_STATIC);
            sqlite3_step(ins);
        }

        if (pd&&cstr[0]){
            snprintf(buf,sizeof(buf),"0x%lx  %-30s  -> 0x%lx  %s  [%s]",
                (unsigned long)iaddr,op,(unsigned long)target,cstr,ctype);
            fields_add(pd,buf,0,0,DETAIL_NONE,-1);n++;
        }
    }
    sqlite3_finalize(q);
    if (ins) sqlite3_finalize(ins);
    if (pd&&n==0) fields_add(pd,"(no reg snapshots — step the process first)",0,0,DETAIL_NONE,-1);
    return n;
}

/* ── 一键全解析 ────────────────────────────────────────────────── */
int rt_resolve_all(struct DebugState *ds, Elf64_Ctx *elf,
                   AnalysisDB *adb, PanelData *pd)
{
    if (!ds||!elf||!adb) return -1;
    int total=0;
    total+=rt_resolve_addresses(ds,elf,adb,pd);
    total+=rt_resolve_got(ds,elf,adb,pd);
    total+=rt_resolve_indirect_calls(ds,adb,pd);
    total+=rt_resolve_data_refs(ds,elf,adb,pd);
    return total;
}

/* ── 运行时增强反编译 ──────────────────────────────────────────── */
int rt_decompile_function(AnalysisDB *adb, uint64_t func_addr, PanelData *pd)
{
    if (!adb||!pd) return -1;
    sqlite3 *c=(sqlite3*)db_conn(adb);
    if (!c) return -1;

    /* 函数元信息 */
    sqlite3_stmt *fs=NULL;
    sqlite3_prepare_v2(c,
        "SELECT start_addr,end_addr,name,bb_count FROM functions WHERE start_addr=?1",
        -1,&fs,NULL);
    if (!fs) return -1;
    sqlite3_bind_int64(fs,1,(sqlite3_int64)func_addr);
    if (sqlite3_step(fs)!=SQLITE_ROW){sqlite3_finalize(fs);return -1;}
    uint64_t fend=(uint64_t)sqlite3_column_int64(fs,1);
    const char *fname=(const char*)sqlite3_column_text(fs,2);
    sqlite3_finalize(fs);

    char buf[512];
    snprintf(buf,sizeof(buf),"=== Decompile: %s (0x%lx) [RT-enhanced] ===",
        fname?fname:"?",(unsigned long)func_addr);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 遍历函数内的指令 */
    sqlite3_stmt *iq=NULL;
    sqlite3_prepare_v2(c,
        "SELECT address,mnemonic,op_str FROM instructions "
        "WHERE address>=?1 AND address<?2 ORDER BY address",
        -1,&iq,NULL);
    if (!iq) return -1;
    sqlite3_bind_int64(iq,1,(sqlite3_int64)func_addr);
    sqlite3_bind_int64(iq,2,(sqlite3_int64)fend);

    while (sqlite3_step(iq)==SQLITE_ROW){
        uint64_t addr=(uint64_t)sqlite3_column_int64(iq,0);
        const char *mn=(const char*)sqlite3_column_text(iq,1);
        const char *op=(const char*)sqlite3_column_text(iq,2);

        char line[512];
        snprintf(line,sizeof(line),"0x%lx  %-8s %s",(unsigned long)addr,mn?mn:"?",op?op:"");

        /* 查运行时间接调用目标 */
        if (mn&&!strcmp(mn,"call")&&op&&strstr(op,"0x")){
            /* 直接调用: 已有目标 */
        } else if (mn&&!strcmp(mn,"call")){
            sqlite3_stmt *rt=NULL;
            sqlite3_prepare_v2(c,
                "SELECT rt_target,rt_symbol,confidence FROM rt_indirect "
                "WHERE call_addr=?1",-1,&rt,NULL);
            if (rt){
                sqlite3_bind_int64(rt,1,(sqlite3_int64)addr);
                if (sqlite3_step(rt)==SQLITE_ROW){
                    uint64_t target=(uint64_t)sqlite3_column_int64(rt,0);
                    const char *sym=(const char*)sqlite3_column_text(rt,1);
                    double conf=sqlite3_column_double(rt,2);
                    if (target>0x1000&&conf>=0.7){
                        snprintf(line+strlen(line),sizeof(line)-strlen(line),
                            "  ; → %s (0x%lx) [%.0f%%]", sym?sym:"?",(unsigned long)target,conf*100);
                    }
                }
                sqlite3_finalize(rt);
            }
        }

        /* 查运行时数据引用 */
        if (op&&strstr(op,"[rip")){
            sqlite3_stmt *dr=NULL;
            sqlite3_prepare_v2(c,
                "SELECT content_str,content_type FROM rt_data_refs "
                "WHERE insn_addr=?1",-1,&dr,NULL);
            if (dr){
                sqlite3_bind_int64(dr,1,(sqlite3_int64)addr);
                if (sqlite3_step(dr)==SQLITE_ROW){
                    const char *cs=(const char*)sqlite3_column_text(dr,0);
                    const char *ct=(const char*)sqlite3_column_text(dr,1);
                    if (cs&&cs[0]){
                        snprintf(line+strlen(line),sizeof(line)-strlen(line),
                            "  ; [%s] %s", ct?ct:"?", cs);
                    }
                }
                sqlite3_finalize(dr);
            }
        }

        fields_add(pd,line,0,0,DETAIL_NONE,(int)(addr&0xFFFF));
    }
    sqlite3_finalize(iq);

    /* 跨函数调用关系 */
    fields_add(pd,"",0,0,DETAIL_NONE,-1);
    sqlite3_stmt *cl=NULL;
    sqlite3_prepare_v2(c,
        "SELECT to_addr,ref_type FROM xrefs WHERE from_addr>=?1 AND from_addr<?2 AND ref_type='call'",
        -1,&cl,NULL);
    if (cl){
        sqlite3_bind_int64(cl,1,(sqlite3_int64)func_addr);
        sqlite3_bind_int64(cl,2,(sqlite3_int64)fend);
        int nc=0;
        while (sqlite3_step(cl)==SQLITE_ROW&&nc<100){
            uint64_t to=(uint64_t)sqlite3_column_int64(cl,0);
            sqlite3_stmt *sn=NULL;
            sqlite3_prepare_v2(c,"SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sn,NULL);
            if (sn){
                sqlite3_bind_int64(sn,1,(sqlite3_int64)to);
                const char *tn="?";
                if (sqlite3_step(sn)==SQLITE_ROW) tn=(const char*)sqlite3_column_text(sn,0);
                snprintf(buf,sizeof(buf),"  → 0x%lx  %s",(unsigned long)to,tn?tn:"?");
                fields_add(pd,buf,0,0,DETAIL_NONE,-1);
                sqlite3_finalize(sn);nc++;
            }
        }
        sqlite3_finalize(cl);
    }

    return pd->count;
}
