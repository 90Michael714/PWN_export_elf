/*
 * decompile.c — C伪代码反编译 + 汇编对照 v8 (DWARF + 全节交叉对比)
 *
 * 前提: 必须 attach 到进程。decompile_load_base 由 btn_decompile_action 设置。
 * 右侧面板输出: C 伪代码(上) + 汇编参考(下)
 */

#include "elf_parser.h"
#include "core/db.h"
#include "core/dwarf_reader.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

extern AnalysisDB *g_active_db;
uint64_t decompile_load_base = 0;
static uint64_t real_a(uint64_t sa) { return decompile_load_base + sa; }

/* ── 中间面板 ──────────────────────────────────────────────────── */
int parse_decompile(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)ctx; (void)shdr_idx;
    if (!g_active_db) { fields_add(pd,"(DB not available)",0,0,DETAIL_NONE,-1); return 0; }
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) { fields_add(pd,"(DB connection)",0,0,DETAIL_NONE,-1); return 0; }
    char buf[512]; int total=0;

    snprintf(buf,sizeof(buf),"=== Decompile (base +0x%lx) ===",(unsigned long)decompile_load_base);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    fields_add(pd,"[F]=func [V]=var [S]=str [P]=PLT  [Enter]=detail",0,0,DETAIL_NONE,-1);
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* 符号 */
    { sqlite3_stmt *st=NULL;
      sqlite3_prepare_v2(c,"SELECT address,name,type,bind,size FROM symbols "
        "WHERE address>0x100 AND type NOT IN('FILE','SECTION') ORDER BY address",-1,&st,NULL);
      if(st){ while(sqlite3_step(st)==SQLITE_ROW){
        uint64_t sa=(uint64_t)sqlite3_column_int64(st,0);
        const char *nm=(const char*)sqlite3_column_text(st,1);
        const char *tp=(const char*)sqlite3_column_text(st,2);
        const char *bd=(const char*)sqlite3_column_text(st,3);
        int sz=sqlite3_column_int(st,4); if(!nm||!nm[0]) continue;
        char tag[4]="[V]";
        if(tp){ if(!strcmp(tp,"FUNC")) snprintf(tag,4,"[F]");
                else if(!strcmp(tp,"OBJECT")) snprintf(tag,4,"[V]");
                else snprintf(tag,4,"[%c]",tp[0]); }
        snprintf(buf,sizeof(buf),"%s 0x%016lx %-40s sz=%-6d %s",
                 tag,(unsigned long)real_a(sa),nm,sz,bd?bd:"");
        fields_add(pd,buf,0,1,DETAIL_NONE,(int)sa); total++;
      } sqlite3_finalize(st); } }

    /* 字符串 */
    { sqlite3_stmt *st=NULL;
      sqlite3_prepare_v2(c,"SELECT address,value,length FROM strings "
        "WHERE address NOT IN(SELECT address FROM symbols) AND address>0x100 "
        "ORDER BY address",-1,&st,NULL);
      if(st){ while(sqlite3_step(st)==SQLITE_ROW){
        uint64_t sa=(uint64_t)sqlite3_column_int64(st,0);
        const char *v=(const char*)sqlite3_column_text(st,1);
        int len=sqlite3_column_int(st,2); char pv[40]=""; if(v){ int pp=0;
          for(const char *s=v;*s&&pp<36;s++){
            if(*s=='\n'){pv[pp++]='\\';pv[pp++]='n';}
            else if((unsigned char)*s>=32)pv[pp++]=*s; } pv[pp]=0; }
        snprintf(buf,sizeof(buf),"[S] 0x%016lx \"%s\"%s (%dB)",
                 (unsigned long)real_a(sa),pv,(v&&(int)strlen(v)>36)?"...":"",len);
        fields_add(pd,buf,0,1,DETAIL_NONE,(int)sa); total++;
      } sqlite3_finalize(st); } }

    /* PLT */
    { sqlite3_stmt *st=NULL;
      sqlite3_prepare_v2(c,"SELECT s.address,s.name FROM symbols s "
        "JOIN sections sec ON s.address>=sec.addr AND s.address<sec.addr+sec.size "
        "WHERE sec.name LIKE '%%plt%%' AND s.type='FUNC' ORDER BY s.address",
        -1,&st,NULL);
      if(st){ while(sqlite3_step(st)==SQLITE_ROW){
        uint64_t sa=(uint64_t)sqlite3_column_int64(st,0);
        const char *nm=(const char*)sqlite3_column_text(st,1); if(!nm||!nm[0]) continue;
        snprintf(buf,sizeof(buf),"[P] 0x%016lx %-40s PLT",(unsigned long)real_a(sa),nm);
        fields_add(pd,buf,0,1,DETAIL_NONE,(int)sa); total++;
      } sqlite3_finalize(st); } }

    snprintf(buf,sizeof(buf),"── %d entries [j/k]=nav [Enter]=detail [h]=back ──",total);
    fields_add(pd,buf,0,0,DETAIL_NONE,-1);
    return pd->count;
}

/* ── 操作数分割 ── */
static int split_ops(const char *op_str, char dst[64], char src[64])
{
    if (!op_str) { dst[0]=src[0]=0; return 0; }
    int depth=0, n=0; const char *start=op_str;
    while (*start==' ') start++;
    for (const char *p=start; ; p++) {
        if (*p=='[') depth++;
        else if (*p==']'&&depth>0) depth--;
        else if ((*p==','||*p=='\0')&&depth==0) {
            size_t len=(size_t)(p-start);
            while (len>0&&start[len-1]==' ') len--;
            if (n==0) { if(len<63){memcpy(dst,start,len);dst[len]=0;} n++; }
            else      { if(len<63){memcpy(src,start,len);src[len]=0;} return 2; }
            if (*p=='\0') break;
            start=p+1; while(*start==' ') start++;
        }
        if (*p=='\0') break;
    }
    return n;
}

/* ── 右侧面板: C伪代码(上) + 汇编参考(下) ───────────────────────── */

int decompile_addr_detail(sqlite3 *c, uint64_t static_input_addr, PanelData *pd)
{
    if (!c||!pd) return -1;
    uint64_t sa=static_input_addr, ra=real_a(sa);
    char buf[600];

    if (pd->fields) {
        extern void fields_free(Elf64_Field*, int);
        fields_free(pd->fields,pd->count);
        pd->fields=NULL; pd->count=pd->capacity=0;
        pd->cursor=pd->scroll=pd->scroll_x=0;
    }

    /* ── 标题 ── */
    { char sec[64]="";
      sqlite3_stmt *ss=NULL; sqlite3_prepare_v2(c,
        "SELECT name FROM sections WHERE addr<=?1 AND (?1-addr)<size ORDER BY addr DESC LIMIT 1",
        -1,&ss,NULL);
      if(ss){ sqlite3_bind_int64(ss,1,(sqlite3_int64)sa);
        if(sqlite3_step(ss)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(ss,0); if(sn)snprintf(sec,64,"%s",sn); }
        sqlite3_finalize(ss); }
      snprintf(buf,sizeof(buf),"▸ 0x%016lx  %s  (static 0x%lx + base 0x%lx)",
               (unsigned long)ra,sec[0]?sec:"?",(unsigned long)sa,(unsigned long)decompile_load_base);
      fields_add(pd,buf,0,0,DETAIL_NONE,-1); }
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* ── 符号 ── */
    int is_func=0; char sym_name[128]="";
    { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
        "SELECT name,type,bind,size FROM symbols WHERE address=?1 LIMIT 1",-1,&st,NULL);
      if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)sa);
        if(sqlite3_step(st)==SQLITE_ROW){
            const char *nm=(const char*)sqlite3_column_text(st,0);
            const char *tp=(const char*)sqlite3_column_text(st,1);
            if(nm)snprintf(sym_name,sizeof(sym_name),"%s",nm);
            if(tp&&!strcmp(tp,"FUNC"))is_func=1; }
        sqlite3_finalize(st); } }

    /* ── DWARF ── */
    char dw_fname[128]="", dw_file[256]=""; int dw_line=0;
    { sqlite3_stmt *dw=NULL; sqlite3_prepare_v2(c,
        "SELECT name,source_file,line_no FROM dwarf_funcs WHERE addr=?1",-1,&dw,NULL);
      if(dw){ sqlite3_bind_int64(dw,1,(sqlite3_int64)sa);
        if(sqlite3_step(dw)==SQLITE_ROW){
            const char *dn=(const char*)sqlite3_column_text(dw,0);
            const char *ds=(const char*)sqlite3_column_text(dw,1);
            if(dn)snprintf(dw_fname,sizeof(dw_fname),"%s",dn);
            if(ds)snprintf(dw_file,sizeof(dw_file),"%s",ds);
            dw_line=sqlite3_column_int(dw,2); }
        sqlite3_finalize(dw); } }

    /* ── 函数范围 ── */
    uint64_t fe=sa;
    { sqlite3_stmt *fs=NULL; sqlite3_prepare_v2(c,
        "SELECT end_addr FROM functions WHERE start_addr=?1",-1,&fs,NULL);
      if(fs){ sqlite3_bind_int64(fs,1,(sqlite3_int64)sa);
        if(sqlite3_step(fs)==SQLITE_ROW) fe=(uint64_t)sqlite3_column_int64(fs,0);
        sqlite3_finalize(fs); } }
    if (fe<=sa) fe=sa+0x10000;

    /* ═════════════════════════════════════════════════════════════
     * 上半部分: C 伪代码
     * ═════════════════════════════════════════════════════════════ */
    const char *fn = dw_fname[0]?dw_fname:(sym_name[0]?sym_name:"sub_unknown");

    if (dw_file[0]&&dw_line>0) { snprintf(buf,sizeof(buf),"// %s:%d",dw_file,dw_line); fields_add(pd,buf,0,0,DETAIL_NONE,-1); }

    if (!is_func) {
        snprintf(buf,sizeof(buf),"// Data: %s  (not a function)", fn);
        fields_add(pd,buf,0,0,DETAIL_NONE,-1);
        fields_add(pd,"}",0,0,DETAIL_NONE,-1);
    } else {
        snprintf(buf,sizeof(buf),"void %s() {", fn);
        fields_add(pd,buf,0,0,DETAIL_NONE,-1);

        /* 收集指令 */
        typedef struct { uint64_t a; char m[12], o[128]; } ins_t;
        ins_t ins[300]; int ni=0;
        { sqlite3_stmt *is=NULL; sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str FROM instructions "
            "WHERE address BETWEEN ?1 AND ?2 ORDER BY address",-1,&is,NULL);
          if(is){ sqlite3_bind_int64(is,1,(sqlite3_int64)sa); sqlite3_bind_int64(is,2,(sqlite3_int64)fe);
            while(sqlite3_step(is)==SQLITE_ROW&&ni<300){
                ins[ni].a=(uint64_t)sqlite3_column_int64(is,0);
                const char *mn=(const char*)sqlite3_column_text(is,1);
                const char *op=(const char*)sqlite3_column_text(is,2);
                snprintf(ins[ni].m,sizeof(ins[ni].m),"%s",mn?mn:"?");
                snprintf(ins[ni].o,sizeof(ins[ni].o),"%s",op?op:""); ni++;
            } sqlite3_finalize(is); } }

        if (ni==0) { fields_add(pd,"(no instructions)",0,0,DETAIL_NONE,-1); fields_add(pd,"}",0,0,DETAIL_NONE,-1); }
        else {
            int indent=2, skip=0;
            for (int i=0; i<ni; i++) {
                if (skip>0) { skip--; continue; }
                ins_t *in=&ins[i]; const char *mn=in->m, *op=in->o;

                if (!strcmp(mn,"endbr64")||!strcmp(mn,"nop")) continue;
                if (!strcmp(mn,"push")&&!strcmp(op,"rbp")&&i<3) continue;
                if (!strcmp(mn,"mov")&&strstr(op,"rbp, rsp")&&i<4) continue;
                if (!strcmp(mn,"sub")&&strstr(op,"rsp")&&i<5) continue;

                char dst[64]="",src[64]=""; split_ops(op,dst,src);

                /* DWARF 行号 */
                char sl[24]="";
                { sqlite3_stmt *dl=NULL; sqlite3_prepare_v2(c,
                    "SELECT line_no FROM dwarf_lines WHERE addr=?1 LIMIT 1",-1,&dl,NULL);
                  if(dl){ sqlite3_bind_int64(dl,1,(sqlite3_int64)in->a);
                    if(sqlite3_step(dl)==SQLITE_ROW){ int ln=sqlite3_column_int(dl,1); if(ln>0)snprintf(sl,sizeof(sl),"  // :%d",ln); }
                    sqlite3_finalize(dl); } }

                char sp[16]; memset(sp,' ',16); int spp=indent*2; if(spp>14)spp=14; sp[spp]=0;

                /* call */
                if (!strcmp(mn,"call")) {
                    uint64_t t=op?strtoull(op,NULL,16):0;
                    char cn[128]=""; int have=0;
                    { sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                        "SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sy,NULL);
                      if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)t);
                        if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0); if(sn){snprintf(cn,128,"%s",sn);have=1;} }
                        sqlite3_finalize(sy); } }
                    if(!have){ sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                        "SELECT name FROM dwarf_funcs WHERE addr=?1 LIMIT 1",-1,&sy,NULL);
                      if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)t);
                        if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0); if(sn){snprintf(cn,128,"%s",sn);have=1;} }
                        sqlite3_finalize(sy); } }
                    snprintf(buf,sizeof(buf),"%s%s();%s",sp,have?cn:"sub_?","");
                    fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue;
                }
                /* jmp */
                if (!strcmp(mn,"jmp")) {
                    uint64_t t=op?strtoull(op,NULL,16):0;
                    if (t<in->a) { indent--; if(indent<2)indent=2; sp[indent*2]=0;
                        snprintf(buf,sizeof(buf),"%s}  // loop%s",sp,sl); }
                    else snprintf(buf,sizeof(buf),"%sgoto 0x%lx;%s",sp,(unsigned long)real_a(t),sl);
                    fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue;
                }
                /* cmp/test + jcc */
                if ((!strcmp(mn,"cmp")||!strcmp(mn,"test"))&&i+1<ni) {
                    const char *jcc=ins[i+1].m; char dc=0,s2c=0;
                    if (jcc[0]=='j'&&strcmp(jcc,"jmp")) { dc=1; s2c=1; }
                    if (dc) {
                        const char *cond="?"; if(!strcmp(jcc,"je")||!strcmp(jcc,"jz"))cond="==";
                        else if(!strcmp(jcc,"jne")||!strcmp(jcc,"jnz"))cond="!=";
                        else if(!strcmp(jcc,"jg")||!strcmp(jcc,"jnle"))cond=">";
                        else if(!strcmp(jcc,"jge")||!strcmp(jcc,"jnl"))cond=">=";
                        else if(!strcmp(jcc,"jl")||!strcmp(jcc,"jnge"))cond="<";
                        else if(!strcmp(jcc,"jle")||!strcmp(jcc,"jng"))cond="<=";
                        char L[64]="",R[64]=""; { char d3[64]="",s3[64]=""; split_ops(op,d3,s3);
                            if(d3[0])snprintf(L,64,"%s",d3);
                            if(s3[0]){ uint64_t iv=strtoull(s3,NULL,16);
                                if(iv>0x100){ sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                                    "SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sy,NULL);
                                  if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)iv);
                                    if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0); if(sn)snprintf(R,64,"&%s",sn); }
                                    sqlite3_finalize(sy); } }
                                if(!R[0]){
                                    if(s3[0]=='0'&&s3[1]=='x')
                                        snprintf(R,64,"0x%lx",(unsigned long)iv);
                                    else
                                        snprintf(R,64,"%s",s3);
                                }
                            } }
                        snprintf(buf,sizeof(buf),"%sif (%s %s %s) {%s",sp,L[0]?L:"?",cond,R[0]?R:"0",sl);
                        fields_add(pd,buf,0,0,DETAIL_NONE,-1);
                        indent++; skip=1; continue;
                    }
                }
                /* ret */
                if (!strcmp(mn,"ret")||!strcmp(mn,"retn")) {
                    while(indent>2){ indent--; fields_add(pd,"  }",0,0,DETAIL_NONE,-1); }
                    snprintf(buf,sizeof(buf),"%sreturn;%s",sp,sl);
                    fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue;
                }
                /* mov/lea */
                if (!strcmp(mn,"mov")||!strcmp(mn,"movsx")||!strcmp(mn,"movzx")||!strcmp(mn,"lea")) {
                    char R[80]=""; if(src[0]){
                        uint64_t iv=strtoull(src,NULL,16);
                        if(iv>0x100){ sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                            "SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sy,NULL);
                          if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)iv);
                            if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0); if(sn)snprintf(R,80,"&%s",sn); }
                            sqlite3_finalize(sy); }
                          if(!R[0]){ sqlite3_stmt *ss=NULL; sqlite3_prepare_v2(c,
                              "SELECT value FROM strings WHERE address=?1 LIMIT 1",-1,&ss,NULL);
                            if(ss){ sqlite3_bind_int64(ss,1,(sqlite3_int64)iv);
                              if(sqlite3_step(ss)==SQLITE_ROW){ const char *sv=(const char*)sqlite3_column_text(ss,0);
                                if(sv){ char pv[48];int pp=0; for(const char *x=sv;*x&&pp<44;x++){ if(*x=='\n'){pv[pp++]='\\';pv[pp++]='n';} else if((unsigned char)*x>=32)pv[pp++]=*x; } pv[pp]=0;
                                  snprintf(R,80,"\"%s\"",pv); } }
                              sqlite3_finalize(ss); } }
                        }
                        if(!R[0])snprintf(R,80,"%s",src);
                    }
                    snprintf(buf,sizeof(buf),"%s%s = %s;%s",sp,dst[0]?dst:"?",R[0]?R:"?",sl);
                    fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue;
                }
                /* push/pop/syscall */
                if (!strcmp(mn,"push")) { snprintf(buf,sizeof(buf),"%spush(%s);%s",sp,op?op:"?",sl); fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue; }
                if (!strcmp(mn,"pop"))  { snprintf(buf,sizeof(buf),"%s%s = pop();%s",sp,op?op:"?",sl); fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue; }
                if (!strcmp(mn,"syscall")) { snprintf(buf,sizeof(buf),"%ssyscall;%s",sp,sl); fields_add(pd,buf,0,0,DETAIL_NONE,-1); continue; }

                /* 其他 → C 注释 */
                snprintf(buf,sizeof(buf),"%s// %-8s  %s%s",sp,mn,op?op:"",sl);
                fields_add(pd,buf,0,0,DETAIL_NONE,-1);
            }
            while(indent>2){ indent--; fields_add(pd,"  }",0,0,DETAIL_NONE,-1); }
            fields_add(pd,"}",0,0,DETAIL_NONE,-1);
        }
    }
    fields_add(pd,"",0,0,DETAIL_NONE,-1);

    /* ═════════════════════════════════════════════════════════════
     * 下半部分: 汇编参考 — 以选定地址为起点, 显示 25 条指令
     * ═════════════════════════════════════════════════════════════ */
    {
        snprintf(buf,sizeof(buf),"── Assembly @ 0x%lx (static 0x%lx) ──",
                 (unsigned long)ra, (unsigned long)sa);
        fields_add(pd,buf,0,0,DETAIL_NONE,-1);

        sqlite3_stmt *st=NULL;
        sqlite3_prepare_v2(c,
            "SELECT address,mnemonic,op_str,bytes,size FROM instructions "
            "WHERE address >= ?1 ORDER BY address LIMIT 25",
            -1,&st,NULL);
        if(st){
            sqlite3_bind_int64(st,1,(sqlite3_int64)sa);
            while(sqlite3_step(st)==SQLITE_ROW){
                uint64_t ia=(uint64_t)sqlite3_column_int64(st,0);
                const char *mn=(const char*)sqlite3_column_text(st,1);
                const char *op=(const char*)sqlite3_column_text(st,2);
                const uint8_t *by=(const uint8_t*)sqlite3_column_blob(st,3);
                int bsz=sqlite3_column_bytes(st,3);
                uint64_t ria=real_a(ia);

                char hx[32]=""; int hp=0;
                if(by) for(int i=0;i<bsz&&i<8&&hp<28;i++)
                    hp+=snprintf(hx+hp,32-hp,"%02x ",by[i]);

                char sl[16]="";
                { sqlite3_stmt *dl=NULL; sqlite3_prepare_v2(c,
                    "SELECT line_no FROM dwarf_lines WHERE addr=?1 LIMIT 1",-1,&dl,NULL);
                  if(dl){ sqlite3_bind_int64(dl,1,(sqlite3_int64)ia);
                    if(sqlite3_step(dl)==SQLITE_ROW){ int ln=sqlite3_column_int(dl,1);
                      if(ln>0)snprintf(sl,sizeof(sl)," :%-4d",ln); }
                    sqlite3_finalize(dl); } }

                char tag[80]="";
                { uint64_t t=op?strtoull(op,NULL,16):0;
                  if(t>0x100&&(mn[0]=='c'||mn[0]=='j')){
                    sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                        "SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sy,NULL);
                    if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)t);
                      if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0);
                        if(sn)snprintf(tag,80,"  → <%s>",sn); }
                      sqlite3_finalize(sy); } }
                  if(!tag[0]&&t>0x100){
                    sqlite3_stmt *ss=NULL; sqlite3_prepare_v2(c,
                        "SELECT value FROM strings WHERE address=?1 LIMIT 1",-1,&ss,NULL);
                    if(ss){ sqlite3_bind_int64(ss,1,(sqlite3_int64)t);
                      if(sqlite3_step(ss)==SQLITE_ROW){ const char *sv=(const char*)sqlite3_column_text(ss,0);
                        if(sv){ char pv[32];int pp=0; for(const char *x=sv;*x&&pp<28;x++){
                            if(*x=='\n'){pv[pp++]='\\';pv[pp++]='n';}
                            else if((unsigned char)*x>=32)pv[pp++]=*x; } pv[pp]=0;
                          snprintf(tag,80,"  ; \"%s\"",pv); } }
                      sqlite3_finalize(ss); } }
                  if(!tag[0]&&t>0x100){
                    sqlite3_stmt *sy=NULL; sqlite3_prepare_v2(c,
                        "SELECT name FROM symbols WHERE address=?1 LIMIT 1",-1,&sy,NULL);
                    if(sy){ sqlite3_bind_int64(sy,1,(sqlite3_int64)t);
                      if(sqlite3_step(sy)==SQLITE_ROW){ const char *sn=(const char*)sqlite3_column_text(sy,0);
                        if(sn)snprintf(tag,80,"  ; &%s",sn); }
                      sqlite3_finalize(sy); } }
                }

                char m=' '; if(ia==sa)m='>';
                snprintf(buf,sizeof(buf),"  %c 0x%lx: %-20s %-8s %-20s%s%s",
                         m,(unsigned long)ria,hx,mn?mn:"?",op?op:"",tag,sl);
                fields_add(pd,buf,1,(ia==sa)?1:0,DETAIL_NONE,-1);
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 交叉引用 ── */
    { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
        "SELECT x.from_addr,x.ref_type,COALESCE(s.name,'') FROM xrefs x "
        "LEFT JOIN symbols s ON s.address=x.from_addr WHERE x.to_addr=?1 LIMIT 16",
        -1,&st,NULL);
      if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)sa); int f=0;
        while(sqlite3_step(st)==SQLITE_ROW){ if(!f){ fields_add(pd,"── Incoming XRefs ──",0,0,DETAIL_NONE,-1); f=1; }
          uint64_t fr=(uint64_t)sqlite3_column_int64(st,0); const char *rt=(const char*)sqlite3_column_text(st,1);
          const char *sn=(const char*)sqlite3_column_text(st,2);
          snprintf(buf,sizeof(buf),"  ← 0x%lx %-10s %s",(unsigned long)real_a(fr),rt?rt:"",sn&&sn[0]?sn:"");
          fields_add(pd,buf,1,0,DETAIL_NONE,-1); }
        sqlite3_finalize(st); } }

    { sqlite3_stmt *st=NULL; sqlite3_prepare_v2(c,
        "SELECT e.to_addr,COALESCE(s.name,'') FROM cfg_edges e "
        "LEFT JOIN symbols s ON s.address=e.to_addr "
        "WHERE e.from_addr BETWEEN ?1 AND ?2 AND e.edge_type='call' LIMIT 32",
        -1,&st,NULL);
      if(st){ sqlite3_bind_int64(st,1,(sqlite3_int64)sa); sqlite3_bind_int64(st,2,(sqlite3_int64)fe); int f=0;
        while(sqlite3_step(st)==SQLITE_ROW){ if(!f){ fields_add(pd,"── Outgoing Calls ──",0,0,DETAIL_NONE,-1); f=1; }
          uint64_t to=(uint64_t)sqlite3_column_int64(st,0); const char *sn=(const char*)sqlite3_column_text(st,1);
          snprintf(buf,sizeof(buf),"  → 0x%lx  %s",(unsigned long)real_a(to),sn&&sn[0]?sn:"sub_?");
          fields_add(pd,buf,1,0,DETAIL_NONE,-1); }
        sqlite3_finalize(st); } }

    fields_add(pd,"── [h]=back ──",0,0,DETAIL_NONE,-1);
    return pd->count;
}

int decompile_function_at(uint64_t addr, PanelData *pd)
{
    if (!g_active_db) return -1;
    sqlite3 *c = (sqlite3 *)db_conn(g_active_db);
    if (!c) return -1;
    return decompile_addr_detail(c, addr, pd);
}
