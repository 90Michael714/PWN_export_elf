/*
 * func_boundary.c — Function Boundary Scanner (streaming edition)
 *
 * No temp arrays, no sorting, no truncation.
 * Streams functions directly to PanelData from symtab + dynsym + prologue scan.
 */

#include "elf_parser.h"
#include <string.h>
#include <stdio.h>

static const uint8_t PROLOGUE_1[] = {0xf3,0x0f,0x1e,0xfa,0x55};
static const uint8_t PROLOGUE_2[] = {0x55,0x48,0x89,0xe5};
static const uint8_t PROLOGUE_3[] = {0x55,0x48,0x83};

int parse_func_boundary(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    (void)shdr_idx;
    int shnum = (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
    char buf[256];
    int from_symtab=0, from_dynsym=0, from_prologue=0, total=0;

    fields_add(pd,"=== Function Boundary Scan ===",0,0,DETAIL_NONE,-1);

    /* Stream symbols directly to PanelData */
    for (int pass=0; pass<2; pass++) {
        Elf64_Word want = (pass==0)?SHT_SYMTAB:SHT_DYNSYM;
        for (int si=0; si<shnum; si++) {
            Elf64_Shdr *sh=elf_get_shdr(ctx,si);
            if(!sh||sh->sh_type!=want)continue;
            Elf64_Shdr *st=elf_get_shdr(ctx,sh->sh_link);
            if(!st)continue;
            Elf64_Sym *sym=(Elf64_Sym*)(ctx->map+sh->sh_offset);
            int ns=(int)(sh->sh_size/sizeof(Elf64_Sym));
            for(int j=0;j<ns;j++){
                if(ELF64_ST_TYPE(sym[j].st_info)!=STT_FUNC)continue;
                if(sym[j].st_value==0)continue;
                const char *n=elf_strtab_get(ctx,st->sh_offset,sym[j].st_name);
                const char *nm=(n&&n[0])?n:"(unnamed)";
                int is_exp=(ELF64_ST_BIND(sym[j].st_info)==STB_GLOBAL||
                            ELF64_ST_BIND(sym[j].st_info)==STB_WEAK);
                char sz[24]="?";uint64_t ss=sym[j].st_size;
                if(ss>=1024)snprintf(sz,sizeof(sz),"%luKB",(unsigned long)ss/1024);
                else if(ss>0)snprintf(sz,sizeof(sz),"%luB",(unsigned long)ss);
                snprintf(buf,sizeof(buf),"[%04d] 0x%lx %6s %-40s %s",
                         total,(unsigned long)sym[j].st_value,sz,nm,is_exp?"EXPORT":"");
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)sym[j].st_value);
                total++;
                if(pass==0)from_symtab++;else from_dynsym++;
            }
        }
    }

    /* Stream prologue hits directly to PanelData */
    for(int si=0;si<shnum;si++){
        Elf64_Shdr *sh=elf_get_shdr(ctx,si);
        if(!sh||!(sh->sh_flags&SHF_EXECINSTR)||sh->sh_size<5)continue;
        const uint8_t *d=ctx->map+sh->sh_offset;
        size_t sz=sh->sh_size;uint64_t a=sh->sh_addr;
        for(size_t off=0;off+5<=sz;off++){
            int m=0;
            if(off+5<=sz&&!memcmp(d+off,PROLOGUE_1,5))m=1;
            else if(off+4<=sz&&!memcmp(d+off,PROLOGUE_2,4))m=2;
            else if(d[off]==0x55&&off+3<=sz&&!memcmp(d+off,PROLOGUE_3,3))m=1;
            if(m){
                snprintf(buf,sizeof(buf),"[%04d] 0x%lx %6s sub_%lx",
                         total,(unsigned long)(a+off),"?",(unsigned long)(a+off));
                fields_add(pd,buf,1,1,DETAIL_NONE,(int)(a+off));
                total++;from_prologue++;
            }
        }
    }

    fields_add(pd,"─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─",0,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"Total: %d (symtab:%d dynsym:%d prologue:%d)",
             total,from_symtab,from_dynsym,from_prologue);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    return pd->count;
}
