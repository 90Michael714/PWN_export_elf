/*
 * got_plt.c — GOT/PLT 表完整解析模块 (Prompt 02, v3)
 *
 * ── 架构 ──
 * .plt       过程链接表 (跳转桩代码)
 * .got.plt   全局偏移表 (函数指针数组, 延迟绑定)
 * .rela.plt  重定位表 (GOT槽位 → dynsym 索引 → 符号名)
 * .dynsym    动态符号表
 * .dynstr    动态字符串表
 *
 * ── 关系 ──
 * call printf@plt  →  PLT[0] header (resolver)
 *                    PLT[1] stub for func1
 *                      → jmp [GOT[3]]    (首次: 指向 PLT resolver)
 *                      → 首次调用后 GOT[3] = 真实的 libc printf 地址
 *
 * ── 漏洞研究价值 ──
 * 1. GOT 覆写: Partial RELRO → GOT 可写 → 劫持函数指针
 * 2. 导入函数审计: 列出所有外部依赖, 识别潜在危险函数
 * 3. PLT 签名: 识别导入函数模式 (如 crypto 相关、网络 I/O)
 *
 * 符合 COORDINATION.md: int parse_got_plt(Elf64_Ctx*, int shdr_idx, PanelData*);
 * 依赖: 无 (纯 ELF 解析)
 */
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>

typedef struct { Elf64_Shdr *sec; int idx; } sec_t;

static int get_shnum(Elf64_Ctx *ctx) {
    return (int)((Elf64_Ehdr *)ctx->map)->e_shnum;
}

static sec_t find_sec(Elf64_Ctx *ctx, const char *name) {
    int shnum = get_shnum(ctx);
    sec_t r = {NULL, -1};
    if (!name) return r;
    for (int i = 0; i < shnum; i++) {
        const char *n = elf_section_name(ctx, i);
        if (n && strcmp(n, name) == 0) {
            r.sec = elf_get_shdr(ctx, i); r.idx = i; return r;
        }
    }
    return r;
}

static sec_t find_sec_by_type(Elf64_Ctx *ctx, Elf64_Word type) {
    int shnum = get_shnum(ctx);
    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, i);
        if (sh && sh->sh_type == type) { sec_t r = {sh, i}; return r; }
    }
    sec_t r = {NULL, -1}; return r;
}

/* ── RELRO 检测 ── */
typedef enum { RELRO_NONE, RELRO_PARTIAL, RELRO_FULL } relro_t;

static relro_t detect_relro(Elf64_Ctx *ctx) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
    int has_relro = 0, has_bind_now = 0;
    for (int i = 0; i < (int)ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        if (ph && ph->p_type == PT_GNU_RELRO) has_relro = 1;
    }
    sec_t dyn = find_sec_by_type(ctx, SHT_DYNAMIC);
    if (dyn.sec && dyn.sec->sh_entsize > 0) {
        Elf64_Dyn *e = (Elf64_Dyn *)(ctx->map + dyn.sec->sh_offset);
        int n = (int)(dyn.sec->sh_size / sizeof(Elf64_Dyn));
        for (int i = 0; i < n; i++)
            if (e[i].d_tag == DT_FLAGS && (e[i].d_un.d_val & 8)) has_bind_now = 1;
    }
    sec_t got = find_sec(ctx, ".got.plt");
    if (!got.sec) got = find_sec(ctx, ".got");
    int got_in_relro = 0;
    if (has_relro && got.sec)
        for (int i = 0; i < (int)ehdr->e_phnum; i++) {
            Elf64_Phdr *ph = elf_get_phdr(ctx, i);
            if (ph && ph->p_type == PT_GNU_RELRO &&
                got.sec->sh_addr >= ph->p_vaddr &&
                got.sec->sh_addr < ph->p_vaddr + ph->p_memsz)
                { got_in_relro = 1; break; }
        }
    if (has_bind_now && got_in_relro) return RELRO_FULL;
    if (got_in_relro) return RELRO_PARTIAL;
    return RELRO_NONE;
}

/* ── PLT → GOT 映射 ── */
static uint64_t plt_entry_get_got(const uint8_t *plt_data, size_t plt_size,
                                   uint64_t plt_base, size_t entry_offset) {
    if (entry_offset + 10 > plt_size) return 0;
    const uint8_t *p = plt_data + entry_offset;
    if (p[0]==0xf3 && p[1]==0x0f && p[2]==0x1e && p[3]==0xfa) p += 4;
    if (p[0]==0xff && p[1]==0x25) {
        int32_t disp = *(int32_t *)(p + 2);
        uint64_t rip = plt_base + entry_offset + (size_t)(p - plt_data) + 6;
        return rip + (int64_t)disp;
    }
    return 0;
}

static int map_plt_to_got(Elf64_Ctx *ctx, uint64_t *got_targets, int max) {
    sec_t plt = find_sec(ctx, ".plt");
    if (!plt.sec || plt.sec->sh_size < 16) return 0;
    const uint8_t *data = ctx->map + plt.sec->sh_offset;
    size_t size = plt.sec->sh_size;
    int count = 0;
    uint64_t plt_base = plt.sec->sh_addr;
    for (size_t off = 16; off + 10 <= size && count < max; off += 16) {
        uint64_t a = plt_entry_get_got(data, size, plt_base, off);
        if (a > 0) got_targets[count++] = a;
    }
    return count;
}

/* ── 公共接口 ── */
int parse_got_plt(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd) {
    (void)shdr_idx;
    sec_t got = find_sec(ctx, ".got.plt");
    if (!got.sec) got = find_sec(ctx, ".got");  /* Full RELRO 没有 .got.plt */
    sec_t rela = find_sec(ctx, ".rela.plt");
    if (!rela.sec) rela = find_sec(ctx, ".rela.dyn");  /* fallback */
    sec_t plt = find_sec(ctx, ".plt");
    sec_t dynsym = find_sec_by_type(ctx, SHT_DYNSYM);
    sec_t dynstr = {NULL, -1};
    if (dynsym.sec) { dynstr.sec = elf_get_shdr(ctx, dynsym.sec->sh_link); dynstr.idx = (int)dynsym.sec->sh_link; }

    if (!got.sec || got.sec->sh_size == 0) {
        fields_add(pd, "(no .got.plt section — static binary?)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }
    char buf[384];
    relro_t relro = detect_relro(ctx);
    const char *rs[] = {"NONE","PARTIAL","FULL"};
    snprintf(buf,sizeof(buf),"=== GOT/PLT Analysis (RELRO: %s) ===", rs[relro]);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    if (relro==RELRO_NONE) fields_add(pd,"GOT is WRITABLE (overwrite possible)",1,0,DETAIL_NONE,-1);
    else if (relro==RELRO_PARTIAL) fields_add(pd,"Partial RELRO — .got.plt writable",1,0,DETAIL_NONE,-1);
    else fields_add(pd,"Full RELRO — GOT read-only after relocation",1,0,DETAIL_NONE,-1);

    if (plt.sec) { snprintf(buf,sizeof(buf),".plt: at 0x%lx (%luB)",(unsigned long)plt.sec->sh_addr,(unsigned long)plt.sec->sh_size); fields_add(pd,buf,1,0,DETAIL_NONE,-1); }
    snprintf(buf,sizeof(buf),".got.plt: at 0x%lx (%luB, %d entries)",(unsigned long)got.sec->sh_addr,(unsigned long)got.sec->sh_size,(int)(got.sec->sh_size/sizeof(Elf64_Addr))); fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    if (rela.sec) snprintf(buf,sizeof(buf),".rela.plt: at 0x%lx (%luB, %d reloc)",(unsigned long)rela.sec->sh_addr,(unsigned long)rela.sec->sh_size,(int)(rela.sec->sh_size/sizeof(Elf64_Rela))); else snprintf(buf,sizeof(buf),".rela.plt: NOT FOUND"); fields_add(pd,buf,1,0,DETAIL_NONE,-1);

    #define MAX_S 512
    uint64_t plt_got[MAX_S]; int n_plt = map_plt_to_got(ctx, plt_got, MAX_S);
    typedef struct { Elf64_Addr a; const char *n; } slot_t;
    slot_t slots[MAX_S]; int nslots = 0;
    if (rela.sec && dynsym.sec && dynstr.sec) {
        Elf64_Rela *r = (Elf64_Rela *)(ctx->map + rela.sec->sh_offset);
        int nr = (int)(rela.sec->sh_size / sizeof(Elf64_Rela));
        Elf64_Sym *s = (Elf64_Sym *)(ctx->map + dynsym.sec->sh_offset);
        for (int i=0; i<nr && nslots<MAX_S; i++) {
            uint32_t si = (uint32_t)(r[i].r_info >> 32);
            if (si*sizeof(Elf64_Sym) < dynsym.sec->sh_size) {
                slots[nslots].a = r[i].r_offset;
                const char *nm = elf_strtab_get(ctx, dynstr.sec->sh_offset, s[si].st_name);
                slots[nslots].n = nm ? nm : "?"; nslots++;
            }
        }
    }

    Elf64_Addr *ge = (Elf64_Addr *)(ctx->map + got.sec->sh_offset);
    int gc = (int)(got.sec->sh_size / sizeof(Elf64_Addr));
    fields_add(pd,"─── Reserved ───",0,0,DETAIL_NONE,-1);
    const char *rd[] = {"[_DYNAMIC]→.dynamic","[link_map]→linker data","[_dl_runtime_resolve]→resolver"};
    for (int i=0; i<3 && i<gc; i++) {
        Elf64_Addr ga = got.sec->sh_addr + (Elf64_Word)(i*sizeof(Elf64_Addr));
        snprintf(buf,sizeof(buf),"GOT[%d]: 0x%lx → 0x%lx  %s",i,(unsigned long)ga,(unsigned long)ge[i],rd[i]);
        fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    }
    fields_add(pd,"─── Imported Functions ───",0,0,DETAIL_NONE,-1);
    for (int i=3; i<gc; i++) {
        Elf64_Addr ga = got.sec->sh_addr + (Elf64_Word)(i*sizeof(Elf64_Addr));
        const char *sn = "?"; for (int s=0; s<nslots; s++) if (slots[s].a==ga) {sn=slots[s].n;break;}
        uint64_t pa = 0; for (int p=0; p<n_plt; p++) if (plt_got[p]==ga) {pa=plt.sec->sh_addr+16+(uint64_t)(p*16);break;}
        const char *st = ge[i]==0?"(lazy)":(pa>0&&ge[i]==pa+6?"(resolver)":"(resolved)");
        char pl[32]=""; if (pa>0) snprintf(pl,sizeof(pl),"PLT@0x%lx",(unsigned long)pa); else snprintf(pl,sizeof(pl),"(no PLT)");
        snprintf(buf,sizeof(buf),"GOT[%d]: 0x%lx → %-24s  %17s  %s",i,(unsigned long)ga,sn,pl,st);
        fields_add(pd,buf,1,1,DETAIL_NONE,(int)ga);
    }
    fields_add(pd,"──────────────",0,0,DETAIL_NONE,-1);
    snprintf(buf,sizeof(buf),"Summary: %d imports, %d PLT entries, RELRO: %s", gc-3, n_plt, rs[relro]);
    fields_add(pd,buf,1,0,DETAIL_NONE,-1);
    if (relro!=RELRO_FULL) fields_add(pd,"[!] GOT overwrite possible via arbitrary-write",1,0,DETAIL_NONE,-1);
    return pd->count;
}
