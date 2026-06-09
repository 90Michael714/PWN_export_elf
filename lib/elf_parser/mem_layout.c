/*
 * mem_layout.c — 虚拟地址空间布局
 *
 * 功能: 将 ELF 的 Program Header 中 PT_LOAD 段在虚拟地址空间中的
 * 映射关系以紧凑对齐的表格形式展示出来。
 *
 * 安全研究用途:
 *   这是内核 ELF 加载器 (fs/binfmt_elf.c) 看到的视角 ——
 *   每个 PT_LOAD 段通过 mmap() 映射到虚拟地址空间, 权限由 p_flags 决定。
 *   可以一眼看出:
 *     - 代码/数据/只读数据各自的范围和权限
 *     - 是否存在 W^X 违规 (可写+可执行段, 便于注入 shellcode)
 *     - 段之间是否有空隙 (gap, 可能被利用做 heap-spray 或其他攻击)
 *     - .bss 零填充区域的范围
 *     - 栈是否可执行
 *     - RELRO 是否保护了 GOT 表
 *
 * 接口: int parse_mem_layout(Elf64_Ctx *ctx, PanelData *pd);
 */
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_SEGS 32
#define MAX_DESC 200

typedef struct {
    uint64_t start, end, filesz;
    Elf64_Word flags;
    char     desc[MAX_DESC];
    int      has_entry;
} seg_t;

static int seg_cmp(const void *a, const void *b) {
    return ((const seg_t *)a)->start < ((const seg_t *)b)->start ? -1 : 1;
}

static int keep_sec(const char *n) {
    if (!n || !*n) return 0;
    static const char *drop[] = {
        ".shstrtab",".symtab",".strtab",".dynstr",".comment",
        ".gnu.hash",".gnu.version",".gnu.version_r",".note.gnu",
        ".note.ABI",".debug_",".zdebug_",".eh_frame_hdr",".rela.",".rel.",
        NULL
    };
    for (const char **p = drop; *p; p++)
        if (strncmp(n, *p, strlen(*p)) == 0) return 0;
    return 1;
}

static void fmt_sz(uint64_t b, char *o, size_t os) {
    if      (b >= 1048576) snprintf(o, os, "%.1fM", (double)b/1048576.0);
    else if (b >= 1024)    snprintf(o, os, "%luK",  (unsigned long)(b/1024));
    else                   snprintf(o, os, "%luB",  (unsigned long)b);
}

static const char *seg_tag(Elf64_Word f) {
    int r = (f & PF_R), w = (f & PF_W), x = (f & PF_X);
    if (r &&  x && !w) return "CODE";
    if (r && !x && !w) return "RO";
    if (r &&  w && !x) return "DATA";
    if (r &&  w &&  x) return "RWX";
    return "SEG";
}

int parse_mem_layout(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *eh = (Elf64_Ehdr *)ctx->map;
    int phnum = (int)eh->e_phnum, shnum = (int)eh->e_shnum;
    Elf64_Phdr *ph = (Elf64_Phdr *)(ctx->map + eh->e_phoff);

    /* ── 收集 LOAD 段 ──────────────────────────────────────── */
    seg_t segs[MAX_SEGS]; int nseg = 0;
    for (int i = 0; i < phnum && nseg < MAX_SEGS; i++) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) continue;
        seg_t *s = &segs[nseg];
        memset(s, 0, sizeof(*s));
        s->start = ph[i].p_vaddr; s->end = ph[i].p_vaddr + ph[i].p_memsz;
        s->filesz = ph[i].p_filesz; s->flags = ph[i].p_flags;
        s->has_entry = (eh->e_entry >= s->start && eh->e_entry < s->end);
        int dl = 0;
        for (int si = 0; si < shnum && dl < MAX_DESC - 30; si++) {
            Elf64_Shdr *shdr = elf_get_shdr(ctx, si);
            if (!shdr || shdr->sh_size == 0) continue;
            if (!(shdr->sh_flags & SHF_ALLOC)) continue;
            if (shdr->sh_addr >= s->start && shdr->sh_addr < s->end) {
                const char *sn = elf_section_name(ctx, si);
                if (sn && keep_sec(sn))
                    dl += snprintf(s->desc+dl, (size_t)(MAX_DESC-dl),
                                   "%s%s", dl?" ": "", sn);
            }
        }
        nseg++;
    }
    if (!nseg) { fields_add(pd, "(no LOAD segments)", 0, 0, DETAIL_NONE, -1); return pd->count; }
    qsort(segs, (size_t)nseg, sizeof(seg_t), seg_cmp);

    uint64_t base = segs[0].start, vtop = segs[nseg-1].end;

    /* ── 输出 ──────────────────────────────────────────────── */
    char buf[512], szs[12], addrs[44];
    fields_add(pd, "=== Virtual Address Space Layout ===", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "  base 0x%lx  top 0x%lx  %s",
             (unsigned long)base, (unsigned long)vtop,
             (eh->e_type == ET_DYN) ? "(PIE/ASLR)" : "(fixed)");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 表头 */
    fields_add(pd, "  segment   address range          size   perm  contents",
               0, 0, DETAIL_NONE, -1);
    fields_add(pd, "  ───────  ────────────────────  ──────  ────  ────────",
               0, 0, DETAIL_NONE, -1);

    int wx = 0; size_t total = 0;
    for (int i = 0; i < nseg; i++) {
        seg_t *s = &segs[i];
        uint64_t sz = s->end - s->start; total += sz;

        /* gap */
        if (i > 0 && s->start > segs[i-1].end) {
            fmt_sz(s->start - segs[i-1].end, szs, sizeof(szs));
            snprintf(buf, sizeof(buf), "  %-7s  (%s unmapped)", " ", szs);
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        }

        /* perm */
        char perm[4] = "---";
        if (s->flags & PF_R) perm[0] = 'r';
        if (s->flags & PF_W) perm[1] = 'w';
        if (s->flags & PF_X) perm[2] = 'x';
        if ((s->flags & PF_W) && (s->flags & PF_X)) wx = 1;

        /* addresses compact: 0xS-0xE */
        uint64_t os = s->start - base, oe = s->end - base;
        snprintf(addrs, sizeof(addrs), "0x%lx-0x%lx", (unsigned long)os, (unsigned long)oe);

        fmt_sz(sz, szs, sizeof(szs));

        /* 主行: [TAG] addrs SIZE perm sections */
        snprintf(buf, sizeof(buf), "  [%-4s]  %-20s  %6s  %s  %s",
                 seg_tag(s->flags), addrs, szs, perm,
                 s->desc[0] ? s->desc : "");
        fields_add(pd, buf, 0, 1, DETAIL_NONE, -1);

        /* entry / bss sub-lines */
        if (s->has_entry) {
            snprintf(buf, sizeof(buf), "          ★ entry 0x%lx",
                     (unsigned long)(eh->e_entry - base));
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
        if (s->filesz > 0 && s->filesz < sz) {
            snprintf(buf, sizeof(buf), "          file %luK + zero-fill %luK",
                     (unsigned long)(s->filesz/1024),
                     (unsigned long)((sz - s->filesz)/1024));
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        }
    }

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* stack / relro */
    int exe_stk = 0;
    for (int i = 0; i < phnum; i++) {
        if (ph[i].p_type == PT_GNU_STACK) {
            exe_stk = (ph[i].p_flags & PF_X);
            snprintf(buf, sizeof(buf), "  [%-4s]  %-20s  %6s  %s  %s",
                     "STK", " ", " ", exe_stk ? "RWX" : "RW",
                     exe_stk ? "(executable!)" : "(NX)");
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        }
        if (ph[i].p_type == PT_GNU_RELRO) {
            uint64_t rs = ph[i].p_vaddr - base;
            uint64_t re = ph[i].p_vaddr + ph[i].p_memsz - base;
            snprintf(addrs, sizeof(addrs), "0x%lx-0x%lx", (unsigned long)rs, (unsigned long)re);
            snprintf(buf, sizeof(buf), "  [%-4s]  %-20s  %6luK  %s  %s",
                     "RLRO", addrs,
                     (unsigned long)(ph[i].p_memsz/1024),
                     "r--", "(GOT read-only)");
            fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
        }
    }

    /* 总结 */
    fmt_sz(total, szs, sizeof(szs));
    snprintf(buf, sizeof(buf), "  %-7s  %s total, %d LOAD segments  %s%s",
             " ", szs, nseg,
             wx ? "⚠ W^X" : "✓ W^X clean",
             exe_stk ? "  ⚠ exec-stack" : "");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    return pd->count;
}
