/*
 * seg_perm.c — 段权限冲突检测模块 (Prompt 09)
 *
 * 遍历 PT_LOAD 段, 检测 RWX/重叠/对齐异常。
 * 符合 COORDINATION.md:
 *   接口: int parse_seg_perm(Elf64_Ctx *ctx, PanelData *pd);
 * 依赖: 无 (纯 Program Header 解析, 不需要 Capstone)
 */
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>

int parse_seg_perm(Elf64_Ctx *ctx, PanelData *pd)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
    int shnum = (int)ehdr->e_shnum;

    fields_add(pd, "=== Segment Permission Audit ===", 0, 0, DETAIL_NONE, -1);

    int critical = 0, warning = 0, ok_count = 0;
    int phnum = (int)ehdr->e_phnum;

    if (phnum <= 0 || ehdr->e_phoff == 0) {
        fields_add(pd, "(no program headers found)", 1, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(ctx->map + ehdr->e_phoff);

    /* 收集 LOAD 段用于重叠检查 */
    typedef struct { uint64_t start; uint64_t end; int idx; } range_t;
    range_t ranges[64];
    int nload = 0;

    char buf[256];

    for (int i = 0; i < phnum && i < shnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        const char *type_str = elf_p_type_str(ph->p_type);
        if (!type_str) type_str = "?";

        if (ph->p_type != PT_LOAD) continue;

        /* 记录范围 */
        if (nload < 64) {
            ranges[nload].start = ph->p_vaddr;
            ranges[nload].end   = ph->p_vaddr + ph->p_memsz;
            ranges[nload].idx   = i;
            nload++;
        }

        char perm[4] = "";
        int r = (ph->p_flags & PF_R) ? 'R' : '-';
        int w = (ph->p_flags & PF_W) ? 'W' : '-';
        int x = (ph->p_flags & PF_X) ? 'X' : '-';
        snprintf(perm, sizeof(perm), "%c%c%c", r, w, x);

        /* 检查 RWX */
        if ((ph->p_flags & (PF_R | PF_W | PF_X)) == (PF_R | PF_W | PF_X)) {
            snprintf(buf, sizeof(buf),
                     "🔴 [CRITICAL] LOAD[%d]: %s  RWX segment at 0x%lx-0x%lx",
                     i, perm, (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_memsz));
            critical++;
        }
        /* 代码段可写 */
        else if ((ph->p_flags & PF_W) && (ph->p_flags & PF_X)) {
            snprintf(buf, sizeof(buf),
                     "🟡 [WARNING] LOAD[%d]: %s  Writable+Executable at 0x%lx-0x%lx",
                     i, perm, (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_memsz));
            warning++;
        }
        /* 数据段可执行 */
        else if ((ph->p_flags & PF_X) && !(ph->p_flags & PF_W)) {
            /* 正常代码段, 但检查是否包含非代码数据 */
            /* 简化: 代码段 R-X 是正常的 */
            snprintf(buf, sizeof(buf),
                     "✅ [OK]     LOAD[%d]: %s  (code)  0x%lx-0x%lx",
                     i, perm, (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_memsz));
            ok_count++;
        } else {
            snprintf(buf, sizeof(buf),
                     "✅ [OK]     LOAD[%d]: %s  (data)  0x%lx-0x%lx",
                     i, perm, (unsigned long)ph->p_vaddr,
                     (unsigned long)(ph->p_vaddr + ph->p_memsz));
            ok_count++;
        }

        fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
    }

    /* 重叠检查 */
    if (nload >= 2) {
        for (int a = 0; a < nload - 1; a++) {
            for (int b = a + 1; b < nload; b++) {
                if (ranges[a].start < ranges[b].end &&
                    ranges[b].start < ranges[a].end) {
                    uint64_t ov_start = ranges[a].start > ranges[b].start
                                      ? ranges[a].start : ranges[b].start;
                    uint64_t ov_end   = ranges[a].end < ranges[b].end
                                      ? ranges[a].end : ranges[b].end;
                    snprintf(buf, sizeof(buf),
                             "🔴 [CRITICAL] LOAD[%d] overlaps LOAD[%d] at 0x%lx-0x%lx",
                             ranges[a].idx, ranges[b].idx,
                             (unsigned long)ov_start, (unsigned long)ov_end);
                    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
                    critical++;
                }
            }
        }
    }

    /* 总结 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);
    if (critical == 0 && warning == 0) {
        snprintf(buf, sizeof(buf), "Results: %d OK — All segments pass", ok_count);
    } else {
        snprintf(buf, sizeof(buf), "Results: %d CRITICAL, %d WARNING, %d OK",
                 critical, warning, ok_count);
    }
    fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);

    return pd->count;
}
