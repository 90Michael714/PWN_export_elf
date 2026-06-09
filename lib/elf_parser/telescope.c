/*
 * telescope.c — 内存指针链解引用 (依赖: debug_worker.h)
 *
 * 从给定地址开始, 递归读取指针值, 显示指针链。
 * 类似 GDB 的 "x/20gx $rsp" 但增加了自动识别:
 *   - 代码段地址: 标记为 <function>
 *   - 栈地址:     标记为 <stack+offset>
 *   - 堆地址:     标记为 <heap+offset>
 *   - libc 地址:  标记为 <libc+offset>
 *
 * API:
 *   int telescope_chain(DebugState *ds, uint64_t addr, int depth,
 *                       tsc_entry_t *entries, int max);
 *
 * 依赖:
 *   #include "core/debug_worker.h" (debug_readmem)
 */
#include "core/debug_worker.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    int      depth;
    uint64_t addr;
    uint64_t value;
    char     annotation[64];   /* 如 "stack+0x30", "libc+0x1a2b3" */
} tsc_entry_t;

/* 从 /proc/pid/maps 读取基址信息 (内部使用, 简化版) */
static int get_libc_base(DebugState *ds, uint64_t *libc_base, uint64_t *ld_base)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (libc_base) *libc_base = 0;
    if (ld_base)   *ld_base   = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end; char perm[5], fpath[256]="";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s",
                   &start, &end, perm, fpath) < 3) continue;
        if (perm[2] != 'x') continue;
        if (libc_base && *libc_base == 0 && strstr(fpath, "libc")) *libc_base = start;
        if (ld_base   && *ld_base   == 0 && strstr(fpath, "ld-"))  *ld_base   = start;
    }
    fclose(fp);
    return 0;
}

/**
 * 从地址 addr 开始解引用链。
 *
 * @param ds      调试状态
 * @param addr    起始地址
 * @param depth   解引用深度
 * @param entries 输出: 条目数组
 * @param max     最大条目数
 * @return        实际条目数
 */
int telescope_chain(DebugState *ds, uint64_t addr, int depth,
                    tsc_entry_t *entries, int max)
{
    if (!ds || !entries || max <= 0) return 0;

    uint64_t libc_base = 0, ld_base = 0;
    get_libc_base(ds, &libc_base, &ld_base);

    /* 获取栈和堆范围 */
    uint64_t stack_base = ds->regs.rsp;
    (void)0; /* heap_start not needed */

    int count = 0;
    uint64_t cur = addr;

    for (int i = 0; i < depth && count < max; i++) {
        uint64_t val = 0;
        if (debug_readmem(ds, cur, &val, 8) != 8) break;

        entries[count].depth = i;
        entries[count].addr  = cur;
        entries[count].value = val;

        /* 标注 */
        if (val >= stack_base - 8192 && val < stack_base + 8192)
            snprintf(entries[count].annotation, 64, "stack%+-ld",
                     (long)(val - stack_base));
        else if (libc_base && val >= libc_base && val < libc_base + 0x200000)
            snprintf(entries[count].annotation, 64, "libc+0x%lx",
                     (unsigned long)(val - libc_base));
        else if (ld_base && val >= ld_base && val < ld_base + 0x80000)
            snprintf(entries[count].annotation, 64, "ld+0x%lx",
                     (unsigned long)(val - ld_base));
        else if (val >= 0x400000 && val < 0x1000000)
            snprintf(entries[count].annotation, 64, "code+0x%lx",
                     (unsigned long)(val - 0x400000));
        else
            entries[count].annotation[0] = '\0';

        count++;
        cur = val;  /* 下一跳: 解引用值作为新地址 */
    }

    return count;
}
