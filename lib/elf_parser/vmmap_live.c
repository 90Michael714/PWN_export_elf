#include "elf_parser.h"
/*
 * vmmap_live.c — 运行时内存映射查看器 (依赖: debug_worker.h)
 *
 * 读取 /proc/<pid>/maps, 解析并格式化显示。
 * 每行: 地址范围 + 权限 + 偏移 + 设备 + inode + 路径
 *
 * 用途:
 *   - 查看 libc 加载基址 (ASLR 绕过第一步)
 *   - 查看堆栈位置和权限
 *   - 查找可写可执行区域 (RWX)
 *   - 确认 PIE/ASLR 是否生效
 *
 * API:
 *   void vmmap_show(const DebugState *ds);
 *   int  vmmap_find_base(const DebugState *ds, const char *libname, uint64_t *base);
 *
 * 依赖:
 *   #include "core/debug_worker.h"  (DebugState → pid)
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "core/debug_worker.h" /* 前向声明, 实际由 debug_worker.h 提供 */

/* ================================================================== */
/* /proc/<pid>/maps 行解析                                             */
/* ================================================================== */

typedef struct {
    uint64_t    start;
    uint64_t    end;
    char        perms[5];       /* rwxp */
    uint64_t    offset;
    unsigned int dev_major;
    unsigned int dev_minor;
    unsigned long inode;
    char        path[256];
} vmmap_entry_t;

/** 解析一行 /proc/pid/maps */
static int parse_maps_line(const char *line, vmmap_entry_t *e)
{
    memset(e, 0, sizeof(*e));
    int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255[^\n]",
                   &e->start, &e->end, e->perms,
                   &e->offset, &e->dev_major, &e->dev_minor,
                   &e->inode, e->path);
    if (n < 7) return -1;
    if (n == 7) e->path[0] = '\0'; /* 匿名映射无路径 */
    return 0;
}

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/**
 * 从 /proc/<pid>/maps 读取所有内存映射。
 * @param ds       调试状态 (提供 PID)
 * @param entries  输出: 映射条目数组 (调用者分配, 至少 *count 个)
 * @param count    输入: 数组大小; 输出: 实际条目数
 * @return         0=成功, -1=失败
 */
int vmmap_read(const struct DebugState *ds, vmmap_entry_t *entries,
               int *count)
{
    if (!ds || !entries || !count || *count <= 0) return -1;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    int n = 0;
    int max = *count;

    while (fgets(line, sizeof(line), fp) && n < max) {
        if (parse_maps_line(line, &entries[n]) == 0)
            n++;
    }
    fclose(fp);

    *count = n;
    return 0;
}

/**
 * 查找指定库的加载基址。
 * @param ds       调试状态
 * @param libname  库名 (如 "libc"、"libc.so.6"、"ld-linux")
 * @param base     输出: 基址
 * @return         0=找到, -1=未找到
 */
int vmmap_find_base(const struct DebugState *ds, const char *libname,
                    uint64_t *base)
{
    if (!ds || !libname || !base) return -1;

    vmmap_entry_t entries[256];
    int count = 256;
    if (vmmap_read(ds, entries, &count) != 0) return -1;

    for (int i = 0; i < count; i++) {
        /* 查找路径中包含 libname 且权限含 'x' 的第一个 (代码段基址) */
        if (entries[i].path[0] && strstr(entries[i].path, libname) &&
            entries[i].perms[2] == 'x') {
            *base = entries[i].start;
            return 0;
        }
    }
    return -1;
}

/**
 * 查找堆区域 (标记为 [heap])。
 */
int vmmap_find_heap(const struct DebugState *ds, uint64_t *start, uint64_t *end)
{
    if (!ds || !start || !end) return -1;
    vmmap_entry_t entries[256];
    int count = 256;
    if (vmmap_read(ds, entries, &count) != 0) return -1;
    for (int i = 0; i < count; i++) {
        if (strstr(entries[i].path, "[heap]")) {
            *start = entries[i].start;
            *end   = entries[i].end;
            return 0;
        }
    }
    return -1;
}

/**
 * 检查是否有可写可执行区域 (RWX — 严重安全问题)。
 * @return 找到的 RWX 区域数量
 */
int vmmap_count_rwx(const struct DebugState *ds)
{
    vmmap_entry_t entries[256];
    int count = 256;
    if (vmmap_read(ds, entries, &count) != 0) return 0;
    int n = 0;
    for (int i = 0; i < count; i++)
        if (entries[i].perms[2] == 'x' && entries[i].perms[1] == 'w')
            n++;
    return n;
}

/* ── PanelData wrapper (Phase 6) ───────────────────────────────── */

int vmmap_to_panel(const void *ds_ptr, PanelData *pd)
{
    const struct DebugState *ds = (const struct DebugState *)ds_ptr;
    if (!ds || !pd) return -1;
    vmmap_entry_t entries[256];
    int count = 256;
    if (vmmap_read(ds, entries, &count) != 0) {
        fields_add(pd, "(cannot read /proc/PID/maps)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }
    char buf[512];

    /* ── 标题 (合并 MemSearch 的 Enter hexdump 提示) ── */
    snprintf(buf, sizeof(buf),
             "=== Memory Map (PID %d) ===  [Enter] hexdump  [h] back",
             ds->pid);
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* ── 列标签 (保留 MemSearch 原有格式) ── */
    fields_add(pd, "Start-End              Size     Perms  Region",
               1, 0, DETAIL_NONE, -1);
    fields_add(pd, "──────────────         ──────── ────── ────────────",
               1, 0, DETAIL_NONE, -1);

    unsigned long total_kb = 0;
    for (int i = 0; i < count; i++) {
        vmmap_entry_t *e = &entries[i];
        uint64_t sz = e->end - e->start;
        total_kb += (unsigned long)(sz / 1024);

        /* ── 自适应单位 (合并 MemSearch 的 B/KB/MB/GB 特性) ── */
        const char *unit = "B";
        double dsz = (double)sz;
        if     (dsz >= 1024.0*1024*1024) { dsz /= 1024.0*1024*1024; unit = "GB"; }
        else if(dsz >= 1024.0*1024)      { dsz /= 1024.0*1024;      unit = "MB"; }
        else if(dsz >= 1024.0)           { dsz /= 1024.0;            unit = "KB"; }

        /* ── 段名 (保留路径 basename; 匿名段推测类型) ── */
        const char *seg_name = "anon";
        if (e->path[0]) {
            char *slash = strrchr(e->path, '/');
            seg_name = slash ? slash + 1 : e->path;
        } else {
            if     (e->perms[1] == 'w' && e->start > 0x600000000000ULL)
                seg_name = "[stack]";
            else if(e->perms[1] == 'w')
                seg_name = "[heap]";
            else if(e->perms[2] == 'x')
                seg_name = "[code]";
            else if(e->perms[1] == '-')
                seg_name = "[ro]";
        }

        /* ── 库标签 (保留 VMMap 原有标签特性) ── */
        const char *tag = "";
        if (e->path[0]) {
            if      (strstr(e->path, "[stack]"))     tag = " [STACK]";
            else if (strstr(e->path, "[heap]"))      tag = " [HEAP]";
            else if (strstr(e->path, "libc"))        tag = " [LIBC]";
            else if (strstr(e->path, "ld-"))         tag = " [LD]";
            else if (strstr(e->path, "libpthread"))  tag = " [PTHREAD]";
            else if (strstr(e->path, "libm"))        tag = " [LIBM]";
            else if (strstr(e->path, "libdl"))       tag = " [LIBDL]";
        }

        snprintf(buf, sizeof(buf),
                 "[%d] 0x%lx-0x%lx  %6.1f%s %-6s %s%s",
                 i,
                 (unsigned long)e->start, (unsigned long)e->end,
                 dsz, unit, e->perms, seg_name, tag);
        fields_add(pd, buf, 0, 1, DETAIL_NONE, i);
    }

    /* ── 汇总行 (保留 VMMap 原有汇总特性) ── */
    snprintf(buf, sizeof(buf),
             "── %d segments, total mapped: %lu KB (%lu MB)",
             count, total_kb, total_kb / 1024);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    return count;
}
