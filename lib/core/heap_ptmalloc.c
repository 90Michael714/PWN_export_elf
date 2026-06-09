/*
 * heap_ptmalloc.c — glibc ptmalloc 分配器解析器
 *
 * 实现 allocator_parser 接口: detect + parse_chunks + consistency
 * 不假设 chunk 布局 — 逐字节读取 + 验证 + 写入 DB
 */

#include "core/heap_analyzer.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* glibc chunk 物理结构 */
#define PREV_INUSE     0x1
#define IS_MMAPPED     0x2
#define NON_MAIN_ARENA 0x4
#define SIZE_MASK      (~(uint64_t)0x7)

#define TCACHE_MAX_BINS 64
#define FASTBIN_MAX_IDX 10  /* glibc 2.35: bins 0-9 (16-160 bytes) */

/* ── detect: 检查 /proc/pid/maps 中是否链接了 libc ── */
static int ptmalloc_detect(struct DebugState *ds) {
    if (!ds) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[512]; int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libc") || strstr(line, "libc.so")) { found = 1; break; }
    }
    fclose(fp);
    return found;
}

/* ── 读 tcache_perthread_struct ── */
static uint64_t heap_base_addr = 0;

static int parse_tcache(struct DebugState *ds, AnalysisDB *adb, int sid,
                        uint64_t tcache_addr) {
    /* tcache_perthread_struct 布局 (glibc 2.35):
     *   counts[64]  (uint16_t × 64 = 128 bytes)
     *   entries[64] (uint64_t × 64 = 512 bytes)
     * Total: 640 bytes
     */
    uint8_t buf[640];
    if (debug_readmem(ds, tcache_addr, buf, sizeof(buf)) != sizeof(buf))
        return -1;

    uint16_t *counts = (uint16_t *)buf;
    uint64_t *entries = (uint64_t *)(buf + 128);

    for (int i = 0; i < TCACHE_MAX_BINS; i++) {
        int cnt = (int)counts[i];
        if (cnt == 0 || cnt > 7) continue;  /* tcache 最多 7 个 */
        uint64_t head = entries[i];
        if (head == 0 || head < heap_base_addr) continue;

        /* 遍历 tcache 单链表 (最多 cnt 个节点) */
        uint64_t cur = head, prev = 0;
        for (int j = 0; j < cnt && cur != 0 && cur >= heap_base_addr; j++) {
            /* 读 fd 指针 (tcache chunk 的 fd 在用户数据区偏移 0) */
            uint64_t fd = 0;
            if (debug_readmem(ds, cur, &fd, 8) != 8) break;
            /* 写链接边 */
            if (prev) heap_link_insert(adb, sid, prev, cur, "tcache");
            prev = cur;
            cur = fd;
        }
    }
    return 0;
}

/* ── parse_chunks: 线性遍历 ptmalloc chunk 链 ── */
static int ptmalloc_parse_chunks(struct DebugState *ds,
                                  memory_region_t *regions, int nregions,
                                  AnalysisDB *adb, int session_id) {
    if (!ds || !regions || !adb) return -1;

    for (int ri = 0; ri < nregions; ri++) {
        uint64_t addr = regions[ri].start;
        uint64_t end  = regions[ri].end;
        if (addr == 0 || end <= addr) continue;

        heap_base_addr = addr;  /* 记录 heap 基址 */

        uint64_t prev_chunk_size = 0;
        int chunk_idx = 0;

        while (addr < end && chunk_idx < 10000) {
            /* 读 chunk 头部: prev_size (8) + size (8) */
            uint64_t header[2];
            if (debug_readmem(ds, addr, header, 16) != 16) break;

            uint64_t prev_size = header[0];  /* 仅 PREV_INUSE=0 时有效 */
            uint64_t size_field = header[1];
            uint64_t chunk_size = size_field & SIZE_MASK;
            int flags = (int)(size_field & 0x7);

            /* 基本合法性检查 */
            if (chunk_size == 0 || chunk_size > (end - addr) || chunk_size < 0x20) break;

            /* 判断状态 */
            int allocated = (flags & PREV_INUSE) ? 1 : 0;
            /* 更准确的状态: 读取后一个 chunk 的 PREV_INUSE 位 */
            if (addr + chunk_size < end) {
                uint64_t next_header[2];
                if (debug_readmem(ds, addr + chunk_size, next_header, 16) == 16) {
                    uint64_t next_flags = next_header[1] & 0x7;
                    if (next_flags & PREV_INUSE)
                        allocated = 1;  /* 后一个chunk认为此chunk已使用 */
                    else
                        allocated = 0;  /* 后一个chunk认为此chunk已释放 */
                }
            }

            /* 写入 chunk */
            uint64_t user_size = chunk_size - 16;  /* 减去头部 */
            heap_chunk_insert(adb, session_id, addr + 16, user_size,
                              allocated, prev_size, flags);

            /* free chunk: 读 fd 指针创建链表边 */
            if (!allocated && user_size >= 16) {
                uint64_t fd = 0;
                debug_readmem(ds, addr + 16, &fd, 8);
                if (fd > heap_base_addr)
                    heap_link_insert(adb, session_id, addr + 16, fd, "free_list");
                /* 物理相邻边 */
                if (chunk_idx > 0)
                    heap_link_insert(adb, session_id,
                        addr - prev_chunk_size + 16, addr + 16, "next_chunk");
            } else if (chunk_idx > 0) {
                heap_link_insert(adb, session_id,
                    addr - prev_chunk_size + 16, addr + 16, "next_chunk");
            }

            prev_chunk_size = chunk_size;
            addr += chunk_size;
            chunk_idx++;
        }
    }
    return 0;
}

/* ── consistency: ptmalloc 特有检查 ── */
static int ptmalloc_consistency(struct DebugState *ds, AnalysisDB *adb, int sid) {
    (void)ds;
    return heap_consistency_run(adb, sid);
}

/* ── 注册到全局解析器列表 ── */
allocator_parser_t ptmalloc_parser = {
    .name         = "ptmalloc",
    .detect       = ptmalloc_detect,
    .parse_chunks = ptmalloc_parse_chunks,
    .consistency  = ptmalloc_consistency,
};

/* jemalloc 解析器声明 (定义在 heap_jemalloc.c) */
extern allocator_parser_t jemalloc_parser;

allocator_parser_t *allocator_parsers[] = {
    &ptmalloc_parser,
    &jemalloc_parser,   /* jemalloc (lib/core/heap_jemalloc.c) */
    NULL  /* 未来: &tcmalloc_parser, &mimalloc_parser */
};

allocator_parser_t *heap_detect_allocator(struct DebugState *ds) {
    for (int i = 0; allocator_parsers[i]; i++)
        if (allocator_parsers[i]->detect(ds))
            return allocator_parsers[i];
    return &ptmalloc_parser;  /* 默认 */
}
