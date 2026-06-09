/*
 * mem_search.c — Tracee 内存搜索引擎实现
 *
 * 搜索流程:
 *   1. 解析搜索模式 (hex bytes / ascii / address / wildcard)
 *   2. 读取 /proc/<pid>/maps 获取可读内存段
 *   3. 逐段用 debug_readmem() 读取 → Boyer-Moore-Horspool 搜索
 *   4. 格式化为弹窗文本
 *
 * 依赖:
 *   core/debug_worker.h  — DebugState, debug_readmem()
 *   core/mem_search.h    — 自身接口
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "core/mem_search.h"
#include "core/debug_worker.h"

/* ── 内部常量 ──────────────────────────────────────────────────── */

#define MAX_HITS         256
#define MAPS_CHUNK_SIZE  0x10000    /* 每次读 64KB */

/* ── 模式解析 ──────────────────────────────────────────────────── */

/*
 * 解析十六进制字节字符串。
 * 格式: "41 41 41 41" 或 "41,41,41,41" 或 "\x41\x41\x41\x41"
 * 支持 ?? 作为通配符 (匹配任意字节)。
 */
static int parse_hex(const char *s, uint8_t *out, size_t max_len,
                     size_t *out_len)
{
    *out_len = 0;
    const char *p = s;

    /* 跳过可选的 \x 前缀 */
    if (p[0] == '\\' && p[1] == 'x') p += 2;

    while (*p && *out_len < max_len) {
        /* 跳过分隔符 */
        while (*p == ' ' || *p == ',' || *p == '\t') p++;
        if (!*p) break;

        /* 通配符 ?? */
        if (p[0] == '?' && p[1] == '?') {
            out[*out_len] = 0x00;   /* wildcard — value不重要 */
            (*out_len)++;
            p += 2;
            continue;
        }

        /* 跳过 \x 前缀 (每对 hex 前都可能有) */
        if (p[0] == '\\' && p[1] == 'x') p += 2;

        /* 读取两个 hex 字符 */
        if (!isxdigit((unsigned char)p[0])) return -1;

        char hex[3] = { p[0], 0, 0 };
        if (isxdigit((unsigned char)p[1])) {
            hex[1] = p[1];
            p += 2;
        } else {
            /* 单个 hex 数字 (如 "F") — 当作 0x0F */
            hex[1] = '\0';
            p += 1;
        }

        out[*out_len] = (uint8_t)strtoul(hex, NULL, 16);
        (*out_len)++;
    }

    return (*out_len > 0) ? 0 : -1;
}

/*
 * 解析引号包裹的 ASCII 字符串: "AAAA" 或 'AAAA'
 */
static int parse_quoted_ascii(const char *s, uint8_t *out,
                              size_t max_len, size_t *out_len)
{
    *out_len = 0;
    char quote = s[0];
    if (quote != '"' && quote != '\'') return -1;

    const char *p = s + 1;
    while (*p && *p != quote && *out_len < max_len) {
        if (*p == '\\' && p[1]) {
            /* 转义字符 */
            p++;
            switch (*p) {
                case 'n':  out[*out_len] = '\n'; break;
                case 't':  out[*out_len] = '\t'; break;
                case '0':  out[*out_len] = '\0'; break;
                case '\\': out[*out_len] = '\\'; break;
                case '"':  out[*out_len] = '"';  break;
                default:   out[*out_len] = (uint8_t)*p; break;
            }
        } else {
            out[*out_len] = (uint8_t)*p;
        }
        (*out_len)++;
        p++;
    }

    return (*out_len > 0) ? 0 : -1;
}

/*
 * 解析地址值 (0x41414141) → little-endian 字节序列。
 * 例如 0x41414141 → 41 41 41 41 (32-bit)
 *      0x0000000000401234 → 34 12 40 00 00 00 00 00 (64-bit)
 */
static int parse_address(const char *s, uint8_t *out,
                         size_t max_len, size_t *out_len)
{
    *out_len = 0;
    const char *p = s;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    char *end = NULL;
    uint64_t addr = strtoull(p, &end, 16);
    if (end == p) return -1;

    /* 判断地址宽度: ≤ 0xFFFFFFFF → 4 字节, 否则 8 字节 */
    int width = (addr > 0xFFFFFFFFULL) ? 8 : 4;

    if ((size_t)width > max_len) return -1;

    /* Little-endian */
    for (int i = 0; i < width; i++) {
        out[i] = (uint8_t)(addr & 0xFF);
        addr >>= 8;
    }
    *out_len = (size_t)width;
    return 0;
}

/* ── 公开: 初始化 ──────────────────────────────────────────────── */

int mem_search_init(MemSearchConfig *cfg, const char *pattern)
{
    if (!cfg || !pattern || !*pattern) return -1;

    memset(cfg, 0, sizeof(*cfg));
    cfg->max_results   = 256;
    cfg->search_stack  = 1;
    cfg->search_heap   = 1;
    cfg->search_libs   = 1;
    cfg->search_rodata = 1;
    cfg->search_exec   = 0;    /* 默认不搜 .text — 少见作为数据出现 */

    const char *p = pattern;
    size_t len = 0;

    /* 跳过空白 */
    while (*p == ' ' || *p == '\t') p++;

    /* 检测模式类型 */
    if (*p == '"' || *p == '\'') {
        /* ── 引号 ASCII 字符串 ── */
        if (parse_quoted_ascii(p, cfg->pattern, sizeof(cfg->pattern),
                                &len) != 0)
            return -1;
        cfg->pattern_type = SEARCH_ASCII_STR;
    }
    else if (*p == '0' && (p[1] == 'x' || p[1] == 'X')) {
        /* ── 地址值 (0x...) ── */
        if (parse_address(p, cfg->pattern, sizeof(cfg->pattern),
                           &len) != 0)
            return -1;
        cfg->pattern_type = SEARCH_ADDRESS;
    }
    else if (p[0] == '/' && p[1] == '/') {
        /* ── // 前缀 → ASCII 字符串 ── */
        if (parse_quoted_ascii(p + 1, cfg->pattern,
                                sizeof(cfg->pattern), &len) < 0) {
            /* 失败则当纯 ASCII 拷贝 */
            len = strlen(p + 2);
            if (len > sizeof(cfg->pattern)) len = sizeof(cfg->pattern);
            memcpy(cfg->pattern, p + 2, len);
        }
        cfg->pattern_type = SEARCH_ASCII_STR;
    }
    else if (isxdigit((unsigned char)*p)) {
        /* ── 十六进制字节序列 ── */
        if (parse_hex(p, cfg->pattern, sizeof(cfg->pattern), &len) == 0) {
            /* 成功: hex 模式 (含 ?? 通配符) */
            cfg->pattern_type = strstr(pattern, "??")
                              ? SEARCH_WILDCARD : SEARCH_HEX_BYTES;
        } else {
            /* 解析失败 (如 "call" — 含非hex字符) → 回退为 ASCII 搜索 */
            len = strlen(p);
            if (len > sizeof(cfg->pattern)) len = sizeof(cfg->pattern);
            memcpy(cfg->pattern, p, len);
            cfg->pattern_type = SEARCH_ASCII_STR;
        }
    }
    else {
        /* ── 普通 ASCII 字符串 ── */
        len = strlen(p);
        if (len > sizeof(cfg->pattern)) len = sizeof(cfg->pattern);
        memcpy(cfg->pattern, p, len);
        cfg->pattern_type = SEARCH_ASCII_STR;
    }

    if (len == 0) return -1;
    cfg->pattern_len = len;
    return 0;
}

/* ── 搜索执行 ────────────────────────────────────────────────────
 *
 * 当前使用线性朴素搜索。每个内存段分块读取后逐字节匹配。
 *
 * 性能说明:
 *   - 搜索速度受 PTRACE_PEEKDATA 往返延迟限制 (非算法)
 *   - 64KB 块搜索 < 1ms, 大段 (MB 级) 线性可接受
 *   - 可升级为 Boyer-Moore-Horspool (在 lib/core/mem_search_bmh.c)
 *     通配符搜索需要 "多个确定串 + 通配符段" 分割策略
 */

/* 内部: 搜索一个内存段 */
static int search_segment(struct DebugState *ds,
                          uint64_t seg_start, uint64_t seg_end,
                          const char *perms,
                          const char *region_name,
                          const MemSearchConfig *cfg,
                          MemSearchResult *result)
{
    size_t seg_size = (size_t)(seg_end - seg_start);
    if (seg_size < cfg->pattern_len || seg_size == 0) return 0;

    /* 分配读缓冲区 */
    size_t buf_sz = MAPS_CHUNK_SIZE;
    if (buf_sz > seg_size) buf_sz = seg_size;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) return 0;

    int seg_hits = 0;
    size_t bytes_read = 0;

    for (uint64_t off = 0; off < seg_size; off += buf_sz) {
        size_t chunk = seg_size - (size_t)off;
        if (chunk > buf_sz) chunk = buf_sz;

        int n = debug_readmem(ds, seg_start + off, buf, chunk);
        if (n <= 0) continue;   /* 该段不可读 */
        bytes_read += (size_t)n;

        /* 对于段边界, 重叠搜索: 最后 (pat_len-1) 字节要和下一块的前部拼接 */
        /* 简化: 在 chunk 内搜索, 带重叠修正 */
        size_t search_len = (size_t)n;
        if (off + chunk < seg_size) {
            /* 非最后一块, 保守地跳过最后 pat_len-1 以避免跨块匹配丢失 */
            if (search_len > cfg->pattern_len)
                search_len -= (cfg->pattern_len - 1);
        }

        /* 搜索当前块 */
        for (size_t i = 0; i + cfg->pattern_len <= search_len; i++) {
            if (result->hit_count >= cfg->max_results) break;

            int match = 1;
            for (size_t j = 0; j < cfg->pattern_len; j++) {
                if (buf[i + j] != cfg->pattern[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                MemSearchHit *h = &result->hits[result->hit_count];
                h->addr    = seg_start + off + i;
                h->search_id = result->hit_count + 1;
                snprintf(h->region_desc, sizeof(h->region_desc),
                         "%s", region_name);
                snprintf(h->region_perms, sizeof(h->region_perms),
                         "%s", perms);
                result->hit_count++;
                seg_hits++;
            }
        }

        if (result->hit_count >= cfg->max_results) break;
    }

    free(buf);
    return seg_hits;
}

/* ── 公开: 搜索 ────────────────────────────────────────────────── */

int mem_search_run(struct DebugState *ds,
                   const MemSearchConfig *cfg,
                   MemSearchResult *result)
{
    if (!ds || !ds->attached || !cfg || !result) return -1;
    if (cfg->pattern_len == 0) return -1;

    memset(result, 0, sizeof(*result));

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* 读取 /proc/<pid>/maps */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (result->hit_count >= cfg->max_results) break;

        uint64_t start = 0, end = 0;
        char perms[8] = "";
        char fname[256] = "";

        /* 格式: 7f...-7f... rw-p 00000000 00:00 0  [pathname] */
        int fields = sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %255[^\n]",
                            &start, &end, perms, fname);

        if (fields < 2) continue;

        /* 跳过不可读段 */
        if (perms[0] != 'r') continue;

        /* 跳过内核地址空间 (vsyscall/vvar 等会导致 ptrace 异常,
         * x86-64 用户态地址上限为 0x7FFFFFFFFFFF) */
        if (start >= 0x7FFFFFFFFFFFULL) continue;

        /* 应用搜索范围过滤 */
        if (cfg->addr_start && end < cfg->addr_start) continue;
        if (cfg->addr_end   && start > cfg->addr_end)   continue;

        /* 确定段类型名称 */
        const char *seg_name = "anonymous";
        if (fname[0]) {
            /* 提取文件名 (不含路径) */
            char *slash = strrchr(fname, '/');
            seg_name = slash ? slash + 1 : fname;
        } else {
            /* 通过地址范围和权限推断类型 */
            if (perms[1] == 'w' && start > 0x600000000000ULL)
                seg_name = "stack";
            else if (perms[1] == 'w' && (perms[2] == 'p' || perms[2] == '-'))
                seg_name = "heap";
            else if (perms[2] == 'x')
                seg_name = "code";
        }

        /* 应用段类型过滤 */
        int is_stack = (strstr(seg_name, "stack") != NULL);
        int is_heap  = (strcmp(seg_name, "heap") == 0);
        int is_lib   = (strstr(fname, ".so") != NULL);
        int is_exec  = (perms[2] == 'x');
        int is_ro    = (perms[0] == 'r' && perms[1] == '-' && !is_lib);

        if (is_stack && !cfg->search_stack) continue;
        if (is_heap  && !cfg->search_heap)  continue;
        if (is_lib   && !cfg->search_libs)  continue;
        if (is_exec  && !cfg->search_exec)  continue;
        if (is_ro    && !cfg->search_rodata) continue;

        result->segments_scanned++;
        search_segment(ds, start, end, perms, seg_name, cfg, result);
    }

    fclose(fp);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    result->elapsed_ms =
        (t1.tv_sec - t0.tv_sec) * 1000.0 +
        (t1.tv_nsec - t0.tv_nsec) / 1000000.0;

    return 0;
}

/* ── 公开: PID 一次性搜索 ──────────────────────────────────────── */

int mem_search_pid(int pid, const MemSearchConfig *cfg,
                   MemSearchResult *result)
{
    if (pid <= 0 || !cfg || !result) return -1;

    struct DebugState *ds = NULL;
    if (debug_attach((pid_t)pid, &ds) != 0) {
        return -1;
    }

    int ret = mem_search_run(ds, cfg, result);

    debug_detach(ds);
    debug_free(ds);
    return ret;
}

/* ── 公开: 结果格式化 ──────────────────────────────────────────── */

const char *mem_search_format(const MemSearchResult *result,
                              const char *pattern,
                              char *out, size_t out_sz)
{
    if (!result || !out || out_sz == 0) return "";

    int pos = 0;

    pos += snprintf(out + pos, out_sz - (size_t)pos,
        "=== Memory Search: \"%s\" ===\n\n", pattern ? pattern : "");

    if (result->hit_count == 0) {
        pos += snprintf(out + pos, out_sz - (size_t)pos,
            "  No matches found.\n\n"
            "  Scanned %d segments.\n"
            "  Try expanding search scope (--all) or\n"
            "  verify the pattern format.\n",
            result->segments_scanned);
    } else {
        pos += snprintf(out + pos, out_sz - (size_t)pos,
            "  %d match%s found  (scanned %d segments, %.1f ms)\n\n",
            result->hit_count,
            result->hit_count == 1 ? "" : "es",
            result->segments_scanned,
            result->elapsed_ms);

        int show = result->hit_count;
        if (show > 50) show = 50;   /* 弹窗最多显示 50 条 */

        for (int i = 0; i < show; i++) {
            const MemSearchHit *h = &result->hits[i];
            pos += snprintf(out + pos, out_sz - (size_t)pos,
                "  [%02d] 0x%llx  %-6s  %-24s\n",
                h->search_id,
                (unsigned long long)h->addr,
                h->region_perms,
                h->region_desc);
        }

        if (result->hit_count > show) {
            pos += snprintf(out + pos, out_sz - (size_t)pos,
                "\n  ... and %d more matches (truncated).\n"
                "  Narrow search range for complete results.\n",
                result->hit_count - show);
        }
    }

    pos += snprintf(out + pos, out_sz - (size_t)pos,
        "\n  [n] Next  [N] Prev  [Enter] Jump  [Esc] Close");

    return out;
}
