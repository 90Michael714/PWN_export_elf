/*
 * mem_search.h — Tracee 内存搜索引擎
 *
 * 在 ptrace tracee 的地址空间中搜索字节模式/字符串/地址值。
 * 通过 /proc/<pid>/maps 确定可读内存区域, 逐段 PTRACE_PEEKDATA 搜索。
 *
 * 独立模块 — 不依赖 elf_parser.h / tui.h / notcurses。
 * 仅依赖: <stdint.h>, <stddef.h>
 *
 * 使用流程:
 *   1. mem_search_init(&cfg, "41 41 41 41");  // 解析搜索模式
 *   2. mem_search_run(ds, &cfg, &result);      // 执行搜索
 *   3. mem_search_format(&result, buf, 4096);  // 格式化为弹窗文本
 */

#ifndef MEM_SEARCH_H
#define MEM_SEARCH_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration — caller provides DebugState */
struct DebugState;

/* ── 搜索模式类型 ──────────────────────────────────────────────── */

typedef enum {
    SEARCH_HEX_BYTES = 0,    /* "41 41 41 41" 或 "41,41,41,41" */
    SEARCH_ASCII_STR,        /* '"AAAA"' 或 'AAAA' 或 //bin/sh    */
    SEARCH_ADDRESS,          /* "0x41414141"  (little-endian)     */
    SEARCH_WILDCARD,         /* "41 ?? 41"  (?? = 任意字节)       */
} MemSearchPatternType;

/* ── 搜索配置 ──────────────────────────────────────────────────── */

typedef struct {
    /* 搜索模式 */
    uint8_t              pattern[256];     /* 规范化后的字节序列 */
    size_t               pattern_len;      /* 0 = 未初始化 */
    MemSearchPatternType pattern_type;

    /* 搜索范围 */
    uint64_t             addr_start;       /* 0 = 搜索整个地址空间 */
    uint64_t             addr_end;         /* 0 = 到地址空间末尾 */
    unsigned int         search_stack : 1; /* 1 = 包含栈 */
    unsigned int         search_heap  : 1; /* 1 = 包含堆 */
    unsigned int         search_libs  : 1; /* 1 = 包含共享库映射 */
    unsigned int         search_rodata: 1; /* 1 = 包含只读数据段 */
    unsigned int         search_exec  : 1; /* 1 = 包含可执行段 */

    /* 限制 */
    int                  max_results;      /* 默认 256 */
} MemSearchConfig;

/* ── 搜索结果 ──────────────────────────────────────────────────── */

typedef struct {
    uint64_t addr;             /* 匹配地址 */
    char     region_desc[64];  /* "stack", "heap", "libc-2.35.so" 等 */
    char     region_perms[8];  /* "rw-", "r--", "r-x" */
    int      search_id;        /* 结果序号 */
} MemSearchHit;

typedef struct {
    MemSearchHit  hits[256];
    int           hit_count;
    int           segments_scanned;  /* 搜查了多少个内存段 */
    int           bytes_scanned;     /* 搜查了多少字节 (KB) */
    double        elapsed_ms;        /* 搜索耗时 */
} MemSearchResult;

/* ── API ───────────────────────────────────────────────────────── */

/*
 * 初始化搜索配置。
 * 参数:
 *   cfg       — 输出配置 (必须是有效的指针)
 *   pattern   — 搜索模式字符串 (见支持格式)
 *
 * 支持的格式:
 *   "41 41 41 41"        十六进制字节 (空格/逗号分隔)
 *   "41,41,41,41"        同上
 *   "\"AAAA\""            双引号包裹的 ASCII 字符串
 *   "AAAA"                无引号 ASCII 字符串
 *   "//bin/sh"            斜杠前缀 ASCII 字符串
 *   "0x41414141"          地址值 (按 little-endian 搜索)
 *   "41 ?? 41"            通配符搜索 (?? = 任意字节)
 *   "\x41\x41\x41\x41"    反斜杠转义 hex
 *
 * 返回: 0 = 解析成功, -1 = 格式错误
 */
int  mem_search_init(MemSearchConfig *cfg, const char *pattern);

/*
 * 在 tracee 地址空间中执行搜索。
 *
 * 参数:
 *   ds       — ptrace 调试状态 (需要已 attach)
 *   cfg      — 搜索配置 (来自 mem_search_init)
 *   result   — 输出结果
 *
 * 返回: 0 = 搜索完成, -1 = 错误 (ds==NULL / 未attach / 模式未初始化)
 */
int  mem_search_run(struct DebugState *ds,
                    const MemSearchConfig *cfg,
                    MemSearchResult *result);

/*
 * 为给定 PID 执行一次性搜索 (自动 attach → 搜索 → detach)。
 *
 * 参数:
 *   pid      — 目标进程 PID
 *   cfg      — 搜索配置
 *   result   — 输出结果
 *
 * 返回: 0 = 成功, -1 = 错误
 *
 * 注意: 这种方式不保留断点/调试状态, 适合一次性查询。
 */
int  mem_search_pid(int pid, const MemSearchConfig *cfg,
                    MemSearchResult *result);

/*
 * 将搜索结果格式化为弹窗友好的文本 (≤4096 字节)。
 *
 * 参数:
 *   result   — 搜索结果
 *   pattern  — 原始搜索模式字符串 (用于标题)
 *   out      — 输出缓冲区
 *   out_sz   — 缓冲区大小
 *
 * 返回: out (与参数相同, 方便链式调用)
 */
const char *mem_search_format(const MemSearchResult *result,
                              const char *pattern,
                              char *out, size_t out_sz);

#endif /* MEM_SEARCH_H */
