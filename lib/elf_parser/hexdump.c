/*
 * hexdump.c — Hex Dump 视图模块 v2 (Prompt 03)
 *
 * 标准 16 字节/行的 hex dump, 格式对齐专业工具 (xxd/hexdump -C).
 *
 * 特性:
 *   - 偏移量 | hex 16列 + 中间分隔 | ASCII 预览
 *   - 非打印字符显示为 '.'
 *   - 大节 (>100KB) 显示头 10KB + 尾 10KB, 标注截断
 *   - 彩色可选 (地址/hex/ASCII 不同颜色)
 *   - 字节高亮: 可以对特定偏移范围着色
 *
 * 符合 COORDINATION.md:
 *   接口: int parse_hexdump(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 * 依赖: 无 (纯字节读取, 不需要 Capstone)
 */
#include "elf_parser.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ================================================================== */
/* 渲染参数                                                           */
/* ================================================================== */

#define BYTES_PER_LINE  16
#define LARGE_THRESHOLD  102400    /* 100KB — 超过此值启用截断模式 */
#define TAIL_SHOW        10240     /* 尾部显示 10KB */

/* ================================================================== */
/* 辅助: 打印单行 hex dump                                             */
/* ================================================================== */

/**
 * 格式化一行 hex dump 到缓冲区。
 * 格式: "XXXXXXXX: HH HH HH HH  HH HH HH HH  |ASCII........|"
 *        ^8B      ^16B hex with mid-gap     ^16B ASCII
 *
 * @param data  数据指针 (从这行起始偏移处开始)
 * @param size  数据区总大小
 * @param off   本行的起始偏移
 * @param buf   输出缓冲区
 * @param bufsz 缓冲区大小
 * @return      实际写入的字符数 (不含 '\0')
 */
static int format_hex_line(const uint8_t *data, size_t size, size_t off,
                           char *buf, size_t bufsz)
{
    int pos = 0;

    /* 偏移量: 8 位十六进制 */
    pos += snprintf(buf + pos, bufsz - (size_t)pos, "%08zx  ", off);

    /* hex 部分: 前 8 字节 */
    for (int j = 0; j < 8; j++) {
        if (off + (size_t)j < size)
            pos += snprintf(buf + pos, bufsz - (size_t)pos,
                           "%02x ", data[off + j]);
        else
            pos += snprintf(buf + pos, bufsz - (size_t)pos, "   ");
    }

    /* 中间分隔 */
    pos += snprintf(buf + pos, bufsz - (size_t)pos, " ");

    /* hex 部分: 后 8 字节 */
    for (int j = 8; j < 16; j++) {
        if (off + (size_t)j < size)
            pos += snprintf(buf + pos, bufsz - (size_t)pos,
                           "%02x ", data[off + j]);
        else
            pos += snprintf(buf + pos, bufsz - (size_t)pos, "   ");
    }

    /* ASCII 分隔 */
    pos += snprintf(buf + pos, bufsz - (size_t)pos, " |");

    /* ASCII 部分 */
    for (int j = 0; j < 16; j++) {
        if (off + (size_t)j < size) {
            unsigned char c = data[off + j];
            pos += snprintf(buf + pos, bufsz - (size_t)pos, "%c",
                           isprint(c) ? (char)c : '.');
        } else {
            pos += snprintf(buf + pos, bufsz - (size_t)pos, " ");
        }
    }

    pos += snprintf(buf + pos, bufsz - (size_t)pos, "|");

    return pos;
}

/**
 * 输出连续的行块。
 * @param label 块标题 (NULL = 不打印标题)
 * @param data  数据指针
 * @param size  数据总大小
 * @param start 起始偏移
 * @param count 要输出的字节数
 * @param pd    面板数据
 * @param indent 行缩进
 */
static void dump_block(Elf64_Ctx *ctx, const char *label,
                       const uint8_t *data, size_t size,
                       size_t start, size_t count,
                       PanelData *pd, int indent,
                       Elf64_Addr base_addr)
{
    (void)ctx;
    char line[128];

    if (label)
        fields_add(pd, label, indent, 0, DETAIL_NONE, -1);

    size_t end = start + count;
    if (end > size) end = size;

    for (size_t off = start; off < end; off += BYTES_PER_LINE) {
        format_hex_line(data, size, off, line, sizeof(line));
        /* 把文件偏移替换为虚拟地址 (0x前缀, 可跳转) */
        char vline[140];
        uint64_t vaddr = base_addr + (uint64_t)off;
        /* 原始格式: "%08zx  HH HH..."  →  新格式: "0x%lx  HH HH..." */
        snprintf(vline, sizeof(vline), "0x%lx%s",
                 (unsigned long)vaddr, line + 8);  /* 跳过旧的 8 位偏移 */
        fields_add(pd, vline, indent, 1, DETAIL_NONE, (int)(vaddr & 0xFFFF));
    }
}

/* ================================================================== */
/* 公共接口                                                           */
/* ================================================================== */

int parse_hexdump(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)
{
    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_size == 0) {
        fields_add(pd, "(empty section)", 0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    if (sh->sh_type == SHT_NOBITS) {
        fields_add(pd, "(SHT_NOBITS — no data on disk, zero-filled at runtime)",
                   0, 0, DETAIL_NONE, -1);
        return pd->count;
    }

    const char *sec_name = elf_section_name(ctx, shdr_idx);
    if (!sec_name) sec_name = "?";

    const uint8_t *data = ctx->map + sh->sh_offset;
    size_t size = sh->sh_size;
    int is_large = (size > LARGE_THRESHOLD);

    /* ── 标题 ── */
    char buf[256];
    if (is_large) {
        snprintf(buf, sizeof(buf),
                 "=== hexdump: %s (%lu.%lu KB) [truncated — showing head+tail] ===",
                 sec_name,
                 (unsigned long)(size / 1024),
                 (unsigned long)((size % 1024) * 100 / 1024));
    } else {
        snprintf(buf, sizeof(buf),
                 "=== hexdump: %s (%lu bytes) ===",
                 sec_name, (unsigned long)size);
    }
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

    /* 元数据行 */
    snprintf(buf, sizeof(buf),
             "Address: 0x%lx  Offset: 0x%lx  Flags: %s%s%s",
             (unsigned long)sh->sh_addr,
             (unsigned long)sh->sh_offset,
             (sh->sh_flags & SHF_WRITE)     ? "W" : "-",
             (sh->sh_flags & SHF_ALLOC)     ? "A" : "-",
             (sh->sh_flags & SHF_EXECINSTR) ? "X" : "-");
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 列标题 */
    fields_add(pd, "Offset    "
                    "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  "
                    "|ASCII.............|",
               1, 0, DETAIL_NONE, -1);
    fields_add(pd, "────────  "
                    "─────────────────────────  ────────────────────────  "
                    "───────────────────",
               1, 0, DETAIL_NONE, -1);

    /* ── 数据块 ── */
    if (is_large) {
        /* 大文件: 头 + 尾 */
        dump_block(ctx, "─── First 10 KB ───", data, size, 0, 10240, pd, 1, sh->sh_addr);

        size_t mid_skip = size - 20480;
        snprintf(buf, sizeof(buf),
                 "...  (skipping %lu.%lu KB in middle)  ...",
                 (unsigned long)(mid_skip / 1024),
                 (unsigned long)((mid_skip % 1024) * 100 / 1024));
        fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);

        size_t tail_start = (size > TAIL_SHOW) ? size - TAIL_SHOW : 0;
        snprintf(buf, sizeof(buf), "─── Last %d KB ───", (int)(TAIL_SHOW / 1024));
        dump_block(ctx, buf, data, size, tail_start, TAIL_SHOW, pd, 1, sh->sh_addr);
    } else {
        /* 小文件: 完整输出 */
        dump_block(ctx, NULL, data, size, 0, size, pd, 1, sh->sh_addr);
    }

    /* 统计摘要 */
    fields_add(pd, "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─", 0, 0, DETAIL_NONE, -1);

    /* 统计零字节/可打印比例 */
    size_t zeros = 0, printable = 0;
    size_t scan = size > 65536 ? 65536 : size;
    for (size_t i = 0; i < scan; i++) {
        if (data[i] == 0) zeros++;
        if (isprint(data[i])) printable++;
    }

    snprintf(buf, sizeof(buf),
             "Stats: %lu bytes total, ~%.0f%% zeros, ~%.0f%% printable (sampled %lu B)",
             (unsigned long)size,
             (double)zeros * 100.0 / (double)scan,
             (double)printable * 100.0 / (double)scan,
             (unsigned long)scan);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    return pd->count;
}
