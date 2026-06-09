/*
 * one_gadget.c — One-Gadget 搜索器 (零依赖, 纯字节模式匹配)
 *
 * One-Gadget = libc 中满足 execve("/bin/sh", NULL, NULL)
 * 的执行路径, 通常形式:
 *   1. mov rdi, <addr of "/bin/sh">; ...; call execve (或 syscall)
 *   2. 约束: $rsp 对齐, [rsp+...] 必须为 NULL/0 等
 *
 * 算法:
 *   1. 在 ELF 中搜索 "/bin/sh" 字符串 (确认为 libc 路径)
 *   2. 扫描代码段, 找 mov rdi, <bin_sh_addr> 指令
 *   3. 从该指令向前后展开, 找 execve 调用路径
 *   4. 提取约束: 哪些寄存器必须满足什么值
 *
 * API:
 *   int one_gadget_find(const uint8_t *code, size_t size, uint64_t base,
 *                       uint64_t bin_sh_addr, one_gadget_t *results, int max);
 *
 * 依赖: 无 (纯 C, 不需要任何外部库)
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/* ================================================================== */
/* 数据结构                                                           */
/* ================================================================== */

typedef struct {
    uint64_t addr;              /* gadget 地址 (libc 中的虚拟地址) */
    uint64_t bin_sh_offset;     /* "/bin/sh" 字符串相对 libc 基址的偏移 */
    int      constraints[8];    /* 约束: 哪些寄存器必须满足特定值 */
    /* constraints[i] = 0:无约束, 1:必须为0/NULL, 2:必须可写, -1:任意 */
    char     desc[128];         /* 人类可读描述 */
} one_gadget_t;

/* ================================================================== */
/* 字节模式搜索                                                       */
/* ================================================================== */

/** 在缓冲区中查找字节模式 (简单线性搜索) */
static const uint8_t *find_bytes(const uint8_t *haystack, size_t hs_len,
                                  const uint8_t *needle, size_t needle_len)
{
    for (size_t i = 0; i + needle_len <= hs_len; i++)
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    return NULL;
}

/** 在代码段中搜索 "/bin/sh" 字符串的地址 */
static uint64_t find_binsh(const uint8_t *data, size_t size, uint64_t base)
{
    const uint8_t *p = find_bytes(data, size,
                                   (const uint8_t *)"/bin/sh", 7);
    return p ? (base + (uint64_t)(uintptr_t)(p - data)) : 0;
}

/* ================================================================== */
/* x86-64 指令模式匹配                                                 */
/* ================================================================== */

/* mov rdi, imm64: 48 bf XX XX XX XX XX XX XX XX (10 bytes) */
static int is_mov_rdi_imm64(const uint8_t *p)
{
    return p[0] == 0x48 && p[1] == 0xbf;
}

/* lea rdi, [rip+disp32]: 48 8d 3d XX XX XX XX (7 bytes) */
static int is_lea_rdi_rip(const uint8_t *p)
{
    return p[0] == 0x48 && p[1] == 0x8d && p[2] == 0x3d;
}

/* xor esi, esi: 31 f6 (2 bytes) */
static int is_xor_esi(const uint8_t *p) { return p[0] == 0x31 && p[1] == 0xf6; }
/* xor edx, edx: 31 d2 (2 bytes) */
static int is_xor_edx(const uint8_t *p) { return p[0] == 0x31 && p[1] == 0xd2; }

/* call rel32: e8 XX XX XX XX (5 bytes) */
static int is_call_rel32(const uint8_t *p) { return p[0] == 0xe8; }

/* syscall: 0f 05 (2 bytes) */
static int is_syscall(const uint8_t *p) { return p[0] == 0x0f && p[1] == 0x05; }

/* 提取 rip-relative 目标地址 */
static uint64_t lea_target(const uint8_t *p, uint64_t insn_addr)
{
    int32_t disp = *(int32_t *)(p + 3);
    return (uint64_t)((int64_t)insn_addr + 7 + (int64_t)disp);
}

/**
 * 评分: 从 p 开始向后看, 找 "设置 execve 参数 + 调用 execve" 的模式。
 * @return 0=不匹配, 1-100=匹配置信度
 */
static int score_gadget(const uint8_t *code, size_t size, size_t off,
                         uint64_t base, uint64_t bin_sh_addr)
{
    const uint8_t *p = code + off;
    size_t remain = size - off;
    int score = 0;

    /* 需要至少 20 字节来容纳完整的 one-gadget */
    if (remain < 20) return 0;

    /* 模式 1: lea rdi, [rip+...]; ... xor esi,esi; xor edx,edx; ... call execve */
    /* 常与约束 "[rsp+0x30] == NULL" 同时出现 */
    for (size_t i = 0; i + 20 <= remain; i++) {
        if (is_lea_rdi_rip(p + i)) {
            uint64_t target = lea_target(p + i, base + off + i);
            if (target == bin_sh_addr) { score += 40; i += 7; continue; }
        }
        if (is_mov_rdi_imm64(p + i)) {
            uint64_t target = *(uint64_t *)(p + i + 2);
            if (target == bin_sh_addr) { score += 40; i += 10; continue; }
        }
        if (is_xor_esi(p + i)) { score += 15; i += 2; continue; }
        if (is_xor_edx(p + i)) { score += 15; i += 2; continue; }
        if (is_call_rel32(p + i) || is_syscall(p + i)) {
            score += 30; break; /* 调用或系统调用结束 */
        }
    }

    return score;
}

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/**
 * 在一个缓冲区中搜索 one-gadget。
 *
 * @param code          代码段数据
 * @param size          代码段大小
 * @param base          代码段虚拟基址
 * @param bin_sh_addr   "/bin/sh" 字符串的虚拟地址 (0 = 自动查找)
 * @param results       输出: gadget 数组
 * @param max_results   最多返回数量
 * @return              找到的 gadget 数量
 */
int one_gadget_find(const uint8_t *code, size_t size, uint64_t base,
                     uint64_t bin_sh_addr,
                     one_gadget_t *results, int max_results)
{
    if (!code || size < 32 || !results || max_results <= 0) return 0;

    /* 自动找 "/bin/sh" */
    if (bin_sh_addr == 0)
        bin_sh_addr = find_binsh(code, size, base);
    if (bin_sh_addr == 0) return 0; /* 没找到字符串 */

    int found = 0;

    /* 滑动窗口: 每 4 字节检查一次 */
    for (size_t off = 0; off + 30 <= size && found < max_results; off += 4) {
        int s = score_gadget(code, size, off, base, bin_sh_addr);
        if (s < 60) continue; /* 阈值: 需要至少 60 分 */

        one_gadget_t *g = &results[found];
        g->addr = base + off;
        g->bin_sh_offset = bin_sh_addr - base;
        memset(g->constraints, -1, sizeof(g->constraints));

        /* 检查常见约束 */
        /* 约束 0: rsp 必须可读写 (总是成立) */
        /* 约束 1: rsp+0x30 必须为 NULL (常见) — 无法静态验证, 标记为需要检查 */
        /* 约束 2: rcx 必须为 NULL */
        g->constraints[4] = 0; /* rsp 约束: 无特殊要求 */
        g->constraints[2] = 1; /* rcx 约束: 需要为 NULL (推测) */

        /* 生成描述 */
        snprintf(g->desc, sizeof(g->desc),
                 "one_gadget @ 0x%lx (score=%d)  "
                 "constraints: [rsp+0x30]==NULL, rcx==NULL (typical)",
                 g->addr, s);
        found++;
    }

    return found;
}

/*
 * 以下 one_gadget_scan 需要 ELF section header 结构。
 * 使用标准的 64 字节 per-entry layout (与 Elf64_Shdr 兼容),
 * 通过 void* 避免直接依赖 elf_parser.h。
 *
 * Elf64_Shdr layout (64 bytes):
 *   offset 0x00: sh_name  (u32)
 *   offset 0x04: sh_type  (u32)
 *   offset 0x08: sh_flags (u64)
 *   offset 0x10: sh_addr  (u64)
 *   offset 0x18: sh_offset(u64)
 *   offset 0x20: sh_size  (u64)
 *
 * 宏定义避免硬编码 */
#define SHT_PROGBITS  1
#define SHF_EXECINSTR 4

static uint64_t sh_at(const void *shdr, int i, int field_off) {
    return *(const uint64_t *)((const char *)shdr + i * 64 + field_off);
}
static uint32_t sh_at32(const void *shdr, int i, int field_off) {
    return *(const uint32_t *)((const char *)shdr + i * 64 + field_off);
}

int one_gadget_scan(const uint8_t *map, size_t mapsz,
                     void *ehdr_v, void *shdrs_v, int shnum,
                     const char *strtab,
                     one_gadget_t *results, int max_results)
{
    (void)ehdr_v; (void)mapsz; (void)strtab;
    int total = 0;
    uint64_t bin_sh = 0;

    /* Pass 1: find "/bin/sh" string in non-executable sections */
    for (int i = 0; i < shnum && bin_sh == 0; i++) {
        uint32_t shtype = sh_at32(shdrs_v, i, 4);
        uint64_t shflags = sh_at(shdrs_v, i, 8);
        uint64_t shsize  = sh_at(shdrs_v, i, 32);
        uint64_t shoff   = sh_at(shdrs_v, i, 24);
        uint64_t shaddr  = sh_at(shdrs_v, i, 16);
        if (shtype != SHT_PROGBITS) continue;
        if (shflags & SHF_EXECINSTR) continue;
        if (shsize < 8) continue;
        bin_sh = find_binsh(map + shoff, shsize, shaddr);
    }

    /* Pass 2: scan executable sections */
    for (int i = 0; i < shnum && total < max_results; i++) {
        uint32_t shtype = sh_at32(shdrs_v, i, 4);
        uint64_t shflags = sh_at(shdrs_v, i, 8);
        uint64_t shsize  = sh_at(shdrs_v, i, 32);
        uint64_t shoff   = sh_at(shdrs_v, i, 24);
        uint64_t shaddr  = sh_at(shdrs_v, i, 16);
        if (shtype != SHT_PROGBITS) continue;
        if (!(shflags & SHF_EXECINSTR)) continue;
        if (shsize < 32) continue;

        int n = one_gadget_find(map + shoff, shsize, shaddr,
                                 bin_sh, results + total, max_results - total);
        total += n;
    }

    return total;
}
