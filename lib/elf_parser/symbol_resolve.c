/*
 * symbol_resolve.c — 运行时符号解析引擎 (依赖: debug_worker.h)
 *
 * 从 /proc/<pid>/maps 获取库加载地址, 从磁盘 ELF 读取符号表,
 * 计算运行时地址 = 加载基址 + 符号偏移。
 *
 * 用途:
 *   - 调试时: "printf 在哪个地址?" → 基址 + printf 的 st_value
 *   - 符号化栈回溯: 0x7f12345678 → libc+0x45678 → printf+0x28
 *   - 绕过 ASLR: 已知 libc 基址 → 所有 libc 函数地址已知
 *
 * API:
 *   int  symbol_resolve(DebugState *ds, const char *name,
 *                       uint64_t *runtime_addr);
 *   int  symbol_resolve_all(DebugState *ds, sym_entry_t *entries, int max);
 *
 * 依赖:
 *   #include "core/debug_worker.h" (ds->pid 用于读 /proc/pid/maps)
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>

#include "core/debug_worker.h"

/* ================================================================== */
/* 辅助: 读取 ELF 文件符号表                                          */
/* ================================================================== */

typedef struct {
    char     name[64];
    uint64_t offset;      /* 在 ELF 文件中的偏移 (st_value) */
    uint64_t size;
} sym_entry_t;

/**
 * 从磁盘上读取一个 ELF 文件的符号表。
 * @param elf_path    ELF 文件路径 (如 "/lib/x86_64-linux-gnu/libc.so.6")
 * @param entries     输出: 符号表条目
 * @param max         最大条目数
 * @return            实际读取条目数
 */
static int read_elf_symbols(const char *elf_path,
                            sym_entry_t *entries, int max)
{
    FILE *fp = fopen(elf_path, "rb");
    if (!fp) return 0;

    /* 读取 ELF header */
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) { fclose(fp); return 0; }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) { fclose(fp); return 0; }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) { fclose(fp); return 0; }

    /* 定位 .dynsym 节 */
    Elf64_Shdr shdr;
    int dynsym_off = 0, dynsym_size = 0;
    int dynstr_off = 0, dynstr_size = 0;

    for (int i = 0; i < (int)ehdr.e_shnum; i++) {
        fseek(fp, (long)(ehdr.e_shoff + i * ehdr.e_shentsize), SEEK_SET);
        if (fread(&shdr, sizeof(shdr), 1, fp) != 1) break;
        if (shdr.sh_type == SHT_DYNSYM) {
            dynsym_off = (int)shdr.sh_offset;
            dynsym_size = (int)shdr.sh_size;
        } else if (shdr.sh_type == SHT_STRTAB && shdr.sh_size > 0) {
            /* 简单策略: 选择最大的 STRTAB (通常是 .dynstr) */
            if ((int)shdr.sh_size > dynstr_size) {
                dynstr_off = (int)shdr.sh_offset;
                dynstr_size = (int)shdr.sh_size;
            }
        }
    }

    if (dynsym_off == 0 || dynstr_off == 0) { fclose(fp); return 0; }

    /* 读取 .dynstr */
    char *dynstr = (char *)malloc((size_t)dynstr_size);
    if (!dynstr) { fclose(fp); return 0; }
    fseek(fp, dynstr_off, SEEK_SET);
    if (fread(dynstr, (size_t)dynstr_size, 1, fp) != 1) {
        free(dynstr); fclose(fp); return 0;
    }

    /* 读取 .dynsym */
    int nsym = dynsym_size / (int)sizeof(Elf64_Sym);
    Elf64_Sym *syms = (Elf64_Sym *)malloc((size_t)dynsym_size);
    if (!syms) { free(dynstr); fclose(fp); return 0; }
    fseek(fp, dynsym_off, SEEK_SET);
    if (fread(syms, (size_t)dynsym_size, 1, fp) != 1) {
        free(syms); free(dynstr); fclose(fp); return 0;
    }
    fclose(fp);

    int count = 0;
    for (int i = 0; i < nsym && count < max; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC) continue;
        if (syms[i].st_value == 0) continue;

        const char *name = dynstr + syms[i].st_name;
        if (!name || !name[0]) continue;

        strncpy(entries[count].name, name, 63);
        entries[count].name[63] = '\0';
        entries[count].offset = syms[i].st_value;
        entries[count].size   = syms[i].st_size;
        count++;
    }

    free(syms);
    free(dynstr);
    return count;
}

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/**
 * 解析指定符号的运行时地址。
 * 流程: 读 /proc/pid/maps → 找到 libc 基址 → 读 libc ELF → 找符号偏移 → 计算地址
 *
 * @param ds            调试状态
 * @param name          符号名 (如 "printf", "system")
 * @param runtime_addr  输出: 运行时地址
 * @return              0=找到, -1=未找到
 */
int symbol_resolve(struct DebugState *ds, const char *name,
                   uint64_t *runtime_addr)
{
    if (!ds || !name || !runtime_addr) return -1;

    /* 1. 从 /proc/pid/maps 获取库加载基址 */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    uint64_t libc_base = 0;
    char libc_path[256] = "";

    while (fgets(line, sizeof(line), fp)) {
        char perms[5], fpath[256] = "";
        if (sscanf(line, "%lx-%*s %4s %*s %*s %*s %255s",
                   &libc_base, perms, fpath) < 3) continue;
        if (perms[2] == 'x' && strstr(fpath, "libc")) {
            strncpy(libc_path, fpath, 255);
            break;
        }
    }
    fclose(fp);

    if (libc_base == 0 || libc_path[0] == '\0') return -1;

    /* 2. 读 libc 的 .dynsym 找符号 */
    sym_entry_t syms[4096];
    int nsyms = read_elf_symbols(libc_path, syms, 4096);

    for (int i = 0; i < nsyms; i++) {
        if (!strcmp(syms[i].name, name)) {
            *runtime_addr = libc_base + syms[i].offset;
            return 0;
        }
    }
    return -1;
}

/**
 * 解析所有已加载库的运行时符号。
 * 返回解析到的符号总数。
 */
int symbol_resolve_all(struct DebugState *ds,
                       sym_entry_t *all_entries, int max)
{
    if (!ds || !all_entries || max <= 0) return 0;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", ds->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    int total = 0;
    char line[512];
    char processed[16][256];  /* 已处理的库, 避免重复 */
    int nprocessed = 0;

    while (fgets(line, sizeof(line), fp) && total < max) {
        uint64_t base;
        char perms[5], fpath[256] = "";
        if (sscanf(line, "%lx-%*s %4s %*s %*s %*s %255s",
                   &base, perms, fpath) < 3) continue;
        if (perms[2] != 'x' || fpath[0] != '/') continue;

        /* 去重: 同一个库只处理一次 */
        int seen = 0;
        for (int i = 0; i < nprocessed; i++)
            if (!strcmp(processed[i], fpath)) { seen = 1; break; }
        if (seen) continue;
        if (nprocessed < 16) strncpy(processed[nprocessed++], fpath, 255);

        sym_entry_t syms[2048];
        int n = read_elf_symbols(fpath, syms, 2048);
        for (int i = 0; i < n && total < max; i++) {
            all_entries[total] = syms[i];
            all_entries[total].offset += base; /* 转换为运行时地址 */
            total++;
        }
    }
    fclose(fp);
    return total;
}
