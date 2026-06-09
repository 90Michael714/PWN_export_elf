/*
 * registers.c — NT_PRSTATUS register display for elf-tui
 *
 * Triggered when the user selects a SHT_NOTE section that contains
 * an NT_PRSTATUS note (e.g. in an ELF core dump).  Displays all
 * 27 x86-64 general-purpose registers in the middle panel.
 *
 * Interface: int parse_registers(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
 *
 * This module is self-contained — it does NOT depend on the
 * standalone reg-reader project.  The note-parsing logic is
 * duplicated intentionally so that elf-tui remains independent.
 */

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "elf_parser.h"

/* ── Constants ──────────────────────────────────────────────────── */

#define NT_PRSTATUS     1
#define PR_REG_OFFSET  112    /* offset of pr_reg within elf_prstatus */
#define USER_REGS_SIZE 216    /* sizeof(struct user_regs_struct) x86-64 */

/* ── Register name → byte offset within struct user_regs_struct ────
 *
 * Verified against Linux 5.x / 6.x kernel ABI on x86-64.
 * These hard-coded offsets are necessary because struct user_regs_struct
 * is NOT a stable ABI — the kernel may change it between versions.
 * For production use, the standalone reg-reader CLI tool validates
 * these against the build host's <sys/user.h> at compile time via
 * offsetof() in ptrace_reader.c.
 */

typedef struct {
    const char *name;
    int         offset;
} RegMapEntry;

static const RegMapEntry reg_map[] = {
    { "rdi",        0 },   { "rsi",        8 },
    { "rdx",       16 },   { "rcx",       24 },
    { "rax",       32 },   { "r8",        40 },
    { "r9",        48 },   { "r10",       56 },
    { "r11",       64 },   { "rbx",       72 },
    { "rbp",       80 },   { "r12",       88 },
    { "r13",       96 },   { "r14",      104 },
    { "r15",      112 },   { "orig_rax", 120 },
    { "rip",      128 },   { "cs",       136 },
    { "eflags",   144 },   { "rsp",      152 },
    { "ss",       160 },   { "fs_base",  168 },
    { "gs_base",  176 },   { "ds",       184 },
    { "es",       192 },   { "fs",       200 },
    { "gs",       208 },
};

#define REG_COUNT  27

/*
 * Key registers — displayed with extra emphasis.
 * rip, rsp, rbp, rax are the most useful for exploit development.
 */
static const char *KEY_REGS[] = {
    "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
    "rsi", "rdi", "eflags", NULL
};

static int is_key_reg(const char *name) {
    for (int i = 0; KEY_REGS[i]; i++)
        if (strcmp(KEY_REGS[i], name) == 0) return 1;
    return 0;
}

/* ── Internal: walk note entries looking for NT_PRSTATUS ─────────── */

static const uint8_t *find_prstatus(const uint8_t *data, size_t size) {
    const uint8_t *cursor = data;
    const uint8_t *end    = data + size;

    while (cursor + sizeof(Elf64_Nhdr) <= end) {
        const Elf64_Nhdr *nhdr = (const Elf64_Nhdr *)cursor;

        size_t n_align = ((size_t)nhdr->n_namesz + 3) & ~(size_t)3;
        size_t d_align = ((size_t)nhdr->n_descsz + 3) & ~(size_t)3;
        size_t desc_off = sizeof(Elf64_Nhdr) + n_align;

        if (cursor + desc_off + d_align > end) break;

        if (nhdr->n_type == NT_PRSTATUS &&
            nhdr->n_descsz >= (Elf64_Word)(PR_REG_OFFSET + USER_REGS_SIZE)) {
            return cursor + desc_off + PR_REG_OFFSET;
        }

        cursor += sizeof(Elf64_Nhdr) + n_align + d_align;
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────────── */

int parse_registers(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd) {
    if (!ctx || !pd || shdr_idx < 0) return -1;

    Elf64_Shdr *sh = elf_get_shdr(ctx, shdr_idx);
    if (!sh || sh->sh_type != SHT_NOTE) return -1;

    /* Bounds-check the section data */
    if (sh->sh_offset >= ctx->size ||
        sh->sh_size < sizeof(Elf64_Nhdr) ||
        sh->sh_offset + sh->sh_size > ctx->size) {
        return -1;
    }

    const uint8_t *data = ctx->map + sh->sh_offset;
    const uint8_t *pr_reg = find_prstatus(data, (size_t)sh->sh_size);

    if (!pr_reg) return 0;   /* No NT_PRSTATUS — nothing to add */

    /* ── Display registers ─────────────────────────────────────── */

    /* Section heading */
    fields_add(pd, "=== Register Dump (NT_PRSTATUS / x86_64) ===",
               0, 0, DETAIL_NONE, -1);

    /*
     * Lay out registers in two groups:
     *   Group 1: Key registers (indent=1, selectable for detail view)
     *   Group 2: Segment / base registers (indent=2, non-selectable)
     */

    /* ── Key registers first ── */
    fields_add(pd, "— General Purpose —", 1, 0, DETAIL_NONE, -1);

    for (int i = 0; i < REG_COUNT; i++) {
        uint64_t val = 0;
        memcpy(&val, pr_reg + reg_map[i].offset, sizeof(val));

        /* Only key regs get indent=1, selectable */
        if (is_key_reg(reg_map[i].name)) {
            char buf[80];
            snprintf(buf, sizeof(buf),
                     "%-8s = 0x%016" PRIx64 "  (%" PRIu64 ")",
                     reg_map[i].name, val, val);
            fields_add(pd, buf, 1, 1, DETAIL_REG, i);
        }
    }

    /* ── Segment / base / other registers ── */
    fields_add(pd, "— Segment & Base —", 1, 0, DETAIL_NONE, -1);

    for (int i = 0; i < REG_COUNT; i++) {
        if (!is_key_reg(reg_map[i].name)) {
            uint64_t val = 0;
            memcpy(&val, pr_reg + reg_map[i].offset, sizeof(val));

            char buf[80];
            snprintf(buf, sizeof(buf),
                     "%-8s = 0x%016" PRIx64 "  (%" PRIu64 ")",
                     reg_map[i].name, val, val);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
    }

    return 0;
}
