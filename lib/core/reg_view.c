/*
 * reg_view.c — Register formatting renderer
 *
 * Two entry points:
 *   render_register_view()     — static analysis (core dump or SHT_NOTE)
 *   render_live_registers()    — live ptrace (DebugState)
 *
 * Layout: two-column format fitting in right panel (40-50% terminal width).
 * Changed registers are marked with [*] when diff context is available.
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "elf_parser.h"
#include "core/debug_worker.h"
#include "core/reg_view.h"

/* ── Register name list (x86-64 GPRs in display order) ──────────── */

typedef struct {
    const char *name;
    size_t      offset;      /* within struct user_regs_struct */
} RegField;

static const RegField gpr_list[] = {
    { "RAX",   offsetof(struct user_regs_struct, rax)      },
    { "RBX",   offsetof(struct user_regs_struct, rbx)      },
    { "RCX",   offsetof(struct user_regs_struct, rcx)      },
    { "RDX",   offsetof(struct user_regs_struct, rdx)      },
    { "RSI",   offsetof(struct user_regs_struct, rsi)      },
    { "RDI",   offsetof(struct user_regs_struct, rdi)      },
    { "R8",    offsetof(struct user_regs_struct, r8)       },
    { "R9",    offsetof(struct user_regs_struct, r9)       },
    { "R10",   offsetof(struct user_regs_struct, r10)      },
    { "R11",   offsetof(struct user_regs_struct, r11)      },
    { "R12",   offsetof(struct user_regs_struct, r12)      },
    { "R13",   offsetof(struct user_regs_struct, r13)      },
    { "R14",   offsetof(struct user_regs_struct, r14)      },
    { "R15",   offsetof(struct user_regs_struct, r15)      },
    { "RBP",   offsetof(struct user_regs_struct, rbp)      },
    { "RSP",   offsetof(struct user_regs_struct, rsp)      },
    { "RIP",   offsetof(struct user_regs_struct, rip)      },
};

#define GPR_COUNT  (sizeof(gpr_list) / sizeof(gpr_list[0]))

/* ── Helper: read uint64_t from struct user_regs_struct at offset ── */

static uint64_t ureg64(const struct user_regs_struct *uregs, size_t off) {
    uint64_t v = 0;
    memcpy(&v, (const unsigned char *)uregs + off, sizeof(v));
    return v;
}

/* ── EFLAGS decomposition ───────────────────────────────────────── */

static void eflags_string(uint64_t efl, char *buf, size_t sz) {
    static const struct {
        uint64_t bit; const char *name;
    } flags[] = {
        { 1 <<  0, "CF" },   /* Carry */
        { 1 <<  2, "PF" },   /* Parity */
        { 1 <<  4, "AF" },   /* Adjust */
        { 1 <<  6, "ZF" },   /* Zero */
        { 1 <<  7, "SF" },   /* Sign */
        { 1 <<  8, "TF" },   /* Trap (single-step) */
        { 1 <<  9, "IF" },   /* Interrupt enable */
        { 1 << 10, "DF" },   /* Direction */
        { 1 << 11, "OF" },   /* Overflow */
        { 1 << 14, "NT" },   /* Nested task */
        { 1 << 16, "RF" },   /* Resume */
        { 1 << 17, "VM" },   /* Virtual 8086 */
        { 1 << 18, "AC" },   /* Alignment check */
        { 1 << 19, "VIF" },  /* Virtual interrupt */
        { 1 << 20, "VIP" },  /* Virtual interrupt pending */
        { 1 << 21, "ID" },   /* CPUID */
    };

    size_t pos = 0;
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        if (efl & flags[i].bit) {
            if (pos > 0) pos += (size_t)snprintf(buf + pos, sz - pos, " ");
            pos += (size_t)snprintf(buf + pos, sz - pos, "%s",
                                    flags[i].name);
        }
    }
    if (pos == 0) {
        snprintf(buf, sz, "(none)");
    }
}

/* ── Build GPR two-column row ───────────────────────────────────── */

static void format_gpr_row(char *buf, size_t sz,
                           const char *n1, uint64_t v1,
                           const char *n2, uint64_t v2) {
    if (n2) {
        snprintf(buf, sz, "%-4s: 0x%016" PRIx64 "  %-4s: 0x%016" PRIx64,
                 n1, v1, n2, v2);
    } else {
        snprintf(buf, sz, "%-4s: 0x%016" PRIx64, n1, v1);
    }
}

/* ── Public: static core dump register view ────────────────────────
 *
 * Scans the ELF context for NT_PRSTATUS notes and renders them.
 * Delegates to parse_registers() if available; otherwise does its
 * own note walking.
 */

int render_register_view(Elf64_Ctx *ctx, PanelData *pd) {
    if (!ctx || !pd) return -1;

    /* First, try to find NT_PRSTATUS from ELF note sections */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;

    /* Walk program headers for PT_NOTE (core dumps) */
    int found = 0;
    for (int i = 0; i < ehdr->e_phnum && !found; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        if (!ph || ph->p_type != PT_NOTE) continue;

        const uint8_t *data = ctx->map + ph->p_offset;
        size_t        size  = (size_t)ph->p_filesz;

        const uint8_t *cursor = data;
        const uint8_t *end    = data + size;

        while (cursor + sizeof(Elf64_Nhdr) <= end) {
            const Elf64_Nhdr *nhdr = (const Elf64_Nhdr *)cursor;

            size_t n_align = ((size_t)nhdr->n_namesz + 3) & ~(size_t)3;
            size_t d_align = ((size_t)nhdr->n_descsz + 3) & ~(size_t)3;
            size_t desc_off = sizeof(Elf64_Nhdr) + n_align;

            if (cursor + desc_off + d_align > end) break;

            if (nhdr->n_type == 1 &&   /* NT_PRSTATUS */
                nhdr->n_descsz >= (uint32_t)(112 + 216)) {

                const uint8_t *pr_reg = cursor + desc_off + 112;

                /* Build display */
                fields_add(pd, "=== x86-64 Registers (Core Dump) ===",
                           0, 0, DETAIL_NONE, -1);
                fields_add(pd, "", 0, 0, DETAIL_NONE, -1);  /* spacer */

                /* GPRs in two-column rows */
                char row[128];
                for (int r = 0; r < GPR_COUNT; r += 2) {
                    uint64_t v1;
                    memcpy(&v1, pr_reg + gpr_list[r].offset, 8);
                    if (r + 1 < GPR_COUNT) {
                        uint64_t v2;
                        memcpy(&v2, pr_reg + gpr_list[r + 1].offset, 8);
                        format_gpr_row(row, sizeof(row),
                                       gpr_list[r].name, v1,
                                       gpr_list[r + 1].name, v2);
                    } else {
                        format_gpr_row(row, sizeof(row),
                                       gpr_list[r].name, v1, NULL, 0);
                    }
                    fields_add(pd, row, 1,
                               (r < 4) ? 1 : 0,  /* key regs selectable */
                               DETAIL_REG, r);
                }

                /* EFLAGS */
                {
                    uint64_t efl;
                    char efl_str[64];
                    memcpy(&efl, pr_reg + offsetof(struct user_regs_struct, eflags), 8);
                    eflags_string(efl, efl_str, sizeof(efl_str));

                    char efl_line[128];
                    snprintf(efl_line, sizeof(efl_line),
                             "EFLAGS: 0x%016" PRIx64 "  [ %s ]", efl, efl_str);
                    fields_add(pd, efl_line, 1, 0, DETAIL_NONE, -1);
                }

                /* Segment registers */
                {
                    char seg_row[128];
                    const char *seg_names[] = {"CS","DS","ES","FS","GS","SS"};
                    int offsets[] = {
                        offsetof(struct user_regs_struct, cs),
                        offsetof(struct user_regs_struct, ds),
                        offsetof(struct user_regs_struct, es),
                        offsetof(struct user_regs_struct, fs),
                        offsetof(struct user_regs_struct, gs),
                        offsetof(struct user_regs_struct, ss),
                    };
                    int pos = 0;
                    for (int s = 0; s < 6; s++) {
                        uint32_t v;
                        memcpy(&v, pr_reg + offsets[s], 4);
                        pos += snprintf(seg_row + pos,
                                       sizeof(seg_row) - (size_t)pos,
                                       "%s:0x%04X  ", seg_names[s], v);
                    }
                    fields_add(pd, seg_row, 1, 0, DETAIL_NONE, -1);
                }

                found = 1;
                break;
            }

            cursor += sizeof(Elf64_Nhdr) + n_align + d_align;
        }
    }

    if (!found) {
        fields_add(pd,
            "No register data found in this ELF file.",
            0, 0, DETAIL_NONE, -1);
        fields_add(pd,
            "(NT_PRSTATUS notes are present in core dumps and coredump sections)",
            1, 0, DETAIL_NONE, -1);
    }

    return 0;
}

/* ── Public: live ptrace register view ──────────────────────────── */

int render_live_registers(DebugState *ds, PanelData *pd) {
    if (!ds || !pd || !ds->regs_valid) return -1;

    struct user_regs_struct *r = &ds->regs;

    char title[80];
    snprintf(title, sizeof(title),
             "=== x86-64 Registers (PID %d, RIP=0x%llx) ===",
             ds->pid, (unsigned long long)r->rip);
    fields_add(pd, title, 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* GPRs in two-column rows */
    char row[128];
    for (int i = 0; i < GPR_COUNT; i += 2) {
        uint64_t v1 = ureg64(r, gpr_list[i].offset);
        if (i + 1 < GPR_COUNT) {
            uint64_t v2 = ureg64(r, gpr_list[i + 1].offset);
            format_gpr_row(row, sizeof(row),
                          gpr_list[i].name, v1,
                          gpr_list[i + 1].name, v2);
        } else {
            format_gpr_row(row, sizeof(row),
                          gpr_list[i].name, v1, NULL, 0);
        }
        fields_add(pd, row, 1,
                   (i < 4) ? 1 : 0,
                   DETAIL_REG, i);
    }

    /* EFLAGS */
    {
        uint64_t efl = r->eflags;
        char efl_str[64];
        eflags_string(efl, efl_str, sizeof(efl_str));

        char efl_line[128];
        snprintf(efl_line, sizeof(efl_line),
                 "EFLAGS: 0x%016" PRIx64 "  [ %s ]", efl, efl_str);
        fields_add(pd, efl_line, 1, 0, DETAIL_NONE, -1);
    }

    /* Segment registers */
    if (ds->fpregs_valid) {
        char seg_row[128];
        snprintf(seg_row, sizeof(seg_row),
                 "CS:0x%04llX  DS:0x%04llX  ES:0x%04llX  "
                 "FS:0x%04llX  GS:0x%04llX  SS:0x%04llX",
                 (unsigned long long)r->cs,
                 (unsigned long long)r->ds,
                 (unsigned long long)r->es,
                 (unsigned long long)r->fs,
                 (unsigned long long)r->gs,
                 (unsigned long long)r->ss);
        fields_add(pd, seg_row, 1, 0, DETAIL_NONE, -1);
    }

    /* Debug hint */
    if (ds->last_signal == SIGTRAP) {
        fields_add(pd, "[*] Stopped at breakpoint (SIGTRAP)",
                   1, 0, DETAIL_NONE, -1);
    } else if (ds->last_signal == SIGSTOP) {
        fields_add(pd, "[*] Stopped (SIGSTOP / attach)",
                   1, 0, DETAIL_NONE, -1);
    } else if (ds->last_signal != 0) {
        char sig[64];
        snprintf(sig, sizeof(sig), "[*] Signal: %d", ds->last_signal);
        fields_add(pd, sig, 1, 0, DETAIL_NONE, -1);
    }

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    return 0;
}

/* ── Single-column register view (调试模式 25% 面板) ──────────── */

int render_reg_single_col(DebugState *ds, PanelData *pd) {
    if (!ds || !pd || !ds->regs_valid) return -1;
    struct user_regs_struct *r = &ds->regs;

    char title[80];
    snprintf(title, sizeof(title), "=== Regs PID=%d ===", ds->pid);
    fields_add(pd, title, 0, 0, DETAIL_NONE, -1);

    char line[64];

    /* RIP: 独立一行, 红色高亮 (tui.c region_lines 检测 "RIP " 前缀) */
    snprintf(line,sizeof(line),"RIP  0x%llx",(unsigned long long)r->rip);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 通用寄存器 */
    #define REG(n, off) snprintf(line,sizeof(line),"%-4s 0x%llx",n,(unsigned long long)ureg64(r,off));fields_add(pd,line,1,1,DETAIL_NONE,(int)(off))
    REG("RAX", offsetof(struct user_regs_struct, rax));
    REG("RBX", offsetof(struct user_regs_struct, rbx));
    REG("RCX", offsetof(struct user_regs_struct, rcx));
    REG("RDX", offsetof(struct user_regs_struct, rdx));
    REG("RSI", offsetof(struct user_regs_struct, rsi));
    REG("RDI", offsetof(struct user_regs_struct, rdi));
    REG("R8",  offsetof(struct user_regs_struct, r8));
    REG("R9",  offsetof(struct user_regs_struct, r9));
    REG("R10", offsetof(struct user_regs_struct, r10));
    REG("R11", offsetof(struct user_regs_struct, r11));
    REG("R12", offsetof(struct user_regs_struct, r12));
    REG("R13", offsetof(struct user_regs_struct, r13));
    REG("R14", offsetof(struct user_regs_struct, r14));
    REG("R15", offsetof(struct user_regs_struct, r15));
    #undef REG

    /* R15 和 RBP/RSP 之间空行隔开, RBP/RSP 紧邻 */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(line,sizeof(line),"RBP  0x%llx",(unsigned long long)r->rbp);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);
    snprintf(line,sizeof(line),"RSP  0x%llx",(unsigned long long)r->rsp);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);

    char efl[64]; eflags_string(r->eflags, efl, sizeof(efl));
    snprintf(line,sizeof(line),"EFL %s", efl);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);

    /* Segment registers — 线程 TLS 研究关键 */
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(line,sizeof(line),"CS 0x%04llx  DS 0x%04llx",(unsigned long long)r->cs,(unsigned long long)r->ds);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);
    snprintf(line,sizeof(line),"ES 0x%04llx  FS 0x%04llx",(unsigned long long)r->es,(unsigned long long)r->fs);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);
    snprintf(line,sizeof(line),"GS 0x%04llx  SS 0x%04llx",(unsigned long long)r->gs,(unsigned long long)r->ss);
    fields_add(pd, line, 1, 1, DETAIL_NONE, -1);

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    fields_add(pd, "[F5]Cont [F7]Step [F8]Over", 1, 0, DETAIL_NONE, -1);
    fields_add(pd, "[F9]BP [F10]Detach", 1, 0, DETAIL_NONE, -1);
    return 0;
}

/* ── Popup text formatter ──────────────────────────────────────── */

/* Internal: read uint64_t from struct user_regs_struct at known offset */
static uint64_t popup_read64(const uint8_t *pr, int off) {
    uint64_t v = 0;
    memcpy(&v, pr + off, sizeof(v));
    return v;
}

static uint32_t popup_read32(const uint8_t *pr, int off) {
    uint32_t v = 0;
    memcpy(&v, pr + off, sizeof(v));
    return v;
}

const char *registers_popup_text(Elf64_Ctx *ctx)
{
    static char content[4096];
    memset(content, 0, sizeof(content));

    if (!ctx || !ctx->map) return "";

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
    int found = 0;
    int pos = 0;

    /* Walk PT_NOTE looking for NT_PRSTATUS */
    for (int i = 0; i < ehdr->e_phnum && !found; i++) {
        Elf64_Phdr *ph = elf_get_phdr(ctx, i);
        if (!ph || ph->p_type != PT_NOTE) continue;

        const uint8_t *data = ctx->map + ph->p_offset;
        size_t size = (size_t)ph->p_filesz;
        if (ph->p_offset >= ctx->size) continue;
        if (ph->p_offset + size > ctx->size)
            size = ctx->size - (size_t)ph->p_offset;

        const uint8_t *cursor = data;
        const uint8_t *end = data + size;

        while (cursor + sizeof(Elf64_Nhdr) <= end) {
            const Elf64_Nhdr *nhdr = (const Elf64_Nhdr *)cursor;
            size_t n_align = ((size_t)nhdr->n_namesz + 3) & ~(size_t)3;
            size_t d_align = ((size_t)nhdr->n_descsz + 3) & ~(size_t)3;
            size_t desc_off = sizeof(Elf64_Nhdr) + n_align;

            if (cursor + desc_off + d_align > end) break;

            /* NT_PRSTATUS = 1, pr_reg offset = 112, uregs size = 216 */
            if (nhdr->n_type == 1 &&
                nhdr->n_descsz >= (uint32_t)(112 + 216)) {

                const uint8_t *pr = cursor + desc_off + 112;

                pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "  %-4s  0x%llx    %-4s  0x%llx\n"
                    "\n"
                    "  RIP     0x%llx\n"
                    "  RSP     0x%llx\n"
                    "  RFLAGS  0x%llx",
                    "RAX", (unsigned long long)popup_read64(pr, 32),
                    "RBX", (unsigned long long)popup_read64(pr, 72),
                    "RCX", (unsigned long long)popup_read64(pr, 24),
                    "RDX", (unsigned long long)popup_read64(pr, 16),
                    "RSI", (unsigned long long)popup_read64(pr, 8),
                    "RDI", (unsigned long long)popup_read64(pr, 0),
                    "R8",  (unsigned long long)popup_read64(pr, 40),
                    "R9",  (unsigned long long)popup_read64(pr, 48),
                    "R10", (unsigned long long)popup_read64(pr, 56),
                    "R11", (unsigned long long)popup_read64(pr, 64),
                    "R12", (unsigned long long)popup_read64(pr, 88),
                    "R13", (unsigned long long)popup_read64(pr, 96),
                    "R14", (unsigned long long)popup_read64(pr, 104),
                    "R15", (unsigned long long)popup_read64(pr, 112),
                    "RBP", (unsigned long long)popup_read64(pr, 80),
                    "orig",(unsigned long long)popup_read64(pr, 120),
                    (unsigned long long)popup_read64(pr, 128),
                    (unsigned long long)popup_read64(pr, 152),
                    (unsigned long long)popup_read64(pr, 144));

                pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
                    "\n  CS:0x%04x  DS:0x%04x  ES:0x%04x  "
                    "FS:0x%04x  GS:0x%04x  SS:0x%04x",
                    popup_read32(pr, 136), popup_read32(pr, 184),
                    popup_read32(pr, 192), popup_read32(pr, 200),
                    popup_read32(pr, 208), popup_read32(pr, 160));

                found = 1;
                break;
            }
            cursor += sizeof(Elf64_Nhdr) + n_align + d_align;
        }
    }

    if (!found) return "";

    snprintf(content + pos, sizeof(content) - (size_t)pos,
             "\n\n  [q or Esc to close]");
    return content;
}

/* ── Live process snapshot (ptrace attach → read → detach) ───── */

const char *registers_snapshot_pid(int pid)
{
    static char content[4096];
    memset(content, 0, sizeof(content));

    if (pid <= 0) {
        snprintf(content, sizeof(content), "Invalid PID: %d", pid);
        return content;
    }

    DebugState *ds = NULL;
    if (debug_attach((pid_t)pid, &ds) != 0) {
        snprintf(content, sizeof(content),
                 "Attach to PID %d failed:\n  %s\n\n"
                 "Requirements:\n"
                 "  - Same UID as target process, or root\n"
                 "  - ptrace_scope = 0\n"
                 "    (echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope)",
                 pid, debug_error());
        return content;
    }

    struct user_regs_struct *r = &ds->regs;

    int pos = 0;
    pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
        "  PID: %d    RIP: 0x%llx\n\n",
        pid, (unsigned long long)r->rip);

    pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
        "  RAX  0x%llx    RBX  0x%llx\n"
        "  RCX  0x%llx    RDX  0x%llx\n"
        "  RSI  0x%llx    RDI  0x%llx\n"
        "  R8   0x%llx    R9   0x%llx\n"
        "  R10  0x%llx    R11  0x%llx\n"
        "  R12  0x%llx    R13  0x%llx\n"
        "  R14  0x%llx    R15  0x%llx\n"
        "  RBP  0x%llx    RSP  0x%llx\n",
        (unsigned long long)r->rax, (unsigned long long)r->rbx,
        (unsigned long long)r->rcx, (unsigned long long)r->rdx,
        (unsigned long long)r->rsi, (unsigned long long)r->rdi,
        (unsigned long long)r->r8,  (unsigned long long)r->r9,
        (unsigned long long)r->r10, (unsigned long long)r->r11,
        (unsigned long long)r->r12, (unsigned long long)r->r13,
        (unsigned long long)r->r14, (unsigned long long)r->r15,
        (unsigned long long)r->rbp, (unsigned long long)r->rsp);

    uint64_t efl = r->eflags;
    pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
        "\n  RFLAGS  0x%llx", (unsigned long long)efl);

    /* Decompose EFLAGS */
    struct { uint64_t bit; const char *name; } fl[] = {
        {1<<0,"CF"},{1<<2,"PF"},{1<<4,"AF"},{1<<6,"ZF"},
        {1<<7,"SF"},{1<<8,"TF"},{1<<9,"IF"},{1<<10,"DF"},
        {1<<11,"OF"},{1<<14,"NT"},{1<<16,"RF"},{1<<17,"VM"},
        {1<<18,"AC"},{1<<19,"VIF"},{1<<20,"VIP"},{1<<21,"ID"},
    };
    int has_flags = 0;
    for (size_t i = 0; i < sizeof(fl)/sizeof(fl[0]); i++) {
        if (efl & fl[i].bit) {
            pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
                           "%s %s", has_flags ? " " : "  [ ", fl[i].name);
            has_flags = 1;
        }
    }
    if (has_flags) {
        pos += snprintf(content + pos, sizeof(content) - (size_t)pos, " ]");
    }

    pos += snprintf(content + pos, sizeof(content) - (size_t)pos,
        "\n\n  CS:0x%04llx  DS:0x%04llx  ES:0x%04llx  "
        "FS:0x%04llx  GS:0x%04llx  SS:0x%04llx",
        (unsigned long long)r->cs, (unsigned long long)r->ds,
        (unsigned long long)r->es, (unsigned long long)r->fs,
        (unsigned long long)r->gs, (unsigned long long)r->ss);

    debug_detach(ds);
    debug_free(ds);

    snprintf(content + pos, sizeof(content) - (size_t)pos,
             "\n\n  [q or Esc to close]");
    return content;
}
