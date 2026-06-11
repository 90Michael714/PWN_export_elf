/*
 * tui_left.c — 左面板: 导航树 + 功能按钮 (可折叠分组)
 */

#include "tui.h"
#include "tui_panels.h"
#include "tui_colors.h"
#include "tui_buttons.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 折叠状态标记 */
static int phdr_expanded    = 0;  /* Program Headers 默认折叠 */
static int sections_expanded = 0;  /* Section Headers 默认折叠 */
static int code_expanded     = 0;  /* Code Analysis */
static int security_expanded = 0;  /* Security Audit */
static int data_expanded     = 0;  /* Data Inspector */
static int tools_expanded    = 0;  /* Tools */
static int debug_expanded    = 0;  /* Debug & Runtime */
static int exploit_expanded  = 0;  /* Exploit Tools */

/* 添加可折叠组标题 (detail_index 用于切换) */
static void add_group_header(PanelData *pd, const char *name,
                             int count, int expanded, int group_id)
{
    char buf[80];
    snprintf(buf, sizeof(buf), "%s %s",
             expanded ? "▼" : "▶", name);
    fields_add(pd, buf, 0, 1, DETAIL_NONE, group_id);
}

/* 添加按钮条目 */
static void add_button(PanelData *pd, const char *label, int btn_id)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "  %-14s", label);
    fields_add(pd, buf, 1, 1, DETAIL_NONE, btn_id);
}

void left_panel_init(PanelData *pd, Elf64_Ctx *ctx)
{
    pd->count = 0;
    pd->capacity = 0;
    pd->fields = NULL;
    pd->cursor = 0;
    pd->scroll = 0;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)ctx->map;

    /* ============================================
     * 0. Test 弹窗按钮
     * ============================================ */
    fields_add(pd, "▶ Test (Popup Demo)", 0, 1, DETAIL_NONE, -4);

    /* ============================================
     * 1. ELF Header
     * ============================================ */
    fields_add(pd, "▶ ELF Header", 0, 1, DETAIL_EHDR, -1);

    /* ============================================
     * 2. Program Headers (可折叠)
     * ============================================ */
    char buf[64];
    snprintf(buf, sizeof(buf), "%s Program Headers",
             phdr_expanded ? "▼" : "▶");
    fields_add(pd, buf, 0, 1, DETAIL_NONE, -2);

    if (phdr_expanded) {
        for (int i = 0; i < ehdr->e_phnum; i++) {
            Elf64_Phdr *ph = elf_get_phdr(ctx, i);
            char fb[8];
            snprintf(buf, sizeof(buf), "  [%02d] %-14s  0x%lX  %s",
                     i, elf_p_type_str(ph->p_type),
                     (unsigned long)ph->p_vaddr,
                     elf_p_flags_str(ph->p_flags, fb, sizeof(fb)));
            fields_add(pd, buf, 1, 1, DETAIL_PHDR, i);
        }
    }

    /* ============================================
     * 3. Section Headers (可折叠)
     * ============================================ */
    snprintf(buf, sizeof(buf), "%s Section Headers",
             sections_expanded ? "▼" : "▶");
    fields_add(pd, buf, 0, 1, DETAIL_NONE, -3);

    if (sections_expanded) {
        for (int i = 0; i < ehdr->e_shnum; i++) {
            const char *name = elf_section_name(ctx, i);
            Elf64_Shdr *sh = elf_get_shdr(ctx, i);
            char flags_buf[16];
            snprintf(buf, sizeof(buf), "  [%02d] %-28s %-12s %s",
                     i, name,
                     elf_sh_type_str(sh->sh_type),
                     elf_sh_flags_str(sh->sh_flags, flags_buf, sizeof(flags_buf)));
            fields_add(pd, buf, 1, 1, DETAIL_SHDR, i);
        }
    }

    /* ============================================
     * 3b. Security Audit (可折叠)
     * ============================================ */
    add_group_header(pd, "Security Audit", 6, security_expanded, -31);
    if (security_expanded) {
        add_button(pd, "Hardening",  BTN_HARDENING);
        add_button(pd, "DangerFunc", BTN_DANGERFUNC);
        add_button(pd, "VulnReport", BTN_TRANS_VULN);
        add_button(pd, "ROPgadget",  BTN_ROPGADGET);
        add_button(pd, "AtkSurface", BTN_ATKSURFACE);
        add_button(pd, "SegPerm",    BTN_SEGPERM);
    }

    /* ============================================
     * 4. Code Analysis (可折叠)
     * ============================================ */
    add_group_header(pd, "Code Analysis", 7, code_expanded, -30);
    if (code_expanded) {
        add_button(pd, "Disasm",     BTN_DISASM);
        add_button(pd, "InsnTrans",  BTN_TRANS_INSN);
        add_button(pd, "GOT/PLT",    BTN_GOTPLT);
        add_button(pd, "HexDump",    BTN_HEXDUMP);
        add_button(pd, "FuncMap",    BTN_FUNCMAP);
        add_button(pd, "DataFlow",   BTN_DATAFLOW);
        add_button(pd, "DF Inter",   BTN_DATAFLOW_INTER);
    }

    /* ============================================
     * 4b. Debug (可折叠) — Attach 进程 + 运行时分析
     * ============================================ */
    add_group_header(pd, "Debug", 11, debug_expanded, -35);
    if (debug_expanded) {
        add_button(pd, "Attach",      -34);
        add_button(pd, "VMMap",       BTN_VMMAP);
        add_button(pd, "SymResolve",  BTN_SYMRESOLVE);
        add_button(pd, "Backtrace",   BTN_BACKTRACE);
        add_button(pd, "T-scope",     BTN_TELESCOPE);
        add_button(pd, "HW BP",       BTN_HWBP);
        add_button(pd, "StackView",   BTN_STACK);
        add_button(pd, "Heap",        BTN_HEAP);
        add_button(pd, "GOT/PLT(Dyn)", BTN_GOTPLT_DYN);
        add_button(pd, "HeapTrace",   BTN_HEAPTRACE);
        add_button(pd, "PT Trace",    BTN_PTTRACE);
    }

    /* Decompile: 独立顶级入口 (v4 section-aware C伪代码) */
    fields_add(pd, "▶ Decompile", 0, 1, DETAIL_NONE, BTN_DECOMPILE);


    /* ============================================
     * 5. Data Inspector (可折叠)
     * ============================================ */
    add_group_header(pd, "Data Inspector", 4, data_expanded, -32);
    if (data_expanded) {
        add_button(pd, "MemLayout",  BTN_MEMLAYOUT);
        add_button(pd, "InitArray",  BTN_INITARRAY);
        add_button(pd, "StrXRef",    BTN_STRXREF);
        add_button(pd, "EHFrame",    BTN_EHFRAME);
    }

    /* ============================================
     * 7. Exploit Tools (可折叠)
     * ============================================ */
    add_group_header(pd, "Exploit Tools", 11, exploit_expanded, -36);
    if (exploit_expanded) {
        add_button(pd, "VulnScan",    BTN_VULNSCAN);
        add_button(pd, "OneGadget",   BTN_ONEGADGET);
        add_button(pd, "SysCall",     BTN_SYSCALL);
        add_button(pd, "ExprEval",    BTN_EXPREVAL);
        add_button(pd, "BpCond",      BTN_BPCOND);
        add_button(pd, "Taint",       BTN_TAINT);
        add_button(pd, "ROPchain",    BTN_ROPCHAIN);
        add_button(pd, "Fuzzer",      BTN_FUZZER);
        add_button(pd, "BinDiff",     BTN_BINDIFF);
        add_button(pd, "Symbolic",    BTN_SYMBOLIC);
        add_button(pd, "RtDecomp",    BTN_RT_DECOMP);
    }

    /* ============================================
     * 9. Other (可折叠)
     * ============================================ */
    add_group_header(pd, "Other", 4, tools_expanded, -33);
    if (tools_expanded) {
        add_button(pd, "Export",     BTN_EXPORT);
        add_button(pd, "KeyHelp",    BTN_KEYHELP);
        add_button(pd, "About",      BTN_ABOUT);
        add_button(pd, "History",    BTN_HISTORY);
    }
}

/* ================================================================
 * 折叠组切换辅助
 * ================================================================ */

static void toggle_group(int group_id)
{
    switch (group_id) {
        case -2:  phdr_expanded     = !phdr_expanded;     return;
        case -3:  sections_expanded = !sections_expanded; return;
        case -30: code_expanded     = !code_expanded;     return;
        case -31: security_expanded = !security_expanded; return;
        case -32: data_expanded     = !data_expanded;     return;
        case -33: tools_expanded    = !tools_expanded;    return;
        case -35: debug_expanded    = !debug_expanded;    return;
        case -36: exploit_expanded  = !exploit_expanded;  return;
    }
}

static void rebuild_left_panel(PanelData *pd, Elf64_Ctx *ctx, int saved_cursor)
{
    int saved_scroll = pd->scroll;
    if (pd->fields) {
        fields_free(pd->fields, pd->count);
        pd->fields = NULL;
        pd->count = 0;
        pd->capacity = 0;
    }
    left_panel_init(pd, ctx);
    pd->cursor = saved_cursor;
    pd->scroll = saved_scroll;
    if (pd->cursor >= pd->count) pd->cursor = pd->count - 1;
    if (pd->cursor < 0) pd->cursor = 0;
    if (pd->scroll > pd->count - 1 && pd->count > 0) pd->scroll = pd->count - 1;
    if (pd->scroll < 0) pd->scroll = 0;
}

/* ================================================================
 * 左面板选中 → 填充中面板
 * ================================================================ */

void left_panel_handle_enter(PanelData *left, PanelData *middle,
                              PanelData *right, Elf64_Ctx *ctx)
{
    if (!left || left->cursor < 0 || left->cursor >= left->count) return;
    if (!middle) return;

    Elf64_Field *sel = &left->fields[left->cursor];
    int idx = sel->detail_index;

    /* 折叠组标题切换 (-2=PHDR, -3=SHDR, -30..-36=功能组, 排除-34=Attach) */
    if (sel->detail_kind == DETAIL_NONE &&
        ((idx >= -36 && idx <= -30 && idx != -34) || idx == -2 || idx == -3)) {
        toggle_group(idx);
        int saved = left->cursor;
        rebuild_left_panel(left, ctx, saved);
        return;
    }

    /* 清空中面板 */
    if (middle->fields) {
        fields_free(middle->fields, middle->count);
        middle->fields = NULL;
        middle->count = 0;
        middle->capacity = 0;
        middle->cursor = 0;
        middle->scroll = 0;
    }

    /* 按 detail_kind/index 分发 */
    if (sel->detail_kind == DETAIL_EHDR) {
        parse_ehdr(ctx, middle);
    } else if (sel->detail_kind == DETAIL_PHDR) {
        /* 展开单个 Program Header 详情到中面板 */
        fields_add(middle, "=== Program Header Detail ===", 0, 0, DETAIL_NONE, -1);
        char detail_buf[512];
        Elf64_Phdr *ph = elf_get_phdr(ctx, idx);
        char fb[8];
        snprintf(detail_buf, sizeof(detail_buf), "p_type:   0x%08X — %s",
                 ph->p_type, elf_p_type_str(ph->p_type));
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_flags:  0x%08X (%s)",
                 ph->p_flags, elf_p_flags_str(ph->p_flags, fb, sizeof(fb)));
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_offset: 0x%lX", (unsigned long)ph->p_offset);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_vaddr:  0x%lX", (unsigned long)ph->p_vaddr);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_paddr:  0x%lX", (unsigned long)ph->p_paddr);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_filesz: 0x%lX (%lu)", (unsigned long)ph->p_filesz, (unsigned long)ph->p_filesz);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_memsz:  0x%lX (%lu)", (unsigned long)ph->p_memsz, (unsigned long)ph->p_memsz);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);
        snprintf(detail_buf, sizeof(detail_buf), "p_align:  0x%lX", (unsigned long)ph->p_align);
        fields_add(middle, detail_buf, 1, 0, DETAIL_NONE, -1);

        /* ── 列出该段包含的节 ── */
        {
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ctx->map;
            uint64_t seg_start = ph->p_vaddr;
            uint64_t seg_end   = ph->p_vaddr + ph->p_memsz;

            /* 先统计匹配的节数 */
            int n_matched = 0;
            for (int i = 0; i < ehdr->e_shnum; i++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, i);
                if (!sh || sh->sh_addr == 0 || sh->sh_size == 0) continue;
                if (sh->sh_addr >= seg_start &&
                    sh->sh_addr + sh->sh_size <= seg_end)
                    n_matched++;
            }

            fields_add(middle, "", 0, 0, DETAIL_NONE, -1);
            snprintf(detail_buf, sizeof(detail_buf),
                     "── Contains %d section(s) ──", n_matched);
            fields_add(middle, detail_buf, 0, 0, DETAIL_NONE, -1);

            /* 列出匹配的节: 编号 + 名称 + 地址范围 + 大小 */
            for (int i = 0; i < ehdr->e_shnum; i++) {
                Elf64_Shdr *sh = elf_get_shdr(ctx, i);
                if (!sh || sh->sh_addr == 0 || sh->sh_size == 0) continue;
                if (sh->sh_addr >= seg_start &&
                    sh->sh_addr + sh->sh_size <= seg_end) {
                    const char *sname = elf_section_name(ctx, i);
                    snprintf(detail_buf, sizeof(detail_buf),
                             "[%2d] %-20s 0x%lx-0x%lx  (%lu B)",
                             i, sname ? sname : "?",
                             (unsigned long)sh->sh_addr,
                             (unsigned long)(sh->sh_addr + sh->sh_size),
                             (unsigned long)sh->sh_size);
                    fields_add(middle, detail_buf, 0, 0,
                               DETAIL_NONE, -1);
                }
            }
        }
    } else if (sel->detail_kind == DETAIL_SHDR) {
        Elf64_Shdr *sh = elf_get_shdr(ctx, idx);

        /* 清空右面板 (为详细内容准备) */
        if (right) {
            if (right->fields) {
                fields_free(right->fields, right->count);
                right->fields = NULL;
                right->count = 0;
                right->capacity = 0;
                right->cursor = 0;
                right->scroll = 0;
                right->scroll_x = 0;
            }
        }

        switch (sh->sh_type) {
            case SHT_SYMTAB:
            case SHT_DYNSYM:     parse_symtab(ctx, idx, middle);    break;
            case SHT_RELA:
            case SHT_REL:        parse_rela(ctx, idx, middle);      break;
            case SHT_NOTE:       parse_note(ctx, idx, middle);      break;
            case SHT_DYNAMIC:    parse_dynamic(ctx, middle);        break;
            case SHT_GNU_verdef:
            case SHT_GNU_verneed:
            case SHT_GNU_versym: parse_version(ctx, middle);        break;
            case SHT_INIT_ARRAY:
            case SHT_FINI_ARRAY:
            case SHT_PREINIT_ARRAY:
                                 parse_init_array(ctx, idx, middle); break;
            case SHT_HASH:
            case SHT_GNU_HASH:
            default:
                /* 中面板: ELF 节头字段 + DB 统计 */
                parse_shdr_detail(ctx, idx, middle);
                /* 右面板: 详细内容 (指令/符号/字符串/hexdump) */
                if (right) parse_shdr_detail_right(ctx, idx, right);
                break;
        }
    }
}
