/* btn_gotplt_dyn.c — Dynamic GOT/PLT: 从运行进程读取已解析的 GOT 值
 *
 * 中面板: GOT 条目列表 (selectable)
 * 右面板: Enter 选中条目 → 详细展开 (解析地址/库/hexdump)
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── vmmap 接口 ─────────────────────────────────────────────────── */
typedef struct { uint64_t start,end;char perms[5];uint64_t offset;
    unsigned int dev_major,dev_minor;unsigned long inode;char path[256];} vmmap_entry_t;
extern int vmmap_read(const struct DebugState *ds, vmmap_entry_t *e, int *c);

/* ── 运行时 GOT 地址缓存 (供 Enter handler 使用) ──────────────── */
static uint64_t dyn_got_runtime = 0;
static int      dyn_got_gc = 0;
static uint64_t dyn_got_file_addr = 0;

/* ── VMMap 缓存 ────────────────────────────────────────────────── */
static vmmap_entry_t dyn_entries[256];
static int            dyn_nents = 0;

/* ── 符号表缓存 ────────────────────────────────────────────────── */
#define MAX_SLOTS 512
typedef struct { uint64_t addr; char name[128]; } dyn_slot_t;
static dyn_slot_t dyn_slots[MAX_SLOTS];
static int        dyn_nslots = 0;

/* 辅助: 查找地址所属库名 */
static const char *resolve_lib(uint64_t addr, char *out, size_t out_sz)
{
    for (int i = 0; i < dyn_nents; i++) {
        if (addr >= dyn_entries[i].start && addr < dyn_entries[i].end) {
            if (dyn_entries[i].path[0]) {
                char *slash = strrchr(dyn_entries[i].path, '/');
                snprintf(out, out_sz, "%s", slash ? slash+1 : dyn_entries[i].path);
            } else {
                if (dyn_entries[i].perms[2]=='x') snprintf(out,out_sz,"[code]");
                else if (dyn_entries[i].perms[1]=='w') snprintf(out,out_sz,"[heap]");
                else snprintf(out,out_sz,"[anon]");
            }
            return out;
        }
    }
    snprintf(out, out_sz, "?");
    return out;
}

/* ── 按钮: 中面板显示 GOT 列表 ────────────────────────────────── */

int btn_gotplt_dyn_action(TuiApp *app)
{
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "Dynamic GOT/PLT",
            "No debug session active.\n\n"
            "Attach to a running process first.");
        app->need_render = 1; return 0;
    }
    if (!app->elf || !app->elf->map) {
        tui_show_popup(app, "Dynamic GOT/PLT", "No ELF loaded.");
        app->need_render = 1; return 0;
    }

    /* ── 1. 定位 GOT/PLT 节 ────────────────────────────────── */
    Elf64_Ehdr *eh = (Elf64_Ehdr *)app->elf->map;
    int shnum = (int)eh->e_shnum;
    Elf64_Shdr *got_sec = NULL, *rela_sec = NULL;
    Elf64_Shdr *dynsym_sec = NULL, *dynstr_sec = NULL;
    int got_idx = -1;

    for (int i = 0; i < shnum; i++) {
        const char *n = elf_section_name(app->elf, i);
        if (!n) continue;
        Elf64_Shdr *sh = elf_get_shdr(app->elf, i);
        if (!sh || sh->sh_size == 0) continue;
        if (!strcmp(n, ".got.plt")) { got_sec = sh; got_idx = i; }
        else if (!strcmp(n, ".got") && !got_sec) { got_sec = sh; got_idx = i; }
        else if (!strcmp(n, ".rela.plt")) rela_sec = sh;
        else if (sh->sh_type == SHT_DYNSYM) dynsym_sec = sh;
    }
    if (dynsym_sec) dynstr_sec = elf_get_shdr(app->elf, dynsym_sec->sh_link);
    if (!got_sec || got_sec->sh_size == 0) {
        tui_show_popup(app, "Dynamic GOT/PLT", "No GOT section in ELF.");
        app->need_render = 1; return 0;
    }

    /* ── 2. 运行时基址 ────────────────────────────────────── */
    dyn_got_runtime = got_sec->sh_addr;
    dyn_got_file_addr = got_sec->sh_addr;
    {
        dyn_nents = 256;
        if (vmmap_read(app->debug, dyn_entries, &dyn_nents) == 0) {
            for (int i = 0; i < dyn_nents; i++) {
                if (dyn_entries[i].perms[2] == 'x' && dyn_entries[i].path[0] &&
                    !strstr(dyn_entries[i].path, ".so")) {
                    Elf64_Phdr *ph = (Elf64_Phdr *)(app->elf->map + eh->e_phoff);
                    for (int p = 0; p < (int)eh->e_phnum; p++) {
                        if (ph[p].p_type == PT_LOAD && (ph[p].p_flags & PF_X)) {
                            dyn_got_runtime = dyn_entries[i].start
                                - ph[p].p_vaddr + got_sec->sh_addr;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    /* ── 3. 符号表 ────────────────────────────────────────── */
    dyn_nslots = 0;
    if (rela_sec && dynsym_sec && dynstr_sec) {
        Elf64_Rela *r = (Elf64_Rela *)(app->elf->map + rela_sec->sh_offset);
        int nr = (int)(rela_sec->sh_size / sizeof(Elf64_Rela));
        Elf64_Sym *s = (Elf64_Sym *)(app->elf->map + dynsym_sec->sh_offset);
        for (int i = 0; i < nr && dyn_nslots < MAX_SLOTS; i++) {
            uint32_t si = (uint32_t)(r[i].r_info >> 32);
            if (si * sizeof(Elf64_Sym) < dynsym_sec->sh_size) {
                dyn_slots[dyn_nslots].addr = r[i].r_offset;
                const char *nm = elf_strtab_get(app->elf,
                    dynstr_sec->sh_offset, s[si].st_name);
                snprintf(dyn_slots[dyn_nslots].name,
                    sizeof(dyn_slots[dyn_nslots].name), "%s", nm ? nm : "?");
                dyn_nslots++;
            }
        }
    }

    /* ── 4. 清空中面板 ────────────────────────────────────── */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL; app->middle_data.count = 0;
        app->middle_data.capacity = 0;
        app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    /* ── 5. 标题 ──────────────────────────────────────────── */
    char buf[512];
    int gc = (int)(got_sec->sh_size / sizeof(Elf64_Addr));
    dyn_got_gc = gc;

    /* RELRO 检测 */
    int relro_full = 0;
    { Elf64_Phdr *ph = (Elf64_Phdr *)(app->elf->map + eh->e_phoff);
      for (int p = 0; p < (int)eh->e_phnum; p++)
          if (ph[p].p_type == PT_GNU_RELRO) relro_full = 1; }
    int is_partial = (got_idx >= 0 && elf_section_name(app->elf, got_idx) &&
        !strcmp(elf_section_name(app->elf, got_idx), ".got.plt"));
    const char *rs = relro_full && !is_partial ? "FULL" :
                     (is_partial ? "PARTIAL" : "NONE");

    snprintf(buf, sizeof(buf), "=== Dynamic GOT/PLT (PID=%d, RELRO:%s) ===",
             app->debug->pid, rs);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "GOT@0x%lx (%d slots)  [Enter]=detail  [h]=back",
             (unsigned long)dyn_got_runtime, gc);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);

    /* ── 6. GOT[0..2] Reserved ──────────────────────────────── */
    fields_add(&app->middle_data, "─── Reserved ───", 0, 0, DETAIL_NONE, -1);
    const char *rd[] = {"[_DYNAMIC]", "[link_map]", "[_dl_runtime_resolve]"};
    for (int i = 0; i < 3 && i < gc; i++) {
        uint64_t ga = dyn_got_runtime + (uint64_t)(i * sizeof(Elf64_Addr));
        uint64_t val = 0;
        debug_readmem(app->debug, ga, &val, sizeof(val));
        char lib[64]; resolve_lib(val, lib, sizeof(lib));
        snprintf(buf, sizeof(buf),
            "GOT[%d]  %-32s  %-24s  0x%016lx  0x%016lx",
            i, rd[i], lib, (unsigned long)ga, (unsigned long)val);
        fields_add(&app->middle_data, buf, 0, 1, DETAIL_NONE, (int)(ga & 0xFFFF));
    }

    /* ── 7. Imported Functions ─────────────────────────────── */
    if (gc > 3)
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);

    int resolved = 0, lazy = 0;
    for (int i = 3; i < gc; i++) {
        uint64_t ga = dyn_got_runtime + (uint64_t)(i * sizeof(Elf64_Addr));
        uint64_t val = 0;
        debug_readmem(app->debug, ga, &val, sizeof(val));

        /* 符号名 */
        uint64_t file_ga = dyn_got_file_addr + (uint64_t)(i * sizeof(Elf64_Addr));
        const char *sn = "?";
        for (int s = 0; s < dyn_nslots; s++)
            if (dyn_slots[s].addr == file_ga) { sn = dyn_slots[s].name; break; }

        /* 库名 + 状态 */
        char lib[64];
        if (val == 0 || val < 0x1000) {
            snprintf(lib, sizeof(lib), "(lazy)"); lazy++;
        } else {
            resolve_lib(val, lib, sizeof(lib)); resolved++;
        }

        snprintf(buf, sizeof(buf),
            "GOT[%d]  %-32s  %-24s  0x%016lx  0x%016lx",
            i, sn, lib, (unsigned long)ga, (unsigned long)val);
        fields_add(&app->middle_data, buf, 0, 1, DETAIL_NONE, (int)(ga & 0xFFFF));
    }

    /* ── 8. 摘要 ──────────────────────────────────────────── */
    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "── %d imports, %d resolved, %d lazy  |  RELRO: %s",
             gc - 3, resolved, lazy, rs);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
    if (resolved > 0)
        fields_add(&app->middle_data,
            "Resolved values leak libc/ld base for ASLR bypass",
            0, 0, DETAIL_NONE, -1);
    if (!is_partial && !relro_full)
        fields_add(&app->middle_data,
            "⚠ No RELRO — GOT overwrite trivial", 0, 0, DETAIL_NONE, -1);

    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ── Enter handler: 中面板选中 GOT 条目 → 右面板详情 ────────────
 * 被 tui_input.c PANEL_MIDDLE Enter 调用
 */
int dyn_gotplt_show_detail(TuiApp *app, const char *line)
{
    if (!app || !app->debug || !line) return -1;

    /* 解析新列格式: "GOT[N]  Symbol  Library  0xGOT_ADDR  0xVAL"
     * 用 strstr 定位两个 0x 地址 */
    const char *p = strstr(line, "0x");
    if (!p) return -1;
    uint64_t got_addr = strtoull(p, NULL, 16);
    p = strstr(p + 2, "0x");
    if (!p) return -1;
    uint64_t val = strtoull(p, NULL, 16);
    if (!got_addr) return -1;

    /* 清空右面板 */
    if (app->right_data.fields) {
        fields_free(app->right_data.fields, app->right_data.count);
        app->right_data.fields = NULL; app->right_data.count = 0;
        app->right_data.capacity = 0;
        app->right_data.cursor = 0; app->right_data.scroll = 0;
        app->right_data.scroll_x = 0;
    }

    char buf[384];
    snprintf(buf, sizeof(buf), "=== GOT Entry Detail ===");
    fields_add(&app->right_data, buf, 0, 0, DETAIL_NONE, -1);

    /* GOT 地址和值 */
    snprintf(buf, sizeof(buf), "GOT addr:    0x%lx", (unsigned long)got_addr);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Runtime val: 0x%lx", (unsigned long)val);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);

    if (val > 0x1000) {
        /* 解析值 → 库名 */
        char lib[64]; resolve_lib(val, lib, sizeof(lib));
        snprintf(buf, sizeof(buf), "Library:     %s", lib);
        fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);

        /* 显示解析地址处的 hexdump */
        fields_add(&app->right_data, "", 0, 0, DETAIL_NONE, -1);
        snprintf(buf, sizeof(buf), "── Hexdump @ 0x%lx ──", (unsigned long)val);
        fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);

        uint8_t mem[64];
        int nr = debug_readmem(app->debug, val, mem, sizeof(mem));
        if (nr > 0) {
            char hx[100];
            for (int off = 0; off < nr; off += 16) {
                int hp = 0;
                hp += snprintf(hx+hp, sizeof(hx)-hp, "0x%lx  ",
                    (unsigned long)(val + off));
                for (int b = 0; b < 16; b++) {
                    if (off+b < nr)
                        hp += snprintf(hx+hp, sizeof(hx)-hp, "%02x ", mem[off+b]);
                    else hp += snprintf(hx+hp, sizeof(hx)-hp, "   ");
                }
                hp += snprintf(hx+hp, sizeof(hx)-hp, " ");
                for (int b = 0; b < 16 && off+b < nr; b++) {
                    uint8_t c = mem[off+b];
                    hp += snprintf(hx+hp, sizeof(hx)-hp, "%c",
                        (c >= 32 && c < 127) ? (char)c : '.');
                }
                fields_add(&app->right_data, hx, 1, 0, DETAIL_NONE, -1);
            }
        } else {
            fields_add(&app->right_data, "(cannot read memory at resolved addr)",
                1, 0, DETAIL_NONE, -1);
        }
    } else {
        fields_add(&app->right_data, "Status:      UNRESOLVED (lazy binding)",
            1, 0, DETAIL_NONE, -1);
    }

    /* GOT 地址处的 raw bytes */
    fields_add(&app->right_data, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "── Raw GOT slot @ 0x%lx ──", (unsigned long)got_addr);
    fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);

    uint8_t raw[8];
    if (debug_readmem(app->debug, got_addr, raw, 8) == 8) {
        snprintf(buf, sizeof(buf), "  %02x %02x %02x %02x %02x %02x %02x %02x",
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]);
        fields_add(&app->right_data, buf, 1, 0, DETAIL_NONE, -1);
    }

    return 0;
}
