/* btn_symresolve.c — SymResolve: 运行时符号解析 (ASLR绕过第一步)
 *
 * 未attach → PID输入弹窗
 * 已attach → 从 /proc/pid/maps 找所有已加载库 → 读取库的 ELF 符号表
 *           → 全部符号 + DB交叉对比 + 寄存器标注
 *
 * 交互键: [s]=search  [l]=leak→base  [e]=ASLR entropy  [a]=show all  [Enter]=nav
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/debug_worker.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── 从磁盘 ELF 读符号表 ────────────────────────────────────────── */

typedef struct { char name[64]; uint64_t off; uint64_t sz; } rsym_t;

static int elf_read_syms(const char *path, rsym_t *out, int max) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, sizeof(eh), 1, fp) != 1
        || eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_ident[EI_MAG1] != ELFMAG1
        || eh.e_ident[EI_MAG2] != ELFMAG2 || eh.e_ident[EI_MAG3] != ELFMAG3
        || eh.e_ident[EI_CLASS] != ELFCLASS64) { fclose(fp); return 0; }

    Elf64_Shdr sh; int doff=0, dsize=0, soff=0, ssize=0;
    for (int i = 0; i < (int)eh.e_shnum; i++) {
        fseek(fp, (long)(eh.e_shoff + i * eh.e_shentsize), SEEK_SET);
        if (fread(&sh, sizeof(sh), 1, fp) != 1) break;
        if (sh.sh_type == SHT_DYNSYM) { soff = (int)sh.sh_offset; ssize = (int)sh.sh_size; }
        else if (sh.sh_type == SHT_STRTAB && (int)sh.sh_size > dsize)
            { doff = (int)sh.sh_offset; dsize = (int)sh.sh_size; }
    }
    if (!soff || !doff) { fclose(fp); return 0; }

    char *strs = malloc((size_t)dsize);
    Elf64_Sym *syms = malloc((size_t)ssize);
    if (!strs || !syms) { free(strs); free(syms); fclose(fp); return 0; }
    fseek(fp, doff, SEEK_SET); fread(strs, (size_t)dsize, 1, fp);
    fseek(fp, soff, SEEK_SET); fread(syms, (size_t)ssize, 1, fp);
    fclose(fp);

    int n = 0, ns = ssize / (int)sizeof(Elf64_Sym);
    for (int i = 0; i < ns && n < max; i++) {
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC) continue;
        if (!syms[i].st_value) continue;
        const char *nm = strs + syms[i].st_name;
        if (!nm[0]) continue;
        strncpy(out[n].name, nm, 63); out[n].off = syms[i].st_value; out[n].sz = syms[i].st_size;
        n++;
    }
    free(strs); free(syms);
    return n;
}

/* ── 文件级持久数据 ─────────────────────────────────────────────── */

static uint64_t g_sym_lib_bases[32];
static char     g_sym_lib_paths[32][256];
static int      g_sym_nlibs = 0;
static int      g_sym_total = 0;

/* ── 按钮动作 ───────────────────────────────────────────────────── */

int btn_symresolve_action(TuiApp *app) {
    /* Step 1: 未attach → PID输入 */
    if (!app->debug || !app->debug->attached) {
        app->pid_target = 1; app->pid_input_active = 1; app->pid_input_pos = 0;
        memset(app->pid_input_buf, 0, 16);
        tui_show_popup(app, "SymResolve",
            "Attach to process to resolve runtime symbols.\n\n"
            "Enter target PID:\n\n  _\n\n[Enter]confirm [Esc]cancel");
        app->need_render = 1; return 0;
    }

    /* Step 2: 已attach → 清空中面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL; app->middle_data.count = 0;
        app->middle_data.capacity = 0; app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "=== Runtime Symbol Resolution ===");
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "PID: %d   RIP: 0x%llx",
        app->debug->pid, (unsigned long long)app->debug->regs.rip);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);

    /* 读 /proc/pid/maps → 找所有加载库 */
    char mpath[64]; snprintf(mpath, sizeof(mpath), "/proc/%d/maps", app->debug->pid);
    FILE *fp = fopen(mpath, "r");
    if (!fp) { fields_add(&app->middle_data, "(cannot read maps)", 0,0,DETAIL_NONE,-1); return 0; }

    typedef struct { uint64_t base; char path[256]; } lib_t;
    lib_t libs[32]; int nlibs = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && nlibs < 32) {
        uint64_t b; char p[5], f[256]="";
        if (sscanf(line, "%lx-%*lx %4s %*s %*s %*s %255s", &b, p, f) < 3) continue;
        if (p[2] != 'x' || !f[0] || f[0] != '/') continue;
        /* 去重 (同一个库可能有多个映射段) */
        int dup = 0;
        for (int i = 0; i < nlibs; i++) if (!strcmp(libs[i].path, f)) { dup=1; break; }
        if (!dup) { libs[nlibs].base = b; strncpy(libs[nlibs].path, f, 255); nlibs++; }
    }
    fclose(fp);

    /* 提取所有库的全部符号，与DB交叉对比，左对齐加序号 */
    int total = 0, seq = 0;
    for (int li = 0; li < nlibs; li++) {
        rsym_t syms[4096];
        int ns = elf_read_syms(libs[li].path, syms, 4096);
        if (ns == 0) continue;

        const char *lbl = libs[li].path;
        const char *sl = strrchr(lbl, '/'); if (sl) lbl = sl + 1;

        /* 库标题 */
        snprintf(buf, sizeof(buf), "── %s  base 0x%lx  %d symbols ──",
            lbl, (unsigned long)libs[li].base, ns);
        fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

        for (int si = 0; si < ns && total < 5000; si++) {
            uint64_t rt = libs[li].base + syms[si].off;
            seq++; total++;

            /* DB 交叉对比 */
            char db_tag[32] = "";
            if (app->adb) {
                sqlite3 *c2 = (sqlite3*)db_conn(app->adb);
                if (c2) {
                    sqlite3_stmt *st2 = NULL;
                    /* 查精确地址匹配 */
                    sqlite3_prepare_v2(c2,
                        "SELECT 'EXACT' FROM symbols WHERE address=?1 LIMIT 1",
                        -1, &st2, NULL);
                    if (st2) {
                        sqlite3_bind_int64(st2, 1, (sqlite3_int64)rt);
                        if (sqlite3_step(st2) == SQLITE_ROW) strcpy(db_tag, "[DB:match]");
                        else {
                            sqlite3_finalize(st2);
                            /* 查同名符号 */
                            sqlite3_prepare_v2(c2,
                                "SELECT address FROM symbols WHERE name=?1 LIMIT 1",
                                -1, &st2, NULL);
                            if (st2) {
                                sqlite3_bind_text(st2, 1, syms[si].name, -1, SQLITE_STATIC);
                                if (sqlite3_step(st2) == SQLITE_ROW)
                                    snprintf(db_tag, sizeof(db_tag), "[DB:0x%lx]",
                                        (unsigned long)sqlite3_column_int64(st2,0));
                                else strcpy(db_tag, "[DB:none]");
                            }
                        }
                        sqlite3_finalize(st2);
                    }
                }
            }

            snprintf(buf, sizeof(buf), "[%d] 0x%lx  %-32s  %s+0x%lx  %s",
                seq, (unsigned long)rt, syms[si].name,
                lbl, (unsigned long)syms[si].off,
                db_tag);
            fields_add(&app->middle_data, buf, 0, 1, DETAIL_NONE, (int)(rt & 0x7FFFFFFF));
        }
    }

    /* 寄存器标注 */
    fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "── Registers ──", 1, 0, DETAIL_NONE, -1);
    uint64_t regs[] = { app->debug->regs.rip, app->debug->regs.rdi,
        app->debug->regs.rsi, app->debug->regs.rdx, app->debug->regs.rax,
        app->debug->regs.rsp, app->debug->regs.rbp };
    const char *rnames[] = {"RIP","RDI","RSI","RDX","RAX","RSP","RBP"};
    for (int ri = 0; ri < 7; ri++) {
        uint64_t rv = regs[ri];
        char annot[128] = "";
        FILE *fp2 = fopen(mpath, "r");
        if (fp2) {
            char ml[512];
            while (fgets(ml, sizeof(ml), fp2)) {
                uint64_t s, e; char mp[5], mf[256]="";
                if (sscanf(ml, "%lx-%lx %4s %*s %*s %*s %255s", &s, &e, mp, mf) < 2) continue;
                if (rv < s || rv >= e) continue;
                if (mf[0] && strstr(mf,"libc")) snprintf(annot,sizeof(annot),"libc+0x%lx",(unsigned long)(rv-s));
                else if (mf[0] && strstr(mf,"ld-")) snprintf(annot,sizeof(annot),"ld+0x%lx",(unsigned long)(rv-s));
                else if (strstr(mf,"[stack]")) snprintf(annot,sizeof(annot),"stack+0x%lx",(unsigned long)(rv-s));
                else if (strstr(mf,"[heap]")) snprintf(annot,sizeof(annot),"heap+0x%lx",(unsigned long)(rv-s));
                else if (mf[0]) { const char *sl2=strrchr(mf,'/'); snprintf(annot,sizeof(annot),"%s+0x%lx",sl2?sl2+1:mf,(unsigned long)(rv-s)); }
                else if (mp[2]=='x') snprintf(annot,sizeof(annot),"code+0x%lx",(unsigned long)(rv-s));
                break;
            }
            fclose(fp2);
        }
        snprintf(buf, sizeof(buf), "%-4s  0x%llx  %s",
            rnames[ri], (unsigned long long)rv, annot[0] ? annot : "");
        fields_add(&app->middle_data, buf, 0, 1, DETAIL_NONE, (int)(rv & 0x7FFFFFFF));
    }

    /* 保存到文件级静态变量供 key handler 使用 */
    for (int i = 0; i < nlibs && i < 32; i++) {
        g_sym_lib_bases[i] = libs[i].base;
        strncpy(g_sym_lib_paths[i], libs[i].path, 255);
    }
    g_sym_nlibs = nlibs; g_sym_total = total;

    snprintf(buf, sizeof(buf), "── %d symbols / %d libs  [s]=search  [l]=leak→base  [e]=ASLR  [a]=all",
        total, nlibs);
    fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);
    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 0;
}

/* ── 交互处理器 ─────────────────────────────────────────────────── */

int btn_symresolve_handle_key(TuiApp *app, int key) {
    char buf[512];
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL; app->middle_data.count = 0;
        app->middle_data.capacity = 0; app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }

    switch (key) {
    case 's': case 'S': case '/':
        /* 搜索: 打开输入弹窗 */
        app->search_input_active = 1; app->search_input_pos = 0;
        memset(app->search_input_buf, 0, sizeof(app->search_input_buf));
        tui_show_popup(app, "SymResolve Search",
            "Filter symbols by name\n\n  _\n\n"
            "[Enter]filter  [Esc]cancel");
        app->need_render = 1;
        return 1;

    case 'l': case 'L':
        /* 泄露→基址 计算器 */
        fields_add(&app->middle_data, "=== Leak → Base Calculator ===", 0, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data,
            "Input: leaked_libc_addr func_name → libc_base → all_func_addrs", 1, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        for (int li = 0; li < g_sym_nlibs && li < 8; li++) {
            const char *lbl = g_sym_lib_paths[li];
            const char *sl = strrchr(lbl, '/'); if (sl) lbl = sl + 1;
            snprintf(buf, sizeof(buf), "%-20s  base 0x%lx  size %lu KB",
                lbl, (unsigned long)g_sym_lib_bases[li],
                (unsigned long)g_sym_lib_bases[li] / 1024);
            fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
        }
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data, "Usage: leak addr of known func → lookup offset → compute base",
            1, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data, "Example: leak printf=0x7f123409d200 → libc_base=leak-printf_offset",
            1, 0, DETAIL_NONE, -1);
        break;

    case 'e': case 'E':
        /* ASLR 熵评估 */
        fields_add(&app->middle_data, "=== ASLR Entropy ===", 0, 0, DETAIL_NONE, -1);
        for (int li = 0; li < g_sym_nlibs && li < 8; li++) {
            const char *lbl = g_sym_lib_paths[li];
            const char *sl = strrchr(lbl, '/'); if (sl) lbl = sl + 1;
            /* 计算基址的有效随机位数 (低12位页对齐=0) */
            uint64_t base = g_sym_lib_bases[li];
            int bits = 0; uint64_t v = base >> 12;
            while (v) { bits++; v >>= 1; }
            int max_bits = 47 - 12; /* x86-64 用户空间 47位 */
            double prob = 1.0 / (1ULL << bits);
            const char *verdict;
            if (bits <= 12) verdict = "BRUTEFORCE feasible (<4096 tries)";
            else if (bits <= 20) verdict = "possible with partial leak";
            else if (bits <= 28) verdict = "need info leak";
            else verdict = "strong ASLR";

            snprintf(buf, sizeof(buf), "%-20s  base 0x%lx  ~%d bits entropy  %s",
                lbl, (unsigned long)base, bits, verdict);
            fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);
        }
        fields_add(&app->middle_data, "", 0, 0, DETAIL_NONE, -1);
        fields_add(&app->middle_data, "Lower bits = easier bruteforce. Page-aligned (low 12 bits = 0).",
            1, 0, DETAIL_NONE, -1);
        break;

    case 'a': case 'A':
        /* 重新显示全部 — 触发 refresh */
        btn_symresolve_action(app);
        return 1;

    default: return 0;
    }

    if (app->middle_data.count > 0) app->active_panel = PANEL_MIDDLE;
    app->need_render = 1;
    return 1;
}
