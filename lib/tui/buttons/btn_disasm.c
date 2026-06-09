/*
 * btn_disasm.c — Disasm: 同步反汇编 (摘要→中面板, 代码→右面板)
 *
 * 不用 Worker 线程: 反汇编数据量巨大(70万行+), Worker 线程内的
 * 700K 次 realloc + 合并拷贝导致假死。改为同步直接调用, 即时反馈。
 * Worker 池留给 ptrace 等需要后台运行的功能使用。
 */

#include "tui.h"
#include "tui_buttons.h"

int btn_disasm_action(TuiApp *app)
{
    /* 清空中面板和右面板 */
    if (app->middle_data.fields) {
        fields_free(app->middle_data.fields, app->middle_data.count);
        app->middle_data.fields = NULL;
        app->middle_data.count = 0; app->middle_data.capacity = 0;
        app->middle_data.cursor = 0; app->middle_data.scroll = 0;
    }
    if (app->right_data.fields) {
        fields_free(app->right_data.fields, app->right_data.count);
        app->right_data.fields = NULL;
        app->right_data.count = 0; app->right_data.capacity = 0;
        app->right_data.cursor = 0; app->right_data.scroll = 0;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)app->elf->map;
    char buf[256];
    int total = 0;
    unsigned long total_bytes = 0;

    /* === 中面板: 反汇编摘要 === */
    fields_add(&app->middle_data, "=== Disassembly Summary ===", 0, 0, DETAIL_NONE, -1);
    fields_add(&app->middle_data, "[Enter]=select section  → 右面板反汇编", 0, 0, DETAIL_NONE, -1);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = elf_get_shdr(app->elf, i);
        if (!(sh->sh_flags & SHF_EXECINSTR) || sh->sh_size == 0) continue;

        const char *name = elf_section_name(app->elf, i);
        int load_idx = -1;
        for (int p = 0; p < ehdr->e_phnum; p++) {
            Elf64_Phdr *ph = elf_get_phdr(app->elf, p);
            if (ph->p_type == PT_LOAD &&
                sh->sh_addr >= ph->p_vaddr &&
                sh->sh_addr + sh->sh_size <= ph->p_vaddr + ph->p_memsz)
                { load_idx = p; break; }
        }
        char fb[8] = "";
        if (load_idx >= 0)
            elf_p_flags_str(elf_get_phdr(app->elf, load_idx)->p_flags, fb, 8);

        /* 行 1: 节名称 */
        snprintf(buf, sizeof(buf), "[%02d] %s", i, name ? name : "(unnamed)");
        fields_add(&app->middle_data, buf, 0, 1, DETAIL_SHDR, i);

        /* 行 2: 地址区间 */
        snprintf(buf, sizeof(buf),
                 "    0x%lx ─ 0x%lx",
                 (unsigned long)sh->sh_addr,
                 (unsigned long)(sh->sh_addr + sh->sh_size));
        fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

        /* 行 3: 大小 */
        snprintf(buf, sizeof(buf), "    %lu bytes", (unsigned long)sh->sh_size);
        fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

        /* 行 4: 属性 */
        if (load_idx >= 0)
            snprintf(buf, sizeof(buf), "    LOAD[%d]  %s", load_idx, fb);
        else
            snprintf(buf, sizeof(buf), "    (no LOAD segment)");
        fields_add(&app->middle_data, buf, 1, 0, DETAIL_NONE, -1);

        /* === 右面板: 实际反汇编 === */
        parse_disasm(app->elf, i, &app->right_data);
        total++;
        total_bytes += sh->sh_size;
    }

    snprintf(buf, sizeof(buf), "Total: %d sections, %lu bytes of code",
             total, total_bytes);
    fields_add(&app->middle_data, buf, 0, 0, DETAIL_NONE, -1);

    if (total > 0)
        app->active_panel = PANEL_RIGHT;
    else
        tui_show_popup(app, "Disasm", "No executable code sections found.");
    app->need_render = 1;
    return 0;
}
