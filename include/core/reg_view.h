/*
 * reg_view.h — Register view renderer declarations
 */

#ifndef REG_VIEW_H
#define REG_VIEW_H

#include "elf_parser.h"

struct DebugState;

/* Render registers to PanelData (static ELF core dump / SHT_NOTE) */
int render_register_view(Elf64_Ctx *ctx, PanelData *pd);

/* Render registers from live ptrace DebugState to PanelData */
int render_live_registers(struct DebugState *ds, PanelData *pd);
/* Single-column compact view (调试模式 25% 中面板) */
int render_reg_single_col(struct DebugState *ds, PanelData *pd);

/* Popup-friendly: format registers as plain text (max 4096 chars).
 * Returns "" if no NT_PRSTATUS found. Safe for tui_show_popup(). */
const char *registers_popup_text(Elf64_Ctx *ctx);

/* Live process snapshot: ptrace ATTACH → GETREGS → DETACH.
 * Returns formatted register text. Safe for tui_show_popup(). */
const char *registers_snapshot_pid(int pid);

#endif /* REG_VIEW_H */
