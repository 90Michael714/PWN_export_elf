# elf-tui 调试引擎集成方案

> 版本: v2.0  
> 日期: 2026-06-06  
> 状态: 设计方案（待实现）

---

## 1. 目标

在 elf-tui 中集成一个完整的 ptrace 实时调试子系统，支持：

- 从 TUI 左面板 "▶ Registers" 入口输入目标 PID，attach 到运行中进程
- 中面板实时显示通用寄存器值（单列布局）
- 右面板实时显示以 RIP 为中心的反汇编代码（capstone 驱动）
- F5/F7/F8/F9/F10 调试热键：Continue / Step / StepOver / Breakpoint / Detach
- Detach 后完整恢复静态分析模式的三面板布局

---

## 2. 布局规格

### 静态模式（不变）

```
原来的三个窗口比例不变。
```

### 调试模式

```
┌─ Navigation (25%) ─┬─ Registers (25%) ─┬─ Disassembly (50%) ──────┐
│                     │                    │                          │
│ ▶ ELF Header        │ RAX  0x0000000042  │ 0x401000  push   rbp    │
│ ▶ Program Headers   │ RBX  0x7FFFFFFFE0  │ 0x401001  mov    rbp,rsp│
│ ▼ Section Headers   │ RCX  0x0000000000  │▶0x401004  mov    [rbp-8]│
│   ...               │ RDX  0x0000000000  │ 0x401008  cmp    rdi,0  │
│ ▶ Code Analysis     │ RSI  0x7F8A123...  │ 0x40100C  je     0x1030 │
│ ▶ Registers          │ RDI  0x0000402000  │ 0x40100E  call   foobar │
│ ▶ Security Audit    │ RIP  0x7F8A12[*]  │           ...           │
│ ...                  │ RSP  0x7FFFFFDFE0  │                          │
│                      │ EFLAGS [IF ZF]     │ [F7]Step [F8]Over [F5]C│
└──────────────────────┴───────────────────┴──────────────────────────┘
  PID:93100 RIP:0x401004                    [q]Quit
```

---

## 3. 数据结构变更

### 3.1 `include/tui.h` — TuiApp 新增字段

```c
#include "core/debug_worker.h"   /* DebugState 类型 */

typedef struct {
    /* ... 现有字段全部保留 ... */

    /* Ptrace 调试状态 (NULL = 静态模式) */
    struct DebugState *debug;

    /* PID 输入模式 (Registers 入口触发，拦截数字键) */
    int         pid_input_active;
    char        pid_input_buf[16];
    int         pid_input_pos;

    /* ... 其余字段不变 ... */
} TuiApp;
```

### 3.2 `include/core/debug_worker.h` — 调试引擎（已存在）

```c
typedef struct {
    pid_t                    pid;
    int                      attached;
    struct user_regs_struct  regs;
    struct user_fpregs_struct fpregs;
    int                      regs_valid;
    int                      fpregs_valid;
    Breakpoint               breakpoints[16];
    int                      bp_count;
    int                      last_signal;
    int                      last_status;
} DebugState;

int  debug_attach(pid_t pid, DebugState **ds_out);
int  debug_continue(DebugState *ds);
int  debug_step(DebugState *ds);
int  debug_step_over(DebugState *ds);
int  debug_getregs(DebugState *ds);
int  debug_readmem(DebugState *ds, uint64_t addr, void *buf, size_t len);
int  debug_writemem(DebugState *ds, uint64_t addr, const void *buf, size_t len);
int  debug_set_breakpoint(DebugState *ds, uint64_t addr);
int  debug_remove_breakpoint(DebugState *ds, uint64_t addr);
int  debug_detach(DebugState *ds);
void debug_free(DebugState *ds);
const char *debug_error(void);
```

### 3.3 `include/core/reg_view.h` — 寄存器视图声明（扩展）

```c
/* 核心 dump / SHT_NOTE 静态解析 → PanelData */
int  render_register_view(Elf64_Ctx *ctx, PanelData *pd);

/* Live ptrace → PanelData */
int  render_live_registers(struct DebugState *ds, PanelData *pd);

/* Live ptrace → PanelData (单列, 适配调试模式中面板 25% 宽) */
int  render_reg_single_col(struct DebugState *ds, PanelData *pd);

/* 弹窗文本 (core dump): 格式化寄存器为纯文本 */
const char *registers_popup_text(Elf64_Ctx *ctx);

/* 一次性快照: ATTACH → GETREGS → DETACH → 格式化文本 */
const char *registers_snapshot_pid(int pid);

/* 调试弹窗刷新: 读取最新 regs + 读取 RIP 处指令字节 → 格式化文本 */
const char *debug_popup_refresh(struct DebugState *ds);
```

---

## 4. 新增/修改函数总表

### 4.1 新建文件

| 文件 | 职责 |
|------|------|
| `include/core/debug_worker.h` | DebugState 声明 + 12 个 ptrace API |
| `include/core/reg_view.h` | 寄存器视图声明 |
| `include/core/process_launcher.h` | debug_launch() 声明（备用） |
| `lib/core/debug_worker.c` | ptrace 引擎实现 (353 行) |
| `lib/core/reg_view.c` | 寄存器渲染器 (480+ 行) |
| `lib/core/process_launcher.c` | fork+exec+PTRACE_TRACEME（备用） |

### 4.2 已有文件修改

| 文件 | 改动 | 行数 |
|------|------|------|
| `include/tui.h` | +`DebugState *debug`, +PID 输入字段, +函数声明 | +8 行 |
| `lib/tui/tui.c` | 布局比例 25/25/50, 中/右面板调试分支, 热键处理 | +30 行 |
| `lib/tui/tui_run()` | popup 循环转发 PID 输入 + 调试热键 | +15 行 |
| `lib/tui/tui_input.c` | Registers 入口逻辑 + PID 输入状态机 | +60 行 |
| `lib/tui/tui_left.c` | +`fields_add(pd, "▶ Registers", 0, 1, DETAIL_NONE, -34)` | +1 行 |
| `lib/tui/tui_status.c` | 调试模式时状态栏显示 PID+RIP | +5 行 |
| `lib/elf_parser/disasm.c` | 新增 `parse_disasm_at_addr()` | +40 行 |
| `CMakeLists.txt` | +`debug_worker.c`, `reg_view.c`, `process_launcher.c` | +3 行 |

---

## 5. 调试模式进入/退出流

### 5.1 进入调试模式

```
用户操作                          代码路径
─────────                        ────────
左面板选中 "▶ Registers"
  → Enter                        tui_input.c: idx == -34

检查 core dump?                   registers_popup_text(app->elf)
├─ YES → 弹出寄存器窗口            (已有的静态 core dump 路径)
└─ NO  → 进入 PID 输入模式          app->pid_input_active = 1

PID 输入模式:
  ┌─────────────────────────────────┐
  │ Enter target PID and press Enter:│
  │  PID: 93100_                    │
  │  [Enter 确认] [Esc 取消]         │
  └─────────────────────────────────┘
  数字键 → pid_input_buf 追加        tui_input.c: pid_input 状态机
  Enter   → debug_attach(pid, &ds)  pid_input_confirm()
            app->debug = ds
            关闭弹窗
            app->need_render = 1

进入调试渲染模式:
  tui_render_all()
    app->debug != NULL  →  中面板 = render_reg_single_col()
                           右面板 = parse_disasm_at_addr(rip)
                           状态栏 = "PID:93100 RIP:0x..."
```

### 5.2 退出调试模式（F10 Detach）

```
F10 按下:
  1. debug_detach(app->debug)     // PTRACE_DETACH, 恢复所有断点
  2. debug_free(app->debug)       // 释放内存
  3. app->debug = NULL            // 关键: 回到静态模式

  4. 清空中面板 (fields_free + middle_panel_init)
  5. 清空右面板 (fields_free + right_panel_init)
  6. app->need_render = 1

渲染:
  app->debug == NULL  →  恢复 25/35/40 布局
                         中面板 = Detail (静态)
                         右面板 = Explanation (静态)
                         状态栏 = "文件名 | ELF64 | ..."
```

---

## 6. 调试热键

| 键 | 功能 | 实现 |
|----|------|------|
| **F5** | Continue | `debug_continue(ds)` → `need_render=1` → 面板刷新 |
| **F7** | Step | `debug_step(ds)` → `need_render=1` → 面板刷新 |
| **F8** | Step Over | `debug_step_over(ds)` → `need_render=1` → 面板刷新 |
| **F9** | Breakpoint at RIP | `debug_set_breakpoint(ds, ds->regs.rip)` |
| **F10** | Detach | `debug_detach` → `debug_free` → `app->debug=NULL` → 恢复静态 |

热键在 `tui_run()` 主循环中处理，**优先于** `tui_handle_input()` 的正常导航键。

---

## 7. 渲染循环改造细节

### 7.1 `tui_render_all()` 中的面板分支

```c
// 中面板
if (app->debug && app->debug->attached) {
    render_reg_single_col(app->debug, &app->middle_data);
    region_border(&R_mid, "Registers", active==PANEL_MIDDLE);
} else {
    region_border(&R_mid, "Detail", active==PANEL_MIDDLE);
}
region_lines(&R_mid, &app->middle_data, active==PANEL_MIDDLE);

// 右面板
if (app->debug && app->debug->attached) {
    parse_disasm_at_addr(app->elf, app->debug->regs.rip,
                         &app->right_data, 30);
    region_border(&R_right, "Disassembly", active==PANEL_RIGHT);
} else {
    region_border(&R_right, "Explanation", active==PANEL_RIGHT);
}
region_lines(&R_right, &app->right_data, active==PANEL_RIGHT);
```

### 7.2 布局比例

```c
// 静态模式: 25/35/40
// 调试模式: 25/25/50
int col1 = tw * 25 / 100;
int col2 = app->debug ? tw * 50 / 100 : tw * 60 / 100;
```

### 7.3 状态栏

```c
if (app->debug && app->debug->attached) {
    snprintf(status, "...", "PID:%d RIP:0x%llx %s",
             app->debug->pid,
             (unsigned long long)app->debug->regs.rip,
             app->status_text);
} else {
    // 原始逻辑不变
}
```

---

## 8. `render_reg_single_col()` 输出规范

适配调试模式中面板 25% 宽（约 25-30 字符）：

```
=== x86-64 Registers ===
                            ← 空行
RAX  0x0000000000000042
RBX  0x00007FFFE1234000
RCX  0x0000000000000000
RDX  0x0000000000000001
RSI  0x00007FFFE1235000
RDI  0x0000000000402000
R8   0x0000000000000000
R9   0x00007F1234567890
R10  0x0000000000000008
R11  0x0000000000000202
R12  0x0000000000401000
R13  0x0000000000000000
R14  0x0000000000000000
R15  0x0000000000000000
RBP  0x00007FFFFFFFE000
                            ← 空行
RIP  0x00007F8A12340230 [*]
RSP  0x00007FFFFFFFDFE0
                            ← 空行
EFLAGS  0x00000202  [ IF ZF ]
                            ← 空行
CS 0x0033  DS 0x0000  ES 0x0000
FS 0x0000  GS 0x0000  SS 0x002B
                            ← 空行
[F7]Step [F8]Over
[F5]Cont [F9]BP
[F10]Detach
```

每行的 `fields_add(pd, ..., indent, selectable, ...)` 参数：
- 标题: indent=0, selectable=0
- 寄存器行: indent=1, selectable=0
- 热键提示: indent=1, selectable=0

---

## 9. `parse_disasm_at_addr()` 输出规范

适配右面板 50% 宽，capstone 反汇编，以指定地址为中心：

```
=== Disassembly @ 0x401000 ===
                            ← 空行
  0x401000  48 89 E5        mov    rbp, rsp
  0x401003  48 83 EC 20     sub    rsp, 0x20
▶ 0x401007  48 8B 45 F8     mov    rax, [rbp-8]    ← 当前 RIP
  0x40100B  48 85 C0        test   rax, rax
  0x40100E  74 20           je     0x401030
  0x401010  E8 AB CD EF FF  call   0x400EC0 <foobar>
  ...
```

- 当前 RIP 行: `▶` 前缀, indent=1, selectable=1
- 其他行: indent=1, selectable=1 (F9 设断点)
- 指令字节: 可选，仅在行宽足够时显示

---

## 10. 弹窗中的 PID 输入处理

弹窗激活时，`tui_run()` 进入独立子循环。当前实现只处理 q/Esc 关闭弹窗，**需要修改为转发键盘事件**：

```c
// tui_run() popup 分支中:
if (a->popup_active) {
    if (a->need_render) {
        tui_render_all(a);
        a->need_render = 0;
    }
    render_popup(a);
    notcurses_render(a->nc);

    uint32_t key = read_key(a->nc, &ni);
    if (key == 0) { nanosleep(...); continue; }

    /* PID 输入: 转发全部按键 */
    if (a->pid_input_active) {
        tui_handle_input(a, &ni);
        continue;
    }

    /* 调试热键 (弹窗可见时也可用) */
    if (a->debug && a->debug->attached) {
        // F5/F7/F8/F9 → 刷新弹窗内容
    }

    /* 关闭弹窗 */
    if (key=='q' || key=='Q' || key==NCKEY_ESC) {
        a->popup_active = 0;
        a->need_render = 1;
    }
}
```

---

## 11. PID 输入状态机

位于 `tui_input.c`，使用 `TuiApp` 中的 `pid_input_*` 字段：

```
状态转换:
  IDLE → (Registers 入口 Enter, 非 core dump) → PID_INPUT
  PID_INPUT:
    数字键 → 追加到 buf → 更新弹窗显示
    Enter  → atoi(buf) → debug_attach → 成功: 设 app->debug, IDLE
                                      → 失败: 弹窗报错, IDLE
    Esc    → 取消, 清空 buf, IDLE
    退格   → 删除末位 → 更新弹窗显示
    其他   → 忽略
```

---

## 12. 依赖库

| 库 | 用途 |
|----|------|
| `notcurses` / `notcurses-core` | TUI 渲染 |
| `capstone` | 反汇编引擎（已链接） |
| `pthread` | Worker 线程池（已链接） |
| `<sys/ptrace.h>` | ptrace 系统调用 |

---

## 13. 验证检查表

- [ ] 静态模式: 打开普通 ELF → 三面板正常显示 → 不崩溃
- [ ] Core dump: 打开 core dump → "▶ Registers" → 弹窗显示寄存器
- [ ] PID 输入: "▶ Registers" → 弹窗 → "Enter PID: _" → 输入数字可见
- [ ] PID 输入: Esc 取消 → 回到 ELF 浏览
- [ ] Attach: 输入有效 PID → 中面板=寄存器, 右面板=反汇编
- [ ] Attach: 输入无效 PID → 弹窗报错 "No such process" / "Permission denied"
- [ ] F7 Step: RIP 前进一条指令 → 反汇编 `▶` 标记移动到新位置 → 寄存器刷新
- [ ] F8 StepOver: call 指令 → 执行到下一行 (不进入 callee)
- [ ] F5 Continue: 程序继续运行 → 遇到 SIGTRAP (断点) → 停止
- [ ] F9 Breakpoint: 在 RIP 设置断点 → F5 → 到断点停止
- [ ] F10 Detach: 三面板恢复静态布局 → "文件名 | ELF64 | ..."
- [ ] 断点清理: Detach 后目标进程恢复正常运行 → 无残留 int3
- [ ] 权限错误: 状态栏显示友好提示 "run with ptrace_scope=0 or as root"

---

## 14. 已知限制

| 限制 | 说明 | 优先级 |
|------|------|--------|
| x86-64 专用 | 寄存器偏移和反汇编架构均硬编码 x86-64 | P2 |
| 用户态 ptrace | 不支持内核模块调试 | 不在范围 |
| 软断点 (int3) | 不支持硬件断点 (DR0-DR7) | P3 |
| 无内存窗口 | 不显示 hexdump/memory 面板 | P2 |
| 无符号解析 | RIP 不映射到函数名 (需 NM/符号表) | P1 |
| PTRACE_SEIZE 未用 | 使用 ATTACH (会发送 SIGSTOP) | P3 |

---

## 15. 相关文件索引

| 文件 | 说明 |
|------|------|
| `docs/COORDINATION.md` | 多 Claude 协作规范 |
| `docs/DEVPLAN.md` | Phase 2 开发方案 (Claude-B = ptrace 引擎) |
| `docs/DEBUGGER.md` | 本文件 |
| `include/core/debug_worker.h` | 调试引擎接口 |
| `include/core/reg_view.h` | 寄存器视图接口 |
| `lib/core/debug_worker.c` | 调试引擎实现 |
| `lib/core/reg_view.c` | 寄存器渲染器实现 |
| `lib/core/process_launcher.c` | 进程启动器（备用） |
| `lib/tui/tui.c` | TUI 主控 + 渲染循环 |
| `lib/tui/tui_input.c` | 键盘输入 + PID 状态机 |
| `lib/tui/tui_left.c` | 导航面板 |
| `lib/tui/tui_status.c` | 状态栏 |
| `src/main.c` | 入口点 |

---

## 16. 对标 GDB/pwndbg — 进阶功能路线图

### 16.0 elf-tui 的独特优势（GDB 做不到的）

| 能力 | elf-tui | GDB/pwndbg |
|------|---------|------------|
| 静态 + 动态 一体化 | ✅ 同一 TUI 内切换 | ❌ 需要两个工具 |
| ELF 结构浏览器 | ✅ Program Headers / Section Headers / 符号表 | ❌ 需要 readelf 或 objdump |
| 多面板 (4-5 个) 同时可见 | ✅ notcurses 原生 | ⚠️ pwndbg context 是单面板滚动 |
| Core dump 一键分析 | ✅ 打开文件即可 | ⚠️ 需要 `gdb binary core` |
| 离线 exploit 分析 | ✅ 不需要运行目标 | ❌ 必须启动进程 |

### 16.1 P0: 漏洞利用核心（对标 pwndbg context）

这些是 pwndbg 打开后最直观的几行信息，也是 exploit 开发 80% 时间在看的东西。

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **栈回溯 (backtrace)** | `bt` / `context stack` | 从 RBP 链回溯，每帧显示返回地址；可选：用 `.eh_frame` 做 unwinding |
| **栈内容 hexdump** | `telescope` / `stack` | 从 RSP 开始向下显示 N 个 qword，解引用指针，标注符号 (libc!__libc_start_main+0x80) |
| **寄存器 diff 标记** | `context regs` | 每次 step 后对比新旧 regs，变化的寄存器用红色/加粗/前缀 `[+]` 标记 |
| **内存映射 (vmmap)** | `vmmap` | 解析 `/proc/<pid>/maps`，标注权限 (rwx)，高亮 stack/heap/libc/ld 区域 |
| **RIP 附近反汇编** | `context code` | 已有 `parse_disasm_at_addr()`，需要加：符号标注、call 目标解析、跳转箭头 |

### 16.2 P0: 断点系统增强

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **条件断点** | `break *0x401000 if rax==0` | `DebugState` 增加条件表达式字符串；continue 循环中在断点命中时 eval 条件 |
| **临时断点** | `tbreak` | `debug_set_breakpoint` 加 `temporary` 标志，命中一次后自动移除 |
| **硬件断点** | `hbreak` / `watch` | 用 DR0-DR7 调试寄存器，`PTRACE_POKEUSER` 写入；执行/写入/读写三种模式 |
| **内存 watchpoint** | `watch *0x601020` | 硬件断点的变体：DR0=addr, DR7=RW 模式；每次 CONT 回来检查是否命中 |
| **断点列表管理** | `info break` | 反汇编面板中 `B` 标记所有活跃断点位置；左面板增加 Breakpoints 列表项 |

### 16.3 P1: 符号与类型系统

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **地址 → 符号解析** | `symbol-name 0x7f...` | 读 `/proc/<pid>/maps` 获取各模块基址 → 解析对应 ELF 的 `.symtab` / `.dynsym` → 匹配偏移 → 显示 `libc.so!__read+0x14` |
| **PLT/GOT 值解析** | `got` | 从 GOT 表读取实际解析后的地址，标注 libc 函数名 |
| **自动符号标注** | 所有地址自动带符号 | 反汇编/栈/寄存器中每个 64-bit 值都尝试匹配符号 |
| **结构体展开** | `p *ptr` / `ptype` | 需要 DWARF 调试信息解析 (`.debug_info` 段)；解析选中地址处的结构体字段 |
| **syscall 参数语义化** | — | 检测 `syscall` 指令 → 从 `orig_rax` 查 syscall 表 → 显示参数名 (如 `execve(path=$rdi, argv=$rsi, envp=$rdx)`) |

### 16.4 P1: 堆分析（对标 pwndbg heap）

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **堆块遍历** | `heap` / `vis_heap_chunks` | 从 `main_arena` (glibc) 开始遍历 bins → 显示每个 chunk 的 size/flag/prev_size |
| **tcache/fastbin 状态** | `bins` / `tcache` | 解析 glibc 的 `tcache_perthread_struct` 和 `fastbinsY[]` |
| **释放后使用检测** | `try_free` / `find_fake_fast` | 检查正在使用的 chunk 是否已被放入 free list |
| **堆布局可视化** | `vis` | 简单版：显示 heap 区域的 ASCII 布局 (`[ALLOC 0x40][FREE 0x30]...`) |

### 16.5 P1: ROP 与 Gadget 集成

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **Gadget 搜索** | `ropgadget` | 已有 `lib/elf_parser/gadget.c`；调试模式下搜索当前加载的所有 .text 段 |
| **ROP 链预览** | `ropper` | 在反汇编面板右侧显示"该地址出现的 gadget"列表 |
| **Gadget 约束检查** | — | 选中 gadget → 自动检查当前寄存器是否满足约束 (如 `rax==0`) |
| **One-gadget 匹配** | `one_gadget` | 对 libc 运行 one_gadget 工具，列出所有 gadget，标注哪些的约束当前已满足 |

### 16.6 P1: 数据流追踪

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **寄存器值来源追踪** | — | 标记"哪些内存写入影响了 rax"→ 上一条修改 rax 的指令是什么 → 它的源操作数来自哪个内存/寄存器 |
| **污点传播 (taint)** | `taint` (pwndbg 插件) | 标记用户输入 → 追踪其通过 `mov`/`add`/`cmp` 的传播路径 → 检测是否到达 `eip` |
| **调用约定可视化** | — | 当前函数调用：`rdi=arg1, rsi=arg2, rdx=arg3, rcx=arg4, r8=arg5, r9=arg6` → 标注参数类型 |

### 16.7 P2: 多线程调试

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **线程列表** | `info threads` | `PTRACE_ATTACH` 到每个 LWP；用 `/proc/<pid>/task/` 枚举线程 |
| **线程切换** | `thread <N>` | 选择当前 active 线程 → cont/step 只作用于该线程 (`PTRACE_LISTEN` 模式) |
| **所有线程寄存器快照** | `thread apply all bt` | core dump: 遍历所有 NT_PRSTATUS note；live: 逐线程 ptrace |

### 16.8 P2: 反汇编增强

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **交叉引用 (xref)** | `x/<N>i $rip` + 手动 | 标记"哪些地址跳转到这里"；已有 `lib/elf_parser/xref.c` |
| **函数边界** | `disassemble main` | 已有 `lib/elf_parser/func_boundary.c`；在反汇编中标记函数起始/结束 |
| **CFG 可视化** | `context code` 的行内箭头 | 简单实现：对 `jmp`/`je`/`call` 画 ASCII 箭头或目标行号 |
| **彩色语义** | `syntax-highlight` | 反汇编语法高亮：`mov`=蓝, `call`=绿, `jmp`=黄, `ret`=红, 立即数=白, 寄存器=青 |

### 16.9 P2: 信号与异常处理

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **信号拦截配置** | `handle SIGSEGV stop` | `debug_continue` 支持 `signal-to-forward` 参数；默认 SIGTRAP/SIGSEGV 停止 |
| **SIGSEGV 上下文** | crash 时自动显示 | 检测 `last_signal == SIGSEGV` → 显示 fault addr → 判断原因 (执行/写/读) |
| **Signal 注入** | `signal SIGINT` | `PTRACE_CONT(ds->pid, NULL, SIGINT)` — 向 tracee 发送信号 |

### 16.10 P2: 表达式与脚本

| 功能 | pwndbg 等价物 | 实现要点 |
|------|-------------|---------|
| **表达式求值** | `print $rax + 0x10` | 简单的 LL(1) parser: 寄存器名 → 值, `+` `-` `*` `/`, 立即数, 内存解引用 `*0x401000` |
| **Python 脚本** | `source script.py` | P3 - 嵌入 Lua 或 Python；初期可跳过 |
| **命令录制/回放** | `record` / `replay` | 记录每次 step/continue 的寄存器快照 → 时间线回放 → 静态分析离线重放 |

### 16.11 P3: 高级特性

| 功能 | 等价物 | 实现要点 |
|------|--------|---------|
| **反向执行** | `reverse-step` (rr) | 配合 `rr` (Record/Replay) 工具：用 rr replay 模式 + ptrace API |
| **远程调试** | `target remote :1234` | GDB RSP 协议的极简实现：TCP socket + 寄存器/内存读写包 |
| **内存搜索** | `search "AAAA"` | 在 tracee 内存中搜索字节模式/字符串/地址 |
| **差分调试** | — | 两个 core dump / 两次快照 的并排对比：相同地址的不同值高亮 |
| **CET/CFI 感知** | — | 检测 IBT (endbr64) / SHSTK 状态；shadow stack 展开 |
| **ASLR 熵估计** | `aslr` | 对比多次运行的基址差异 → 评估随机化质量 |

---

### 16.12 分期路线图

```
Phase 2 (当前)
  寄存器面板 + 反汇编面板 + F5/F7/F8 热键
  栈回溯 (backtrace)
  寄存器 diff 标记
  断点列表管理

Phase 3 (下一步)
  符号解析 (地址 → 函数名)
  条件断点 + 临时断点
  栈内容 hexdump (telescope)
  内存映射 (vmmap)
  反汇编语法高亮

Phase 4
  硬件断点 / watchpoint
  GOT/PLT 值解析
  syscall 参数语义化
  Gadget 搜索 + One-gadget 匹配
  堆分析基础 (chunk 遍历)

Phase 5
  表达式求值引擎
  多线程调试
  信号处理配置
  数据流追踪 (taint)
  结构体展开 (DWARF)

Phase 6
  远程调试 (GDB RSP)
  反向执行 (rr 集成)
  差分调试
  内存搜索
  脚本扩展
```

---

### 16.13 elf-tui 相对 GDB 的不可替代优势

| 维度 | elf-tui | GDB |
|------|---------|-----|
| **学习曲线** | TUI 键盘快捷键 (Tab/j/k/Enter) | 命令行 (需要记住上百个命令) |
| **全局视图** | 4 个面板同时可见、各自独立滚动 | `layout split` 但每个窗口很小 |
| **静态 → 动态无缝切换** | 同一个 TUI 内 | 需要 `file` + `attach` 两个命令 |
| **Core dump 离线分析** | 打开文件即可浏览所有节/段 | 需要二进制 + core + 正确版本 libc |
| **代码量** | ~5000 行 C + capstone + notcurses | ~200 万行 C++ |
| **部署** | 单二进制 (550KB) | 庞大依赖链 |
| **定制深度** | 源码在手, 完全可控 | 有限 (Python plugin API) |

---

## 17. 模块独立开发分析

以下将所有 P0-P3 功能按"是否可以纯新建文件、不改已有代码"分类。

前置条件: 以下 API 已在 Phase 2 就位:

```
debug_attach()         debug_step()        debug_getregs()
debug_continue()       debug_readmem()     debug_writemem()
debug_detach()         debug_set_breakpoint()
render_reg_single_col()  parse_disasm_at_addr()
register_popup_text()    registers_snapshot_pid()
TuiApp.debug            button dispatch (btn_dispatch)
```

---

### 17.1 纯独立模块（新建立 .c/.h 即可，不改任何已有代码）

这些模块唯一的"集成"是: **左面板加 1 行 `add_button(pd, "模块名", BTN_XXX)`** + **`tui_buttons.h` 加 1 个枚举值** + **`CMakeLists.txt` 加 1 行**。

核心逻辑 100% 在新文件中。

| 功能 | 新文件 | 对外仅依赖 | 说明 |
|------|--------|-----------|------|
| **栈回溯** | `lib/elf_parser/backtrace.c` | `DebugState.regs`, `debug_readmem()` | 从 RBP 链逐帧回溯，每帧显示返回地址 + 函数名(如果有符号) |
| **栈 telescope** | `lib/elf_parser/telescope.c` | `DebugState.regs.rsp`, `debug_readmem()` | 从 RSP 向下显示 N×8 bytes，解引用指针链 |
| **vmmap** | `lib/elf_parser/vmmap_live.c` | 无 (纯读 `/proc/<pid>/maps`) | 解析 maps 文件，标注 rwx 权限，高亮 stack/heap/libc |
| **符号解析引擎** | `lib/elf_parser/symbol_resolve.c` | `debug_readmem()`, `/proc/<pid>/maps`, ELF `.symtab` | 给定地址 → 返回 `libc.so!__read+0x14` 字符串 |
| **syscall 语义化** | `lib/elf_parser/syscall_ctx.c` | `DebugState.regs` | `orig_rax` → 系统调用名称 → 参数名 (rdi/rsi/rdx/r10/r8/r9) |
| **硬件断点** | `lib/core/hw_breakpoint.c` | `DebugState`, `PTRACE_POKEUSER` | DR0-DR7 操作: 设置执行/读写/写入断点 |
| **条件断点引擎** | `lib/core/bp_condition.c` | `DebugState`, `debug_readmem()` | 表达式求值: `rax==0x41414141`, `*rsp==0` |
| **堆分析器** | `lib/elf_parser/heap_analyzer.c` | `debug_readmem()`, glibc 内部结构 | chunk 遍历、tcache/fastbin、UAF 检测 |
| **One-gadget** | `lib/elf_parser/one_gadget.c` | libc `.text` 段, `DebugState.regs` | 加载 one_gadget offsets → 检查约束 → 标注哪些满足 |
| **DWARF 解析器** | `lib/elf_parser/dwarf.c` | ELF `.debug_info` `.debug_abbrev` `.debug_line` | 地址 → 源文件:行号, 类型 → 结构体字段 |
| **内存搜索** | `lib/elf_parser/mem_search.c` | `debug_readmem()`, `/proc/<pid>/maps` | 在 tracee 内存中搜索字节模式/字符串/地址列表 |
| **表达式求值** | `lib/core/expr_eval.c` | `DebugState.regs`, `debug_readmem()` | 解析 `$rax+0x10` / `*(0x601020)` / `$rip & 0xFFF` |
| **多线程管理** | `lib/core/thread_manager.c` | `PTRACE_ATTACH` 到每个 LWP | 线程枚举、切换、所有线程寄存器快照 |
| **信号处理器** | `lib/core/signal_handler.c` | `DebugState`, `PTRACE_CONT` 信号参数 | 拦截/转发指定信号, SIGSEGV 时显示 fault addr |
| **telescope 解引用链** | `lib/elf_parser/pointer_chain.c` | `debug_readmem()` | 指针链: `addr → 0x7f... → 0x7f... → "string"` |

**调用方式**: 全部通过 `btn_dispatch(app, BTN_XXX)` → 各自的 `btn_xxx_action(TuiApp *app)` 函数 → 弹窗或填充面板。

### 17.2 需要修改已有文件的模块

这些功能需要修改渲染逻辑、面板布局或核心引擎。

| 功能 | 需要修改的文件 | 原因 |
|------|--------------|------|
| **寄存器 diff 标记** | `reg_view.c` | 需要在渲染时比较新旧值，按变化/不变区分显示 |
| **反汇编内断点标记** | `disasm.c` | 渲染指令行时需检查该地址是否有活跃断点，有则加 `[B]` 前缀 |
| **反汇编语法高亮** | `disasm.c` | 渲染时按指令类型着不同颜色 (notcurses RGB) |
| **反汇编 CFG 箭头** | `disasm.c` | jmp/je/call 指令需要计算目标在视图中的行偏移画箭头 |
| **状态栏动态内容** | `tui_status.c` | 调试模式时需要显示 `PID RIP SymbolName` |
| **调试热键** | `tui_run()` in `tui.c` | F5/F7/F8/F9/F10 必须在主循环中处理 |
| **面板布局切换** | `tui.c` | 调试/静态模式切换需要调整 col1/col2 比例和面板标题 |
| **左面板新入口** | `tui_left.c` | `add_button()` 或 `fields_add()` 注册新菜单项 |
| **TuiApp 扩展** | `tui.h` | 新增 `DebugState *debug`, 符号缓存等字段 |

### 17.3 半独立模块（核心独立，仅需 1-2 行集成胶水）

这些是最常见的情况：核心逻辑 100% 在新文件中，只需要在已有文件的**特定位置**加 1-2 行分发代码。

| 功能 | 核心模块 (新文件) | 胶水代码 (已有文件, 各 1-2 行) |
|------|------------------|-------------------------------|
| 栈回溯 | `backtrace.c` + `backtrace.h` | `tui_buttons.h`: `BTN_BACKTRACE`; `tui_left.c`: `add_button("Backtrace", BTN_BACKTRACE)`; `btn_dispatch.c`: `case BTN_BACKTRACE: return btn_backtrace_action(app)` |
| vmmap | `vmmap_live.c` | 同上模式 |
| syscall | `syscall_ctx.c` | 在反汇编面板遇到 `syscall` 指令时，弹窗显示 syscall 语义 (需要 `disasm.c` 加 3 行检测) |
| 符号解析 | `symbol_resolve.c` | `reg_view.c` 渲染时调用 `symbol_resolve(addr)` 得到符号名 → 格式化到寄存器行 |
| 堆分析 | `heap_analyzer.c` | 按钮模式 (同 backtrace) |
| 表达式 | `expr_eval.c` + `expr_eval.h` | 条件断点和 watchpoint 使用；`debug_worker.c` 在 continue 循环中调用 `expr_eval(ds, condition)` 检查断点条件 |

### 17.4 推荐独立开发顺序

完全不需要动已有代码的 (可以现在就开始):

```
 1. expr_eval.c         表达式求值引擎 (零依赖)
 2. symbol_resolve.c    符号解析引擎 (依赖 /proc/<pid>/maps)
 3. vmmap_live.c        内存映射 (纯读 /proc)
 4. syscall_ctx.c       系统调用表 (纯查表)
 5. backtrace.c         栈回溯 (依赖 RBP + debug_readmem)
 6. telescope.c         栈解引用链
 7. hw_breakpoint.c     硬件断点 (依赖 PTRACE_POKEUSER)
 8. bp_condition.c      条件断点引擎 (依赖 expr_eval)
 9. heap_analyzer.c     堆分析器
10. one_gadget.c        One-gadget 匹配
11. thread_manager.c    多线程管理
12. dwarf.c             DWARF 调试信息解析 (最大, 最复杂)
```

每个模块的集成只靠 **3 行胶水代码**: 枚举值 + add_button + btn_action 函数。模块之间零耦合。

### 17.5 模块接口规范

所有独立模块的 action 函数遵循统一签名:

```c
// 放在 lib/tui/buttons/btn_xxx.c 中
int btn_backtrace_action(TuiApp *app) {
    if (!app->debug || !app->debug->attached) {
        tui_show_popup(app, "Error", "Not attached to any process.");
        return -1;
    }

    const char *result = backtrace_format(app->debug);
    if (result && result[0]) {
        tui_show_popup(app, "Stack Backtrace", result);
    }
    return 0;
}
```

所有解析模块的输出函数统一返回 `const char *` (弹窗) 或 `int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd)` (面板填充)。
