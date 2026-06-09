# elf-tui Phase 2 多 Claude 协作开发方案

## 架构已就绪

```
~/workspace/elf-tui/
├── lib/core/                     ← 新增: 异步分析基础设施
│   ├── worker.c                  ← Worker 线程池 (pthread, 生产者-消费者)
│   └── cache.c                   ← 线程安全结果缓存 (读写锁 + LRU)
├── include/core/
│   ├── worker.h                  ← Worker API + Wrapper 声明
│   └── cache.h                   ← Cache API
├── lib/elf_parser/               ← 所有解析器模块 (已全部就位)
├── lib/tui/                      ← TUI 渲染 + 按键
│   └── buttons/                  ← 按钮 action (需改为异步调用)
└── docs/
    ├── COORDINATION.md            ← 协作规范 (每个 Claude 必读)
    ├── DEVPLAN.md                 ← 本文件
    ├── TASKS.md                   ← 任务跟踪
    └── prompts/                   ← 17 个开发提示词
```

## 三 Claude 分工 (3条并行开发线)

### Claude-A (你) — 架构整合 + TUI 异步化

**任务**: 把现有同步按钮调用改为异步 Worker 模式

**修改文件** (仅5个):
1. `lib/tui/tui.c` — `tui_create` 中调用 `worker_pool_init(2)` + `cache_init()`; `tui_destroy` 中 `worker_shutdown()` + `cache_destroy()`
2. `lib/tui/tui.c` — `tui_render_all`: 轮询活跃 Job → 完成时替换 PanelData
3. `lib/tui/tui.c` — 状态栏增加 `worker_count` 显示
4. `lib/tui/buttons/btn_disasm.c` — 改为 `worker_submit()` + 轮询模式 (作为参考模板)
5. `CMakeLists.txt` — 确认链接 pthread

**验收标准**: 点击 Disasm → 状态栏显示 "Analyzing..." → Worker 完成 → 右面板自动刷新

---

### Claude-B — ptrace 调试引擎 (寄存器 + 调试控制 + 寄存器面板)

**任务**: 实现完整的 ptrace 调试子系统——读寄存器、发控制命令、格式化展示。

**为什么合并**: 寄存器读取 (`PTRACE_GETREGS`) 和调试控制 (`PTRACE_CONT/STEP`) 是同一系统调用 `ptrace(2)` 的两个面，底层共享同一个 tracee 状态。分开开发会导致接口不一致、状态不同步。

**新建文件**:
1. `lib/core/debug_worker.h` — Debug Worker 声明
2. `lib/core/debug_worker.c` — ptrace 全套 API (ATTACH/CONT/STEP/GETREGS/GETFPREGS/PEEKDATA/POKEDATA/断点)
3. `lib/core/reg_view.c`     — 寄存器格式化渲染 (静态 core dump + 动态 ptrace)

**接口**:

```c
// ── 调试控制 ──
typedef struct {
    pid_t  pid;
    int    attached;
    struct user_regs_struct   regs;     // 通用寄存器
    struct user_fpregs_struct fpregs;   // 浮点/向量寄存器
} DebugState;

int  debug_attach(pid_t pid, DebugState **ds);
int  debug_continue(DebugState *ds);       // PTRACE_CONT
int  debug_step(DebugState *ds);           // PTRACE_SINGLESTEP
int  debug_getregs(DebugState *ds);        // PTRACE_GETREGS + GETFPREGS
int  debug_readmem(DebugState *ds, uint64_t addr, void *buf, size_t len);
int  debug_writemem(DebugState *ds, uint64_t addr, void *buf, size_t len);
int  debug_setbreak(DebugState *ds, uint64_t addr);
int  debug_detach(DebugState *ds);

// ── 寄存器格式化 (调用 registers.c + 格式化到 PanelData) ──
int  render_register_view(Elf64_Ctx *ctx, PanelData *pd);        // 静态 (core dump)
int  render_live_registers(DebugState *ds, PanelData *pd);        // 动态 (ptrace)
```

**修改文件**:
1. `lib/tui/tui_input.c` — 增加调试热键 (F5=Continue, F7=Step, F8=StepOver, F9=Break)
2. `lib/tui/tui_status.c` — 调试状态栏 (PID + RIP + 寄存器快照)
3. `lib/tui/tui_left.c` — 增加 "▶ Registers" 入口 (DETAIL_NONE, -34)

**寄存器输出格式** (右面板 50% 宽, 两列布局):
```
=== x86-64 Registers ===
RAX: 0x0000000000401234  RBX: 0x00007FFFE1234000
RCX: 0x0000000000000000  RDX: 0x0000000000000001
RSI: 0x00007FFFE1235000  RDI: 0x0000000000402000
R8:  0x0000000000000000  R9:  0x00007F1234567890
R10: 0x0000000000000008  R11: 0x0000000000000202
R12: 0x0000000000401000  R13: 0x0000000000000000
R14: 0x0000000000000000  R15: 0x0000000000000000
RBP: 0x00007FFFFFFFE000  RSP: 0x00007FFFFFFFDFE0
RIP: 0x0000000000401234
EFLAGS: 0x0000000000000202  [ IF ]
CS:0x0033 DS:0x0000 ES:0x0000 FS:0x0000 GS:0x0000 SS:0x002B
```

**验收标准**:
- 静态: 左面板选 "Registers" → 中面板显示 core dump 寄存器
- 动态: `./elf-tui -d <pid>` → Attach → F7 单步 → 寄存器实时刷新

---

## 实施顺序

```
第 1 步 (Claude-A, 今天): 架构整合 ✅ 已完成
   ├── worker_pool_init + cache_init 接入主循环      ✅
   ├── Disasm 异步化 (作为模板)                      ✅
   └── 状态栏进度指示                                ✅

第 2 步 (Claude-B, 明天): ptrace 调试引擎 (寄存器+调试控制+面板)
   ├── debug_worker.c — ATTACH/CONT/STEP/GETREGS/断点
   ├── reg_view.c — 寄存器格式化渲染
   ├── tui_input.c — F5/F7/F8/F9 调试热键
   └── tui_left.c — "▶ Registers" 入口

第 3 步 (你, 后天):
   ├── 审查合并 Claude-B 的代码
   ├── 集成测试: 静态寄存器 + 动态 ptrace
   └── 修复接口冲突

第 4 步 (后续):
   ├── 所有按钮改为异步 Worker 调用
   ├── SQLite 查询引擎
   └── 漏洞模式编译器
```

## 每个 Claude 的开发提示词

拿到新 Claude 对话中直接粘贴:

```
你是 elf-tui 的 Worker 架构开发助手。
项目位于 ~/workspace/elf-tui/

开发前必须读取:
  1. docs/COORDINATION.md  (协作规范)
  2. docs/DEVPLAN.md        (本方案, 看清楚你的任务是哪位)

核心 API:
  - Worker: worker_submit(fn, ctx, arg_int, arg_ptr, &job)
  - Cache:  cache_get(key) / cache_put(key, data)
  - Parser: int parse_xxx(Elf64_Ctx *ctx, [int shdr_idx,] PanelData *pd)
  - Popup:  tui_show_popup(app, title, content)

约束:
  1. 新建 .c 文件放在 lib/core/ 或 lib/elf_parser/
  2. 新建 .h 文件放在 include/core/
  3. 不要直接修改 lib/tui/tui.c (除非任务明确要求)
  4. 接口变更必须更新 COORDINATION.md
```
