# elf-tui Fuzz 功能模块设计方案

> 版本: v1.0  
> 日期: 2026-06-06  
> 状态: 设计方案（独立模块，纯新建文件）

---

## 1. 定位

在 elf-tui 调试子系统之上构建的**函数级 harnessed fuzzing** 模块。
不替代 AFL++/libFuzzer，而是填补它们之间的空白：

```
libFuzzer / AFL++     →  大规模覆盖引导, 需要源码编译
elf-tui fuzzer         →  快速单函数 fuzz, 黑盒二进制, 集成在 TUI 中
GDB + pwntools 脚本   →  灵活但需要手动准备
```

**核心场景**: 你在 elf-tui 中浏览反汇编，发现一个可疑函数 `parse_input(uint8_t *buf, size_t len)`。
你想快速给它喂 10000 个随机输入，看会不会 crash——不需要写 harness、不需要重新编译。

---

## 2. 工作原理

```
┌─ elf-tui (TUI) ───────────────────────────────────────┐
│                                                        │
│  [Fuzzer Config Popup]                                 │
│   Target Func: 0x401200                                │
│   Arg1 (rdi):  MUTATED_BUF   ← heap buffer             │
│   Arg2 (rsi):  buf_len                                  │
│   Iterations:  5000                                     │
│   [Start] [Stop] [Config]                               │
│                                                        │
│  ┌── Status ──────────────────────────────────────┐    │
│  │ Iter: 2341/5000  Crashes: 3  Unique: 2  exec/s:42│   │
│  └─────────────────────────────────────────────────┘    │
│                                                        │
│  [F12]Stop  [F11]Crash List  [q]Back                    │
└──────────────────────────────────────────────────────────┘
           │ ptrace
           ▼
┌─ Target Process ───────────────────────────────────────┐
│  fork() → child:                                      │
│    while (iterations) {                                │
│      buf = mutate(seed_buf);                           │
│      set_regs(rdi=buf, rsi=len);                       │
│      set RIP = target_func;                             │
│      set return_addr = INT3 (0xCC);                    │
│      PTRACE_CONT;                                      │
│      waitpid → SIGTRAP (正常返回) / SIGSEGV (crash);    │
│      if crash → save crash context;                    │
│      iteration++;                                      │
│    }                                                    │
└──────────────────────────────────────────────────────────┘
```

每次迭代:
1. 变异输入缓冲区
2. 在目标进程内存中写入输入
3. 设置寄存器 (rdi, rsi, ...) 指向输入
4. 在栈上放置一个 INT3 返回地址
5. PTRACE_CONT → 函数执行 → 正常返回时命中 INT3 → SIGTRAP
6. 收集结果 (crash or success)

---

## 3. 文件清单（纯新建，不动已有代码）

```
lib/core/
  fuzz_engine.c           ← 核心: 变异引擎 + 迭代循环 + crash 检测
  fuzz_mutate.c           ← 变异策略: bitflip/byteflip/arithmetic/splice/dictionary

include/core/
  fuzz_engine.h           ← FuzzConfig, FuzzStats, FuzzCrash + API 声明

lib/tui/buttons/
  btn_fuzzer.c            ← TUI 按钮 action: 弹窗配置 + 启动/停止 + 结果显示
```

---

## 4. 数据结构

### 4.1 `include/core/fuzz_engine.h`

```c
#ifndef FUZZ_ENGINE_H
#define FUZZ_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ── Fuzz 配置 ───────────────────────────────────────────────── */

typedef enum {
    FUZZ_MUTATE_BITFLIP    = 1 << 0,   /* 随机 bit 翻转 */
    FUZZ_MUTATE_BYTEFLIP   = 1 << 1,   /* 随机 byte 翻转 */
    FUZZ_MUTATE_ARITHMETIC = 1 << 2,   /* 加减小值 */
    FUZZ_MUTATE_INTERESTING = 1 << 3,  /* 注入 "interesting" 值 (0, -1, INT_MAX, ...) */
    FUZZ_MUTATE_SPLICE     = 1 << 4,   /* 拼接两个输入 */
    FUZZ_MUTATE_DICTIONARY = 1 << 5,   /* 字典替换 */
    FUZZ_MUTATE_HAVOC      = 1 << 6,   /* 组合多种策略随机切换 */
    FUZZ_MUTATE_ALL        = 0x7F,     /* 全部启用 */
} FuzzMutateStrategy;

typedef struct {
    /* 目标 */
    uint64_t  target_addr;       /* 被 fuzz 的函数地址 (RIP) */
    uint64_t  return_trap;       /* 返回地址 (栈顶放 0xCC 地址) */
    uint64_t  input_addr;        /* 输入缓冲区地址 (tracee 内存中) */
    size_t    input_max_size;    /* 输入缓冲区最大字节数 */

    /* 调用约定 (rdi, rsi, rdx, rcx, r8, r9) */
    struct {
        int      is_input;       /* 1 = 该参数是变异的输入指针 */
        int      is_length;      /* 1 = 该参数是输入长度 */
        uint64_t fixed_value;    /* 固定值 (当 is_input==0) */
    } args[6];

    /* 变异配置 */
    int       strategy_mask;     /* FuzzMutateStrategy 位掩码 */
    size_t    seed_input_size;   /* 种子输入大小 (0=随机生成) */
    uint8_t  *seed_input;        /* 种子输入 (NULL=随机) */
    int       max_iterations;    /* 最大迭代次数 (0=无限) */
    int       timeout_ms;        /* 单次迭代超时 (0=不限制) */

    /* 字典 */
    const char **dict_tokens;    /* 字典关键词列表 */
    int         dict_count;
} FuzzConfig;

/* ── 崩溃记录 ────────────────────────────────────────────────── */

typedef struct {
    int      crash_id;
    uint64_t fault_addr;         /* 崩溃地址 (RIP or fault addr) */
    int      signal;             /* SIGSEGV / SIGABRT / SIGILL / SIGBUS */
    uint64_t regs[27];           /* 崩溃时的寄存器快照 (与 user_regs_struct 顺序一致) */
    uint8_t  input[4096];        /* 触发崩溃的输入 (最大 4KB) */
    size_t   input_size;         /* 实际输入大小 */
    uint8_t  stack_snapshot[256];/* 栈顶 256 字节 */
    uint64_t rip_snapshot;       /* 崩溃时的 RIP */
    char     crash_type[64];     /* "SIGSEGV: write to 0x41414141" */
    int      unique_hash;        /* 去重用: 基于 fault_addr + signal 的 hash */
} FuzzCrash;

/* ── 运行时统计 ──────────────────────────────────────────────── */

typedef struct {
    int      total_iterations;
    int      total_crashes;
    int      unique_crashes;
    int      execs_per_second;

    /* 变异统计 */
    int      mut_bitflip_hits;    /* bitflip 导致新覆盖的次数 */
    int      mut_byteflip_hits;
    int      mut_arith_hits;
    int      mut_interesting_hits;
    int      mut_splice_hits;
    int      mut_dict_hits;
    int      mut_havoc_hits;

    /* 覆盖统计 (可选) */
    int      basic_blocks_hit;    /* 命中的基本块数 */
    int      basic_blocks_total;  /* 目标函数的基本块总数 */
} FuzzStats;

/* ── API ─────────────────────────────────────────────────────── */

/*
 * 初始化 fuzz 配置为默认值。
 * 调用者随后修改需要的字段。
 */
void fuzz_config_init(FuzzConfig *cfg);

/*
 * 验证配置完整性。返回 0 有效, -1 无效 (设置 error 字符串)。
 */
int  fuzz_config_validate(const FuzzConfig *cfg, char *error, size_t err_sz);

/*
 * 开始 fuzz 循环 (阻塞式, 在 Worker 线程中调用)。
 *
 * fork() 一个子进程 → 子进程设置 ptrace → 父进程进入变异-执行-检测循环。
 * 每轮迭代调用 progress_cb 报告进度 (可 NULL)。
 * 每检测到一个 crash 调用 crash_cb (可 NULL)。
 *
 * 返回 0 正常结束, -1 致命错误。
 */
int  fuzz_run(FuzzConfig *cfg,
              void (*progress_cb)(const FuzzStats *stats, void *user),
              void (*crash_cb)(const FuzzCrash *crash, void *user),
              void *user);

/*
 * 请求停止正在运行的 fuzz 循环 (信号安全, 从另一个线程调用)。
 */
void fuzz_request_stop(void);

/*
 * 变异一个输入缓冲区。
 * buf/len → 原地修改。strategy 指定使用哪种策略。
 * 返回 1 表示发生了变异, 0 表示未修改。
 */
int  fuzz_mutate(uint8_t *buf, size_t len, int strategy_mask);

/*
 * 分析一个 crash: 判断 crash 类型、可利用性初筛。
 * 填充 FuzzCrash 的 crash_type、unique_hash、fault_addr 字段。
 */
void fuzz_analyze_crash(FuzzCrash *crash);

/*
 * 崩溃去重: 比较两个 crash 是否属于同一根因 (signal + fault addr 匹配)。
 */
int  fuzz_crash_is_duplicate(const FuzzCrash *a, const FuzzCrash *b);

#endif /* FUZZ_ENGINE_H */
```

---

## 5. 变异引擎 (`fuzz_mutate.c`)

### 5.1 策略清单

```
FUZZ_MUTATE_BITFLIP:
  随机选择 1-8 个 bit → 翻转

FUZZ_MUTATE_BYTEFLIP:
  随机选择 1-16 个字节 → 替换为随机值

FUZZ_MUTATE_ARITHMETIC:
  随机选择 1-4 个 uint8/16/32/64 → 加上或减去小值 (0-35)

FUZZ_MUTATE_INTERESTING:
  在随机位置注入 "interesting" 值:
    0x00, 0x01, 0x7F, 0x80, 0xFF,
    0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF,
    0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
    0x0000000000000000, 0x0000000000000001,
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF

FUZZ_MUTATE_SPLICE:
  从历史输入队列中随机选取一个, 截取一段拼接到当前位置

FUZZ_MUTATE_DICTIONARY:
  用配置的字典中的 token 替换随机位置处的一段数据

FUZZ_MUTATE_HAVOC:
  组合多种策略, 每次随机选择:
    1. bitflip (1-4 bits)
    2. byteflip (1-8 bytes)
    3. arithmetic (1-2 values)
    4. interesting (1 value)
    5. delete chunk (1-32 bytes)
    6. insert chunk (1-32 bytes of random)
    7. clone chunk (copy 1-32 bytes to another position)
    8. overwrite chunk (random bytes)
  每个操作有独立概率, 可能执行 0-N 个操作
```

### 5.2 种子管理

```c
/* 内部种子队列 (fifo, max 32 entries) */
typedef struct {
    uint8_t *data;
    size_t   size;
    int      score;        /* 发现新覆盖 +10, 导致 crash +5 */
} FuzzSeed;
```

- 初始: 用户提供的种子（可选）
- 运行时: 每次发现新基本块覆盖 → 将该输入加入种子队列
- 选择: 按 score 加权随机选择

---

## 6. 执行循环 (`fuzz_engine.c`)

### 6.1 每次迭代的 ptrace 流程

```
1. 选择/生成/变异输入
   ├─ 有种子队列 → 按权重选种子 → mutate
   └─ 无种子    → 生成随机输入

2. 写入输入到 tracee 内存
   debug_writemem(ds, cfg->input_addr, input, input_size)

3. 设置调用约定
   rdi = cfg->args[0].is_input ? cfg->input_addr : cfg->args[0].fixed_value
   rsi = cfg->args[1].is_input ? input_size      : cfg->args[1].fixed_value
   rdx = cfg->args[2].fixed_value  (or input_addr for string params)
   ...
   rip = cfg->target_addr
   rsp = 在 tracee 中分配的小栈顶, 栈顶写入 return_trap (0xCC 地址)

4. PTRACE_SETREGS → PTRACE_CONT

5. waitpid() 等待停止
   ├─ SIGTRAP + rip == return_trap  → 正常返回 ✓
   ├─ SIGTRAP + rip != return_trap  → 可能断点, 检查
   ├─ SIGSEGV → crash! → 保存上下文
   ├─ SIGABRT → crash! (assert fail / abort)
   ├─ SIGILL  → crash! (非法指令)
   ├─ SIGBUS  → crash! (未对齐访问)
   └─ timeout → 可能死循环, 跳过

6. 更新统计 → 下一轮迭代
```

### 6.2 内存布局（tracee 进程内）

```
tracee 进程的内存布局 (由 fuzz_engine 分配):

  0x10000  ┌──────────────────┐
           │ 输入缓冲区        │  ← rdi (可变大小, max 64KB)
  0x20000  ├──────────────────┤
           │ 小栈 (4KB)       │  ← rsp
  0x21000  ├──────────────────┤
           │ 0xCC (INT3) × 8  │  ← return_trap
  0x21008  └──────────────────┘

  0x20000 被映射为 rw- (mmap in tracee, via syscall injection)
```

### 6.3 覆盖反馈（可选，Phase 2）

基本块计数覆盖: 在目标函数中每条指令后设置 INT3 → 统计有多少个不同的地址被命中。
- 这很慢（每指令一个往返），仅在 `FUZZ_COVERAGE_BASIC` 模式启用
- 或者用 `/proc/<pid>/maps` 只跟踪 RIP 采样（粗糙但快）

---

## 7. TUI 集成 (`btn_fuzzer.c`)

### 7.1 配置弹窗

```
┌──── Fuzzer Configuration ────────────────────────────┐
│                                                       │
│  Target Function:  0x401200                           │
│  Input Buffer:     0x10000  (allocated in tracee)     │
│  Max Input Size:   4096                               │
│                                                       │
│  Arg 0 (rdi):  [x] Input Buffer                       │
│  Arg 1 (rsi):  [x] Input Length                       │
│  Arg 2 (rdx):  [ ] Fixed Value: 0                     │
│  Arg 3 (rcx):  [ ] Fixed Value: 0                     │
│  Arg 4 (r8):   [ ] Fixed Value: 0                     │
│  Arg 5 (r9):   [ ] Fixed Value: 0                     │
│                                                       │
│  Mutations:   [x] Bitflip  [x] Byteflip               │
│               [x] Arithmetic  [x] Interesting          │
│               [x] Havoc  [ ] Splice  [ ] Dictionary    │
│                                                       │
│  Iterations:  5000                                    │
│  Seed File:   [none]                                  │
│                                                       │
│     [Start Fuzzing]     [Cancel]                      │
└───────────────────────────────────────────────────────┘
```

### 7.2 运行状态弹窗

```
┌──── Fuzzer Running ───────────────────────────────────┐
│                                                        │
│  Progress:    ████████░░░░░░░░░░  2341 / 5000          │
│  Crashes:     3 total, 2 unique                        │
│  Speed:       42 exec/s                                │
│                                                        │
│  Last Crash:  #3  SIGSEGV at 0x4012A0                  │
│               RIP=0x4012A0  RAX=0x41414141             │
│                                                        │
│  Coverage:    18/23 basic blocks (78%)                 │
│                                                        │
│  Mutation breakdown:                                   │
│    Bitflip:   512   Byteflip: 480                      │
│    Arith:     390   Havoc:    959                      │
│                                                        │
│     [Pause]    [Stop]    [Crash List]                  │
└───────────────────────────────────────────────────────┘
```

### 7.3 Crash 列表

```
┌──── Crash List ────────────────────────────────────────┐
│                                                        │
│  #1  SIGSEGV  0x4012A0  RIP=0x41414141  unique: A7F3  │
│       Input: 41 41 41 41 00 00 00 00 ...              │
│                                                        │
│  #2  SIGABRT  0x7F..    __assert_fail     unique: 9E12  │
│       Input: FF FF FF 7F 80 00 00 00 ...              │
│                                                        │
│  #3  SIGSEGV  0x4012A0  RIP=0x41414141  unique: A7F3  │
│       (duplicate of #1)                                │
│                                                        │
│  [Inspect selected crash]  [Export all]  [Close]       │
└───────────────────────────────────────────────────────┘
```

### 7.4 Crash 详情弹窗

```
┌──── Crash #1 Detail ───────────────────────────────────┐
│                                                        │
│  Signal:     SIGSEGV (11)                              │
│  Fault Addr: 0x4141414141414141  (user-controlled!)    │
│  Crash RIP:  0x4012A0   mov [rax], rbx                │
│                                                        │
│  Registers:                                            │
│    RAX  0x4141414141414141  ← input offset +8          │
│    RBX  0x0000000000000000                             │
│    RCX  0x0000000000000000                             │
│    RIP  0x00000000004012A0                             │
│    RSP  0x0000000000020FF0                             │
│                                                        │
│  Disasm @ crash:                                       │
│    0x40129E  mov    rbx, [rdi]                         │
│    0x4012A0  mov    [rax], rbx    ← CRASH              │
│                                                        │
│  Exploitability:                                       │
│    [*] RIP NOT controlled                              │
│    [*] RAX = user input (offset 8-15)                  │
│    [*] Arbitrary write primitive (@ RAX)               │
│                                                        │
│  Triggering input (hex):                               │
│    0000: 00 00 00 00 00 00 00 00   ........            │
│    0008: 41 41 41 41 41 41 41 41   AAAAAAAA            │
│                                                        │
│  [Export input]  [Set as seed]  [Close]                │
└───────────────────────────────────────────────────────┘
```

---

## 8. 按钮集成胶水（供手动合并用）

### 8.1 `include/tui_buttons.h` — 加枚举

```diff
     BTN_HISTORY     = -27,
+    BTN_FUZZER      = -28,   /* Fuzz 引擎 */
 };
```

### 8.2 `lib/tui/tui_left.c` — 左面板入口

在 "Security Audit" 折叠组中添加一行:

```diff
     add_button(pd, "ROPgadget",  BTN_ROPGADGET);
     add_button(pd, "AtkSurface", BTN_ATKSURFACE);
     add_button(pd, "SegPerm",    BTN_SEGPERM);
+    add_button(pd, "Fuzzer",     BTN_FUZZER);
```

### 8.3 `lib/tui/buttons/btn_dispatch.c` — 分发

```diff
     case BTN_HISTORY:     return btn_history_action(app);
+    case BTN_FUZZER:      return btn_fuzzer_action(app);
     default: return -1;
```

### 8.4 `CMakeLists.txt` — 构建

```diff
 set(CORE_SOURCES
     lib/core/worker.c
     lib/core/cache.c
     lib/core/debug_worker.c
     lib/core/reg_view.c
+    lib/core/fuzz_engine.c
+    lib/core/fuzz_mutate.c
 )

 set(TUI_SOURCES
     ...
+    lib/tui/buttons/btn_fuzzer.c
 )
```

---

## 9. 与现有模块的关系

```
                    ┌─────────────┐
                    │  btn_fuzzer │  ← TUI 按钮 + 配置弹窗
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │fuzz_engine│ │debug_    │ │reg_view  │
        │           │ │worker    │ │          │
        │  变异引擎  │ │ ptrace   │ │ crash    │
        │  执行循环  │ │ 控制     │ │ 寄存器   │
        │  crash检测 │ │          │ │ 格式化   │
        └─────┬─────┘ └────┬─────┘ └────┬─────┘
              │            │            │
              └────────────┼────────────┘
                           ▼
                    目标进程 (child)
```

`fuzz_engine` 是**最上层**，内部调用 `debug_worker` 的 ptrace API 控制 tracee，
`fuzz_mutate` 是独立的变异策略库（无状态，无依赖），
`reg_view` 用于格式化 crash 上下文。

---

## 10. 文件模板

### 10.1 `include/core/fuzz_engine.h` — 完整声明

见第 4 节。

### 10.2 `lib/core/fuzz_mutate.c` — 变异策略

```c
/*
 * fuzz_mutate.c — 输入变异策略库
 *
 * 每个策略函数: buf[0..len-1] 原地修改, 返回 1=已修改, 0=未修改。
 * 策略间零耦合, 可单独测试。
 *
 * 依赖: 无 (纯 C 标准库)
 */

#include "core/fuzz_engine.h"
#include <stdlib.h>
#include <string.h>

/* ── 内部随机 ── */

static inline int rand_range(int lo, int hi) {
    return lo + (rand() % (hi - lo + 1));
}

/* ── 策略实现 ── */

static int mut_bitflip(uint8_t *buf, size_t len) { ... }
static int mut_byteflip(uint8_t *buf, size_t len) { ... }
static int mut_arithmetic(uint8_t *buf, size_t len) { ... }
static int mut_interesting(uint8_t *buf, size_t len) { ... }
static int mut_splice(uint8_t *buf, size_t len) { ... }
static int mut_dictionary(uint8_t *buf, size_t len, const char **dict, int dcnt) { ... }
static int mut_havoc(uint8_t *buf, size_t len) { ... }

/* ── 公共入口 ── */

int fuzz_mutate(uint8_t *buf, size_t len, int strategy_mask) {
    int mutated = 0;

    /* 按权重随机选策略 */

    if (strategy_mask & FUZZ_MUTATE_HAVOC) {
        return mut_havoc(buf, len);   /* havoc 已包含多种组合 */
    }

    /* 单策略模式: 每种有一定概率执行 */
    if (strategy_mask & FUZZ_MUTATE_BITFLIP && rand() % 100 < 30)
        mutated |= mut_bitflip(buf, len);
    if (strategy_mask & FUZZ_MUTATE_BYTEFLIP && rand() % 100 < 25)
        mutated |= mut_byteflip(buf, len);
    if (strategy_mask & FUZZ_MUTATE_ARITHMETIC && rand() % 100 < 20)
        mutated |= mut_arithmetic(buf, len);
    if (strategy_mask & FUZZ_MUTATE_INTERESTING && rand() % 100 < 15)
        mutated |= mut_interesting(buf, len);

    /* splice 和 dictionary 需要额外参数, 在 fuzz_engine 中直接调用 */

    return mutated;
}
```

### 10.3 `lib/core/fuzz_engine.c` — 主循环骨架

```c
/*
 * fuzz_engine.c — Fuzz 执行引擎
 *
 * fork() → child 设置 ptrace → parent 进入变异-执行-检测循环。
 * 依赖: debug_worker.h (ptrace API)
 */

#define _GNU_SOURCE
#include "core/fuzz_engine.h"
#include "core/debug_worker.h"
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

/* ── 全局停止标志 ── */
static volatile sig_atomic_t stop_requested = 0;

void fuzz_request_stop(void) { stop_requested = 1; }

/* ── 内部 ── */

static void inject_mmap_in_child(uint64_t addr, size_t size) { ... }
static int  setup_tracee_memory(DebugState *ds, FuzzConfig *cfg) { ... }
static int  fuzz_single_iteration(DebugState *ds, FuzzConfig *cfg,
                                   uint8_t *input, size_t input_size) { ... }

/* ── 主循环 ── */

int fuzz_run(FuzzConfig *cfg,
             void (*progress_cb)(const FuzzStats*, void*),
             void (*crash_cb)(const FuzzCrash*, void*),
             void *user)
{
    /* 1. 验证配置 */
    char err[256];
    if (fuzz_config_validate(cfg, err, sizeof(err)) != 0) return -1;

    /* 2. fork 子进程 */
    pid_t child = fork();
    if (child < 0) return -1;

    if (child == 0) {
        /* 子进程: PTRACE_TRACEME → exec 自身 (自调试) */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        /* 永远不应该到这儿, 除非有人 PTRACE_DETACH */
        _exit(0);
    }

    /* 3. 父进程: 等待子进程停止 */
    waitpid(child, NULL, 0);

    /* 4. Attach + 分配 tracee 内存 + 设置栈 */
    DebugState *ds = NULL;
    debug_attach(child, &ds);
    setup_tracee_memory(ds, cfg);
    debug_getregs(ds);

    /* 5. 初始化种子队列 + 统计 */
    FuzzStats stats = {0};
    FuzzCrash crashes[128];
    int crash_count = 0;
    uint8_t *input_buf = malloc(cfg->input_max_size);
    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* 6. 主循环 */
    for (int iter = 0; iter < cfg->max_iterations && !stop_requested; iter++) {
        /* 生成/变异输入 */
        size_t input_size = mut_next_input(input_buf, cfg->input_max_size);

        /* 单次迭代 */
        int result = fuzz_single_iteration(ds, cfg, input_buf, input_size);

        /* 更新统计 */
        stats.total_iterations++;
        if (result == FUZZ_CRASH) {
            FuzzCrash *c = &crashes[crash_count++];
            /* 填充 crash 结构 */
            memcpy(c->input, input_buf, input_size);
            c->input_size = input_size;
            /* 检查去重 */
            int dup = 0;
            for (int j = 0; j < crash_count - 1; j++) {
                if (fuzz_crash_is_duplicate(c, &crashes[j])) { dup = 1; break; }
            }
            if (!dup) stats.unique_crashes++;
            stats.total_crashes++;
            if (crash_cb) crash_cb(c, user);
        }

        /* 计算速度 */
        clock_gettime(CLOCK_MONOTONIC, &t_now);
        double elapsed = (t_now.tv_sec - t_start.tv_sec) +
                         (t_now.tv_nsec - t_start.tv_nsec) / 1e9;
        if (elapsed > 0)
            stats.execs_per_second = (int)(stats.total_iterations / elapsed);

        /* 进度回调 */
        if (progress_cb && iter % 100 == 0) progress_cb(&stats, user);
    }

    /* 7. 清理 */
    debug_detach(ds);
    debug_free(ds);
    free(input_buf);
    return 0;
}
```

---

## 11. 与现有项目的集成胶水（汇总）

所有胶水代码, 每处 ≤ 3 行:

```
文件                        加什么
────────────────────────────────────────────────────────────
include/tui_buttons.h        BTN_FUZZER = -28
lib/tui/tui_left.c            add_button(pd, "Fuzzer", BTN_FUZZER)
lib/tui/buttons/btn_dispatch.c  case BTN_FUZZER: return btn_fuzzer_action(app);
CMakeLists.txt                +fuzz_engine.c  +fuzz_mutate.c  +btn_fuzzer.c
```

---

## 12. 验收标准

- [ ] `fuzz_mutate` 编译通过, 单元测试覆盖 6 种策略
- [ ] `fuzz_run` 对 `/bin/true` 空函数运行 100 次 → 0 crash
- [ ] `fuzz_run` 对已知 crash 函数 (如 `strcpy(buf, input)`) → 检测到 SIGSEGV
- [ ] Crash 去重: 相同输入产生 3 次 crash → reports 1 unique
- [ ] TUI 弹窗: 配置 → Start → 进度显示 → Stop → crash 列表
- [ ] Worker 集成: `fuzz_run` 在后台线程运行, TUI 主线程不阻塞

---

## 13. 已知限制

| 限制 | 说明 | 优先级 |
|------|------|--------|
| x86-64 only | 寄存器设置和调用约定均为 x86-64 | P2 |
| 单输入 buffer | 不支持多输入参数（如 `func(buf1, len1, buf2, len2)`） | P2 |
| 无覆盖率引导 | 纯盲 fuzz (随机+变异)，无 basic-block 覆盖率反馈 | P1 |
| 单线程 fuzz | 无 fork-server 模式, 每次迭代重新设置寄存器 | P2 |
| 无 ASAN/UBSAN | 不检测内存越界/未定义行为（依赖 SIGSEGV） | P3 |
| 字典大小有限 | 最多 128 个 token | P3 |
| 无持久化模式 | 每次迭代 PTRACE_SETREGS → CONT → wait → SETREGS → ... | P1 |
