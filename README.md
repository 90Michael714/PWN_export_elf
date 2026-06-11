
# elf-tui — ELF64 Binary Analysis TUI Platform

A terminal-based interactive ELF64 binary analysis tool for Linux security researchers,
reverse engineers, and CTF players. Combines static analysis, runtime debugging, and
exploit development in a single terminal interface.

<img width="1920" height="945" alt="ScreenShot_2026-06-11_142730_653" src="https://github.com/user-attachments/assets/ebcb88ac-8610-4c5d-8f87-25b0b69f6161" />




## Overview

elf-tui provides a three-panel Terminal User Interface (TUI) for exploring ELF64
binaries. It covers the full analysis workflow — from initial reconnaissance and
static disassembly through runtime debugging, vulnerability scanning, and exploit
gadget search — without leaving the terminal.

```
┌─ Navigation ──────┐┌─ Detail ───────────────┐┌─ Explanation ──────────────┐
│▶ ELF Header        ││                        ││                           │
│▶ Program Headers   ││                        ││                           │
│▶ Section Headers   ││                        ││                           │
│▶ Security Audit    ││                        ││                           │
|▶ Code Analysis
|▶ Debug             ││                        ││                           │
│▶ Decompile         ││                        ││                           │
│▶ Security Audit    ││                        ││                           │
│▶ Data Inspector    ││                        ││                           │
│▶ Tools             ││                        ││                           │
│▶ Exploit Tools     ││                        ││                           │
│▶ Tools             ││                        ││                           │
│                     ││                        ││                           │
└────────────────────┘└────────────────────────┘└───────────────────────────┘
  Left (20%)             Middle (30%)              Right (50%)
  Navigation tree        Data / disasm / report    Detail explanation
                         [Enter to expand]         [auto-shows context]
```

## Quick Start

### Prerequisites

- Linux x86-64 (native or WSL2)  ONLY x86-64 ELF
- GCC 13+ (C17)
- CMake 3.16+

### Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| [notcurses](https://github.com/dankamongmen/notcurses) | 3.0+ | Terminal UI rendering |
| [Capstone](https://www.capstone-engine.org/) | 4.0+ | x86-64 disassembly engine |
| [SQLite3](https://www.sqlite.org/) | 3.x | Persistent analysis database |

### Build && Run

```bash
./build/elf-tui /bin/ls          # Analyze any ELF64 binary
./build/elf-tui ~/my-binary      # Analyze your target
```

## Keyboard Reference

### Panel Navigation

| Key | Action |
|-----|--------|


| `PgUp` / `↑`  | Move cursor up |
| `PgDn` / `↓` | Move cursor down |
| Space / search
| 'l'  /  Heap Links
|'c'   /   Heap Chunks
| `Enter` | Expand / drill into selected item |
| `h` / `Backspace` | Go back / navigation history |
| `q` | Quit |

### Debug Hotkeys (when attached to process)

| Key | Action |
|-----|--------|
| `F5` | Continue execution |
| `F7` | Step into (single instruction) |
| `F8` | Step over |
| `F9` | Set breakpoint at current RIP |
| `F10` | Detach from process |

### Horizontal Scrolling

| Key | Action |
|-----|--------|
| `M-N` (Alt+N) | Scroll left |
| `M-P` (Alt+P) | Scroll right |

## Feature Guide

### 1. Static Analysis (Left Panel Navigation Tree)

The left panel organizes all analysis capabilities into collapsible groups:

#### ELF Header
View the complete ELF64 file header — magic bytes, class, endianness,
OS/ABI, type, machine, entry point, and program/section header offsets.

#### Program Headers (collapsible)
Expand to see each segment: type, virtual address, file/memory size,
and access permissions (R/W/X flags). Select any segment for details.

#### Section Headers (collapsible)
Full section table with name, type, flags, and address. Select any
section to drill into its contents.

#### Code Analysis
- **Disasm** — Capstone-powered x86-64 disassembly with Intel syntax.
  Supports syntax coloring (calls=green, jumps=yellow, ret=red, etc.)
  and CFG arrow annotations showing jump/call targets.
- **InsnTrans** — Instruction semantic translation: maps x86 instructions
  to natural language explanations (e.g., `mov rax, [rdi]` →
  "load 8 bytes from memory at RDI into RAX").
- **GOT/PLT** — Global Offset Table and Procedure Linkage Table analysis.
  Shows dynamically linked function resolution targets.
- **HexDump** — Hex dump view (similar to `xxd`) for any section.
- **FuncMap** — Function map: lists all detected functions with size,
  basic block count, and call relationships.
- **DataFlow** — Intra-procedural data flow analysis: use-def chains,
  liveness, and value range analysis per function.
- **DF Inter** — Inter-procedural data flow: cross-function taint
  and value propagation through call graphs.


#### Security Audit
- **Hardening** — Security mitigation check: PIE, RELRO, NX, Stack Canary,
  CET (IBT), RPATH/RUNPATH, symbol stripping status.
- **DangerFunc** — Dangerous function call detection (gets, strcpy, sprintf,
  system, etc.) via strings + disassembly cross-reference.
- **ROPgadget** — ROP gadget search in executable sections.
- **AtkSurface** — Attack surface summary: network I/O, file operations,
  process control, IPC endpoints.
- **SegPerm** — Segment permission conflict detection (RWX segments,
  overlapping mappings).

#### Data Inspector
- **MemLayout** — ASCII visualization of the process memory layout.
- **InitArray** — `.init_array` / `.fini_array` / `.preinit_array` entries.
- **StrXRef** — String cross-reference: which code references each string.
- **EHFrame** — `.eh_frame` DWARF CFI unwind table parsing.

#### Tools
- **Export** — Export current panel data (planned).
- **KeyHelp** — Keyboard shortcut reference (planned).
- **About** — Version and dependency info (planned).
- **History** — Recently opened files (planned).

### 2. Runtime Debugging (Debug Group)

Attach to a running process for live analysis:

1. Expand **Debug** → click **Attach**
2. Enter the target PID
3. elf-tui attaches via `ptrace(2)` and displays:
   - **Registers** — Full x86-64 register set with live values and
     symbol annotation (register → function/module name).
   - **Memory Regions** — `/proc/PID/maps` parsed into a browsable list.
     Press Enter on any region to hexdump its contents.
   - **Disassembly at RIP** — Real-time disassembly of the current
     instruction pointer with register value overlay.

**Additional debug views:**
- **VMMap** — Memory map browser.
- **SymResolve** — Resolve symbol names from runtime addresses.
- **Backtrace** — RBP-chain stack unwinding.
- **T-scope** (Telescope) — Pointer dereference chain inspection.
- **HW BP** — Hardware breakpoint management (DR0-DR7).
- **StackView** — Runtime stack inspection around RSP.
- **Heap** — Heap chunk analysis (ptmalloc/jemalloc).
- **GOT/PLT(Dyn)** — Runtime GOT/PLT resolution.
- **HeapTrace** — Heap event tracing (malloc/free/realloc interception).
- **PT Trace** — Intel Processor Trace / software single-step execution recording.

### 3. Exploit Development (Exploit Tools Group)

- **VulnScan** — Vulnerability candidate scanner: buffer overflows,
  format strings, integer overflows, use-after-free patterns.
- **OneGadget** — One-gadget RCE search (like the `one_gadget` tool).
- **SysCall** — x86-64 syscall table reference with calling conventions.
- **ExprEval** — Expression evaluator (register arithmetic, memory derefs).
- **BpCond** — Conditional breakpoints (`$rax == 0x1234`, `[$rdi] == 0`).
- **Taint** — Taint tracking engine (trace attacker-controlled data flow).
- **ROPchain** — ROP chain compiler (gadget sequencing).
- **Fuzzer** — In-process fuzzing engine with mutation strategies
  and crash triage.
- **BinDiff** — Binary diff comparison between two analysis databases.
- **Symbolic** — angr symbolic execution bridge.

### 4. Search

Press `Space` anywhere to open global search. Supports query templates:

| Query | Result |
|-------|--------|
| `callers:NAME` | Functions that call NAME |
| `callees:ADDR` | Functions called by address |
| `largest` | Largest functions by instruction count |
| `most_called` | Most frequently called functions |
| `dangerous` | All dangerous API call sites |
| `src->sink` | Functions containing both a source and a sink |
| keyword / address | Standard text search across symbols, strings, instructions |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      src/main.c                             │
│                  (entry point, arg parsing)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
┌─────────▼──────┐ ┌──────▼───────┐ ┌────▼───────────────────┐
│  lib/elf_parser│ │  lib/core/   │ │  lib/tui/              │
│  (46 modules)  │ │  (21 modules)│ │  (6 core + 36 buttons) │
│                │ │              │ │                        │
│  ELF64 parsing │ │  Debug engine│ │  notcurses rendering   │
│  Section walks │ │  DB (SQLite) │ │  3-panel layout        │
│  Disassembly   │ │  Fuzz engine │ │  Input handling        │
│  Symbol tables │ │  Heap tools  │ │  Popup system          │
│  Relocations   │ │  Trace/P.T.  │ │  Status bar            │
│  CFG / XRef    │ │  IR analysis │ │                        │
│  Security scan │ │  Worker pool │ │                        │
│  Data flow     │ │  Query bus   │ │                        │
│  Decompile     │ │  Symbolic    │ │                        │
└────────────────┘ └──────────────┘ └────────────────────────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │  External Libraries           │
          │  - notcurses (TUI rendering)  │
          │  - Capstone  (disassembly)    │
          │  - SQLite3   (analysis DB)    │
          │  - ptrace(2) (debugging)      │
          └───────────────────────────────┘
```

### Source Tree

```
elf-tui/
├── CMakeLists.txt              # Build configuration
├── README.md                   # This file
├── docs/
│   └── COORDINATION.md         # Multi-developer coordination rules
├── include/
│   ├── elf_parser.h            # ELF64 types, PanelData, parser API (600 lines)
│   ├── tui.h                   # TuiApp state, popup API
│   ├── tui_buttons.h           # Button ID enum (40 entries), action declarations
│   ├── tui_panels.h            # ActivePanel enum, panel init declarations
│   ├── tui_colors.h            # Color constants
│   ├── disasm.h                # Capstone wrapper API
│   ├── core/
│   │   ├── db.h                # AnalysisDB lifecycle + query API
│   │   ├── debug_worker.h      # Ptrace debug engine API
│   │   ├── pt_trace.h          # Trace backend abstraction (Intel PT / BTS / SW)
│   │   ├── worker.h            # Async worker thread pool
│   │   ├── query.h             # Symbol/address query bus
│   │   └── ...                 # Other core module headers
├── src/
│   └── main.c                  # Entry point: elf_open → tui_create → tui_run
├── lib/
│   ├── elf_parser/             # 46 static analysis modules
│   │   ├── elf_parser.c        # Core: elf_open, elf_close, mmap management
│   │   ├── disasm.c            # Capstone-based x86-64 Intel syntax disassembly
│   │   ├── symtab.c            # Symbol table (static + DB-backed)
│   │   ├── security.c          # Mitigation hardening check
│   │   ├── danger.c            # Dangerous function detection
│   │   ├── gadget.c            # ROP gadget search
│   │   ├── cfg_view.c          # Control Flow Graph rendering
│   │   ├── xref.c              # Cross-reference analysis
│   │   ├── decompile.c         # C pseudo-code decompilation
│   │   └── ...                 # 40 more parser modules
│   ├── core/                   # 21 backend engine modules
│   │   ├── db.c                # SQLite schema (35 tables), import, query API (3200 lines)
│   │   ├── debug_worker.c      # Ptrace: ATTACH → GETREGS → CONT/STEP → DETACH
│   │   ├── pt_trace.c          # Intel PT / BTS / Software trace recording
│   │   ├── fuzz_engine.c       # In-process mutation fuzzer
│   │   ├── heap_analyzer.c     # Heap layout analysis (ptmalloc/jemalloc)
│   │   ├── worker.c            # Thread pool for async analysis jobs
│   │   ├── cache.c             # Result cache for repeated queries
│   │   └── ...                 # 14 more core modules
│   └── tui/                    # 42 TUI rendering + button action modules
│       ├── tui.c               # Main render loop, layout, popups (1064 lines)
│       ├── tui_input.c         # Keyboard input dispatch (962 lines)
│       ├── tui_left.c          # Left panel navigation tree builder
│       ├── tui_middle.c        # Middle panel detail expansion
│       ├── tui_right.c         # Right panel explanation view
│       ├── tui_status.c        # Status bar rendering
│       └── buttons/            # 36 button action handlers
│           ├── btn_dispatch.c  # Button ID → action function router (40 cases)
│           ├── btn_common.c    # Registry-based button forwarding
│           ├── btn_disasm.c    # Disassembly view action
│           ├── btn_new_features.c  # Phase 2+ feature actions (PT Trace, Heap,
│           │                   #   DataFlow, Decompile, etc.)
│           └── ...             # 33 more button action files
```

### Data Flow

```
User Input (keyboard)
  │
  ▼
select() + notcurses_get  →  read_key()  →  tui_handle_input()
  │                                              │
  │                         ┌────────────────────┤
  │                         │                    │
  │                    Navigation            Button Action
  │                    (left panel)          (btn_dispatch)
  │                         │                    │
  │                         ▼                    ▼
  │                    parse_xxx()          btn_xxx_action()
  │                         │                    │
  │                         └────────┬───────────┘
  │                                  │
  │                                  ▼
  │                         PanelData (fields[])
  │                                  │
  │                                  ▼
  │                         tui_render_all()
  │                         - region_clear()
  │                         - region_border()
  │                         - region_lines()
  │                         - notcurses_render()
  │                                  │
  │                                  ▼
  └────────────────────────── Terminal Output
```

### Analysis Database

elf-tui maintains a persistent SQLite database at
`~/.cache/elf-tui/db/<file-hash>.db`. The database is created on first
open and reused on subsequent opens for instant loading.

**Key tables (35 total):**

| Table | Contents |
|-------|----------|
| `sections` | All section headers with addresses |
| `segments` | All program headers |
| `symbols` | Static symbol table entries |
| `instructions` | Disassembled instructions with operand decomposition |
| `functions` | Function boundaries, names, basic block counts |
| `basic_blocks` | Basic block start/end addresses |
| `cfg_edges` | Control flow graph edges (branch/fall-through/call) |
| `xrefs` | Cross-references (code→code, data→code) |
| `strings` | Extracted printable strings |
| `vuln_candidates` | Detected vulnerability patterns |
| `reg_snapshots` | Debug session register snapshots |
| `trace_sessions` | Execution trace recording sessions |
| `trace_blocks` | Traced basic blocks with execution counts |
| `heap_*` | Heap analysis data (sessions, chunks, links, anomalies) |
| `ir_stmts` | Intermediate representation statements |
| `taint_*` | Taint tracking sources and propagation |
| `crash_reports` | Fuzzer crash triage results |

DB caching means: first open = 2-30s import (background thread), subsequent opens = instant.

## Use Cases

### Reverse Engineering Workflow

```bash
# 1. Quick look at an unknown binary
./build/elf-tui ./suspicious_binary

# 2. Check security mitigations
#    Expand "Security Audit" → "Hardening"
#    See: PIE, RELRO, NX, Canary, CET status

# 3. Find entry point and main()
#    Expand "Code Analysis" → "Disasm"
#    Navigate .text section → find entry code

# 4. Trace dangerous calls
#    "Security Audit" → "DangerFunc"
#    Find all system(), execve(), strcpy() calls

# 5. Cross-reference strings to code
#    "Data Inspector" → "StrXRef"
#    See which functions reference interesting strings
```

### CTF Binary Exploitation

```bash
# 1. Load the challenge binary
./build/elf-tui ./challenge

# 2. Check hardening (is PIE off? No canary?)
#    Security Audit → Hardening

# 3. Find vulnerabilities
#    Exploit Tools → VulnScan
#    Detects buffer overflows, format strings, etc.

# 4. Find ROP gadgets
#    Security Audit → ROPgadget
#    Search for useful gadgets (pop rdi; ret, etc.)

# 5. Find one-gadgets
#    Exploit Tools → OneGadget
#    Search for execve("/bin/sh") call sites

# 6. Debug the exploit
#    Debug → Attach (enter PID)
#    Set breakpoints (F9), step through (F7/F8)
#    Watch registers change in real-time
```

### Fuzzing & Crash Analysis

```bash
# 1. Load target and find input parsing functions
#    Code Analysis → FuncMap → identify parser functions

# 2. Start fuzzing
#    Exploit Tools → Fuzzer
#    Generates mutated inputs, monitors for crashes

# 3. Analyze crashes
#    Crash reports auto-triaged: fault address, signal,
#    crash type, exploitability assessment

# 4. Trace execution path to crash
#    Debug → PT Trace
#    Record execution trace → decode → view timeline/hotspots
```

### Malware Analysis

```bash
# 1. Initial triage
./build/elf-tui ./malware_sample

# 2. Check for packing/obfuscation
#    Section Headers → look for unusual sections
#    Data Inspector → EHFrame → check unwind info

# 3. Find C2 / persistence mechanisms
#    Security Audit → AtkSurface
#    Network I/O functions, file operations, process creation

# 4. Trace data flow from network input
#    Exploit Tools → Taint
#    Track attacker-controlled data through the program

# 5. Binary diff against clean version
#    Exploit Tools → BinDiff
#    Compare patched vs. unpatched versions
```

## Development

### Adding a New Parser Module

1. Create `lib/elf_parser/xxx.c` implementing:
   ```c
   int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
   ```
2. Add declaration to `include/elf_parser.h`
3. Register in `CMakeLists.txt` under `ELF_PARSER_SOURCES`
4. Use `fields_add(pd, ...)` to populate output rows

### Adding a New Button

1. Add `BTN_XXX = -NN` to the button enum in `include/tui_buttons.h`
2. Implement `int btn_xxx_action(TuiApp *app)` in a new button file
3. Add `case BTN_XXX: return btn_xxx_action(app);` to `btn_dispatch.c`
4. Add button to the navigation tree in `tui_left.c`

### Build System

- Standard CMake workflow: `mkdir build && cd build && cmake .. && make`
- Debug: `-DCMAKE_BUILD_TYPE=Debug` adds `-g -O0 -Wall -Wextra`
- Release: `-DCMAKE_BUILD_TYPE=Release` adds `-O2 -march=native`
- All dependencies discovered via `find_library()`

## Dependencies

| Dependency | Ubuntu/Debian Install | Purpose |
|-----------|----------------------|---------|
| notcurses | `apt install libnotcurses-dev` | TUI rendering |
| Capstone | `apt install libcapstone-dev` | Disassembly |
| SQLite3 | `apt install libsqlite3-dev` | Analysis database |
| pthread | (system) | Threading |
| math | (system) | libm |

## License

MIT License

## Author

Michael — Linux ELF binary vulnerability researcher.
>>>>>>> 2bcf605 (Save local elf-tui files)
