# elf-tui 任务跟踪与接口定义

> 本文档由 Claude-N (总协调) 维护。每个 Claude 实例开发前先读此文档，
> 完成后更新状态。最后更新: 2026-06-05

## 项目文件结构速查

```
~/workspace/elf-tui/
├── docs/
│   ├── COORDINATION.md        ← 协作规范 (必读)
│   └── TASKS.md               ← 本文件 (任务跟踪)
├── include/
│   ├── elf_parser.h           ← 添加模块声明处
│   └── tui.h                  ← 弹窗接口: tui_show_popup()
├── lib/elf_parser/            ← 新模块放这里
│   ├── elf_parser.c           ★ 核心: Elf64_Ctx, fields_add(), 字符串表 API
│   ├── symtab.c               ★ 参考模板: 符号表解析
│   └── xxx.c                  ← 你的新文件
├── lib/tui/tui_left.c         ★ 注册入口: left_panel_handle_enter() switch
├── lib/tui/tui_input.c        ★ 弹窗触发: 见 Enter 处理中的 detail_index == -4
└── CMakeLists.txt             ★ 添加源文件: ELF_PARSER_SOURCES
```

## 当前模块状态

| # | 模块 | 文件 | 状态 | 负责人 | 备注 |
|---|------|------|------|--------|------|
| 1 | 反汇编 | `disasm.c` | 🔨 开发中 | Michael | capstone 依赖 |
| 2 | GOT/PLT | `got_plt.c` | ⬜ 待分配 | — | 解析 .got.plt + .plt |
| 3 | 加固检查 | `security.c` | ⬜ 待分配 | — | 弹窗展示报告 |
| 4 | Hex dump | `hexdump.c` | ⬜ 待分配 | — | 任意节 hex 视图 |
| 5 | 危险函数 | `danger.c` | ⬜ 待分配 | — | 导入函数匹配 |
| 6 | Gadget搜索 | `gadget.c` | ⬜ 待分配 | — | ROP gadget 扫描 |

状态: ⬜ 待分配 | 🔨 开发中 | ✅ 已完成 | 🔀 待合并

## 外部依赖 (需 apt install)

```
capstone-dev      (反汇编引擎, disasm.c 需要)
```

## 每个模块的检查清单

开发完成后自查:
- [ ] 实现了 `int parse_xxx(Elf64_Ctx*, int shdr_idx, PanelData*)`
- [ ] 用 `fields_add()` 填充输出, 符合缩进规范
- [ ] 声明已添加到 `include/elf_parser.h`
- [ ] 入口已添加到 `tui_left.c` 的对应节类型 switch
- [ ] 源文件已添加到 `CMakeLists.txt` 的 ELF_PARSER_SOURCES
- [ ] `cd build && cmake .. && make` 零警告编译通过
- [ ] `./elf-tui /bin/ls` 功能正常
