# elf-tui 多 Claude 协作规范

## 核心原则

每个 Claude 实例只能:
1. 创建新的 `lib/elf_parser/xxx.c` 文件
2. 修改 `include/elf_parser.h` (仅添加声明)
3. 修改 `tui_left.c` 的 switch 分支 (仅添加 1-3 行)
4. 修改 `CMakeLists.txt` 的 ELF_PARSER_SOURCES (仅添加 1 行)

**禁止修改的文件 (需人工合并)**:
- `lib/tui/tui.c` (TUI 主控)
- `lib/tui/tui_input.c` (按键处理)
- `lib/tui/tui_left.c` (超过 3 行的修改)
- `include/tui.h` (弹窗接口已固定)

## 统一数据接口

### 所有新模块必须实现:

```c
// 解析节数据 → 填充 PanelData (由 TUI 中面板渲染)
int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);

// 可选: 弹出独立窗口 (如加固检查报告)
// 调用 tui_show_popup(app, "标题", "内容文本\n换行\n...");
```

### PanelData 填充规范

```c
// 标题行: 缩进 0
fields_add(pd, "=== XXX Section ===", 0, 0, DETAIL_NONE, -1);

// 字段行: 缩进 1, 可选中查看详情
fields_add(pd, "[%d] key = value", 1, 1, DETAIL_XXX, index);

// 子信息行: 缩进 2, 不可选 (纯展示)
fields_add(pd, "  extra info", 2, 0, DETAIL_NONE, -1);
```

### 弹窗用法 (如需弹窗而非面板展示)

```c
tui_show_popup(app,
    "Security Check Report",        // 标题 (最多 63 字符)
    "PIE:    Enabled\n"             // 内容 (最多 4095 字符, \n 换行)
    "RELRO:  Full\n"
    "Stack:  NX\n"
    "CET:    IBT+SHSTK\n"
);
// 弹窗在下次 tui_render_all 时自动显示
// 用户按 q 或 Esc 关闭, 自动回到面板模式
```

## 注册新模块 (3 步操作)

### 步骤 1: include/elf_parser.h — 添加声明

```c
/* 在文件末尾 #endif 之前添加 */
int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
```

### 步骤 2: tui_left.c — 添加入口

```c
/* 在 left_panel_handle_enter 的 switch 中添加 */
case SHT_XXX_TYPE:
    parse_xxx(ctx, idx, middle);
    break;
```

### 步骤 3: CMakeLists.txt — 添加源文件

```cmake
set(ELF_PARSER_SOURCES
    ...
    lib/elf_parser/xxx.c    # ← 新增这行
)
```

## 当前任务分配

| 模块 | 文件 | 状态 | 负责 |
|------|------|------|------|
| 反汇编视图 | `disasm.c` | 开发中 | Michael + Claude A |
| GOT/PLT 解析 | `got_plt.c` | 待分配 | — |
| 加固检查 | `security.c` | 待分配 | — |
| Hex dump | `hexdump.c` | 待分配 | — |
| 危险函数检测 | `danger.c` | 待分配 | — |
| Gadget 搜索 | `gadget.c` | 待分配 | — |

## 合并流程

1. 每个 Claude 完成任务后，输出最终的 `xxx.c` 文件
2. Michael 把文件放到 `lib/elf_parser/xxx.c`
3. 手动执行注册 3 步骤 (添加声明、入口、CMakeLists)
4. 编译验证: `cd build && cmake .. && make`
5. 功能测试: `./elf-tui /bin/ls`

## 给每个 Claude 的开发提示

```
你正在为 elf-tui 项目开发一个新模块。

项目位置: ~/workspace/elf-tui/
必须遵守的接口: ~/workspace/elf-tui/docs/COORDINATION.md

你的任务: [具体功能描述]

约束:
1. 只能创建一个新文件: lib/elf_parser/xxx.c
2. 实现: int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);
3. 使用 fields_add() 填充输出行
4. 参考现有模块的风格: lib/elf_parser/symtab.c 或 lib/elf_parser/note.c
5. 不要修改 lib/tui/ 下的任何文件
```
