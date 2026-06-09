# CLAUDE.md — elf-tui 项目指令

你是 Michael 的 elf-tui 开发助手。elf-tui 是一个 ELF64 TUI 解析器。

## 项目环境

- 语言: C17, 编译: CMake + GCC 13, TUI 库: notcurses 3.0.7
- 项目根: `~/workspace/elf-tui/`
- 构建: `cd build && cmake .. && make`
- 测试: `./build/elf-tui /bin/ls`

## 协作文档 (开发前必读)

在写任何代码之前，读取 `docs/COORDINATION.md` 并严格遵守:
- 只能创建 `lib/elf_parser/xxx.c` 新文件
- 实现统一接口: `int parse_xxx(Elf64_Ctx *ctx, int shdr_idx, PanelData *pd);`
- 使用 `fields_add()` 填充输出行 (声明在 `include/elf_parser.h`)
- 禁止修改 `lib/tui/` 下的文件 (除非 coordinator 指定)
- 注册步骤见 COORDINATION.md 底部

## 架构速查

```
左面板 (20%)  → 导航树 → Enter 选中
中面板 (30%)  → 解析字段展开 → Enter 查看详情
右面板 (50%)  → 字段详细说明
顶部状态栏    → 按键提示
弹窗          → tui_show_popup(app, "标题", "内容")
```

## 关键 API

```c
// 打开 ELF64 文件
Elf64_Ctx* elf_open(const char *filename);

// 获取节头 / 段头
Elf64_Shdr* elf_get_shdr(Elf64_Ctx *ctx, int index);
Elf64_Phdr* elf_get_phdr(Elf64_Ctx *ctx, int index);

// 获取节名 / 字符串
const char* elf_section_name(Elf64_Ctx *ctx, int index);
const char* elf_strtab_get(Elf64_Ctx *ctx, Elf64_Off stroff, Elf64_Word idx);

// 填充输出行
int fields_add(PanelData *pd, const char *fmt, ...);

// 弹出窗口
void tui_show_popup(TuiApp *app, const char *title, const char *content);

// 参考模板: lib/elf_parser/symtab.c  (完整的模块示例)
```

## 按键映射

PageUp/↑: 上移 | PageDown/↓: 下移 | ←/→: 切换面板 | Enter: 展开 | h: 返回 | q: 退出
