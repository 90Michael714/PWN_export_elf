/*
 * symbolic_bridge.c — 符号执行桥接器 (subprocess → angr)
 *
 * 原理: 通过 popen() 调用外部 Python 脚本, JSON 协议通信。
 *   输入: ELF 文件路径 + 目标函数地址 + 探索选项
 *   输出: 路径约束, 输入示例, 可达性报告
 *
 * 依赖: Python3 + angr (可选 — 未安装时弹窗提示)
 * 接口: int symbolic_explore(const char *elf_path, uint64_t target_addr,
 *                            uint64_t avoid_addr, PanelData *pd);
 */

#include "elf_parser.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SYMBOLIC_SCRIPT  "scripts/angr_explore.py"
#define SYMBOLIC_TIMEOUT 60  /* 超时秒数 */

/* ── 路径安全检查: 拒绝含有 shell 元字符的路径 ──────────────────────── */

static int path_is_safe(const char *path)
{
    if (!path) return 0;
    /* 拒绝含有 shell 特殊字符的路径, 防止命令注入 */
    const char *dangerous = "'\"`$()&|;<>!\\";
    for (const char *p = path; *p; p++)
        if (strchr(dangerous, *p)) return 0;
    return 1;
}

/* ================================================================== */
/* 检查依赖                                                            */
/* ================================================================== */

static int symbolic_check_deps(void)
{
    /* 检查 Python3 和 angr 是否可用 */
    FILE *fp = popen("python3 -c 'import angr; print(angr.__version__)' 2>/dev/null", "r");
    if (!fp) return 0;
    char buf[64] = "";
    if (fgets(buf, sizeof(buf), fp)) {
        pclose(fp);
        return 1;
    }
    pclose(fp);
    return 0;
}

/* ================================================================== */
/* 调用 angr 脚本                                                      */
/* ================================================================== */

int symbolic_explore(const char *elf_path, uint64_t target_addr,
                     uint64_t avoid_addr, PanelData *pd)
{
    if (!elf_path || !pd) return -1;

    /* 安全检查: 拒绝含有 shell 元字符的路径 */
    if (!path_is_safe(elf_path)) {
        fields_add(pd, "(unsafe path — contains shell metacharacters)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    /* 检查脚本文件 */
    struct stat st;
    if (stat(SYMBOLIC_SCRIPT, &st) != 0) {
        fields_add(pd, "(angr script not found at " SYMBOLIC_SCRIPT ")", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    /* 检查 angr 是否安装 */
    if (!symbolic_check_deps()) {
        fields_add(pd, "(angr not installed — pip3 install angr)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    char buf[512];
    snprintf(buf, sizeof(buf), "=== Symbolic Exploration ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Target: %s", elf_path);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Goal:   0x%lx", (unsigned long)target_addr);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    if (avoid_addr) {
        snprintf(buf, sizeof(buf), "Avoid:  0x%lx", (unsigned long)avoid_addr);
        fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
    }
    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);

    /* 构建命令行 */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "python3 " SYMBOLIC_SCRIPT " '%s' 0x%lx 0x%lx %d 2>&1",
             elf_path, (unsigned long)target_addr,
             (unsigned long)avoid_addr, SYMBOLIC_TIMEOUT);

    fields_add(pd, "── Executing angr (may take a while) ──", 1, 0, DETAIL_NONE, -1);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fields_add(pd, "(failed to launch symbolic engine)", 1, 0, DETAIL_NONE, -1);
        return -1;
    }

    /* 以 JSON 行协议通信 */
    char line[1024];
    int n_output = 0;
    int found_paths = 0;
    int found_constraints = 0;

    while (fgets(line, sizeof(line), fp) && n_output < 200) {
        /* 去掉尾部换行 */
        size_t ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\n') line[ll - 1] = '\0';

        /* 解析 JSON 事件 (简化: 检查关键字前缀) */
        if (strstr(line, "PATH_FOUND")) {
            snprintf(buf, sizeof(buf), "Path: %s", line);
            fields_add(pd, buf, 1, 1, DETAIL_NONE, -1);
            found_paths++;
        } else if (strstr(line, "CONSTRAINT")) {
            snprintf(buf, sizeof(buf), "Constraint: %s", line);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
            found_constraints++;
        } else if (strstr(line, "INPUT")) {
            snprintf(buf, sizeof(buf), "Input: %s", line);
            fields_add(pd, buf, 2, 1, DETAIL_NONE, -1);
        } else if (strstr(line, "ERROR")) {
            snprintf(buf, sizeof(buf), "Error: %s", line);
            fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);
        } else if (strstr(line, "STATE") || strstr(line, "INFO")) {
            snprintf(buf, sizeof(buf), "%s", line);
            fields_add(pd, buf, 2, 0, DETAIL_NONE, -1);
        }
        n_output++;
    }

    int rc = pclose(fp);

    fields_add(pd, "", 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Result: %d paths, %d constraints (exit=%d)",
             found_paths, found_constraints, WEXITSTATUS(rc));
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    if (found_paths == 0) {
        fields_add(pd, "Target NOT reachable with symbolic execution"
                        " (may need more time or different approach)", 1, 0, DETAIL_NONE, -1);
    }

    return found_paths;
}

/* ================================================================== */
/* 简化版: 函数参数约束求取                                          */
/* ================================================================== */

int symbolic_find_input(const char *elf_path, uint64_t func_addr,
                        int n_args, PanelData *pd)
{
    if (!elf_path || !pd) return -1;

    if (!path_is_safe(elf_path)) {
        fields_add(pd, "(unsafe path)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    if (!symbolic_check_deps()) {
        fields_add(pd, "(angr not installed)", 0, 0, DETAIL_NONE, -1);
        return -1;
    }

    char buf[400];
    snprintf(buf, sizeof(buf), "=== Symbolic Input Discovery ===");
    fields_add(pd, buf, 0, 0, DETAIL_NONE, -1);
    snprintf(buf, sizeof(buf), "Function: 0x%lx (%d args)", (unsigned long)func_addr, n_args);
    fields_add(pd, buf, 1, 0, DETAIL_NONE, -1);

    /* 调用 angr 脚本探索输入空间 */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "python3 " SYMBOLIC_SCRIPT " '%s' 0x%lx 0 60 mode=input nargs=%d 2>&1",
             elf_path, (unsigned long)func_addr, n_args);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fields_add(pd, "(failed)", 1, 0, DETAIL_NONE, -1);
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* 去除尾部换行符 */
        size_t ll = strlen(line);
        if (ll > 0 && line[ll - 1] == '\n') line[ll - 1] = '\0';
        fields_add(pd, line, 1, 0, DETAIL_NONE, -1);
    }

    pclose(fp);
    return 0;
}
