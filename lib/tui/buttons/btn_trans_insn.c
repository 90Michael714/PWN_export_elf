/*
 * btn_trans_insn.c — InsnTranslate: DB 全量指令模式分析弹窗
 *
 * 查询 instructions 表全部指令, 按预定义模式分类统计,
 * 以弹窗展示分析结果, 不污染中/右面板。
 */
#include "tui.h"
#include "tui_buttons.h"
#include "core/db.h"
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>

extern AnalysisDB *g_active_db;

int btn_trans_insn_action(TuiApp *app)
{
    if (!app || !app->adb) {
        if (app) tui_show_popup(app, "InsnTranslate", "DB not available.\nImport ELF first.");
        app->need_render = 1; return 0;
    }
    g_active_db = app->adb;

    sqlite3 *c = (sqlite3 *)db_conn(app->adb);
    if (!c) { tui_show_popup(app, "InsnTranslate", "DB connection failed."); return 0; }

    /* 模式定义: { 匹配键, 标签, 计数 } */
    static const char *pats[][2] = {
        {"push rbp",              "函数序言: push rbp"},
        {"mov rbp, rsp",          "函数序言: mov rbp,rsp (建立栈帧)"},
        {"sub rsp,",              "分配栈空间 (sub rsp,N)"},
        {"mov rdi,",              "设置第1参数 rdi"},
        {"mov rsi,",              "设置第2参数 rsi"},
        {"mov rdx,",              "设置第3参数 rdx"},
        {"mov rcx,",              "设置第4参数 rcx"},
        {"mov r8,",               "设置第5参数 r8"},
        {"mov r9,",               "设置第6参数 r9"},
        {"call",                  "函数调用"},
        {"xor e",                 "寄存器清零 (xor reg,reg)"},
        {"lea rdi,[rip",          "加载字符串地址 → rdi (参数)"},
        {"cmp",                   "比较指令 (cmp)"},
        {"test",                  "测试指令 (test)"},
        {"leave",                 "函数尾声 leave"},
        {"ret",                   "函数返回 ret"},
        {"syscall",               "系统调用 (⚠ 提权/沙箱接口)"},
        {"imul",                  "⚠ 带符号乘法 (溢出风险)"},
        {"rep movs",              "内存块复制 rep movs"},
        {"rep stos",              "内存填充 rep stos"},
        {"endbr64",               "CET IBT 着陆点"},
        {"mov [rbp",              "写栈上局部变量"},
        {"mov rax,",              "准备返回值 rax"},
        {"nop",                   "NOP 填充"},
        {"jmp",                   "无条件跳转"},
        {"je",                    "条件跳转 ZF=1"},
        {"jne",                   "条件跳转 ZF=0"},
        {"jg",                    "条件跳转 > (有符号)"},
        {"jl",                    "条件跳转 < (有符号)"},
        {"pop rbp",               "函数尾声: pop rbp"},
        {NULL, NULL}
    };
    int np = 0; while (pats[np][0]) np++;

    int *hits = calloc((size_t)np, sizeof(int));
    if (!hits) { tui_show_popup(app, "InsnTranslate", "Memory error."); return 0; }

    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(c,
        "SELECT mnemonic, op_str FROM instructions ORDER BY address",
        -1, &st, NULL);
    if (!st) { free(hits); tui_show_popup(app, "InsnTranslate", "Query failed."); return 0; }

    int total = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *mn = (const char *)sqlite3_column_text(st, 0);
        const char *op = (const char *)sqlite3_column_text(st, 1);
        if (!mn) continue;
        total++;

        char key[96];
        snprintf(key, sizeof(key), "%s %s", mn, op ? op : "");

        for (int i = 0; i < np; i++) {
            if (strstr(key, pats[i][0])) { hits[i]++; break; }
        }
    }
    sqlite3_finalize(st);

    /* 弹窗内容 */
    char buf[4096];
    int pos = 0, remain = (int)sizeof(buf);
    pos += snprintf(buf + pos, (size_t)remain, "InsnTranslate — DB Pattern Analysis\n\n"
        "%d total instructions analyzed.\n\n", total);
    remain = (int)sizeof(buf) - pos; if (remain < 0) remain = 0;

    int shown = 0;
    for (int i = 0; i < np && remain > 64; i++) {
        if (hits[i] == 0) continue;
        int n = snprintf(buf + pos, (size_t)remain, "  %-44s %6d\n", pats[i][1], hits[i]);
        pos += n; remain -= n;
        shown++;
    }
    if (!shown && remain > 64) {
        int n = snprintf(buf + pos, (size_t)remain, "  (no patterns matched)\n");
        pos += n; remain -= n;
    }

    snprintf(buf + pos, (size_t)remain,
        "\n%d pattern types  |  %d instructions  |  DB lookup < 1 sec", shown, total);

    tui_show_popup(app, "Code Pattern Analysis", buf);
    free(hits);
    app->need_render = 1;
    return 0;
}
