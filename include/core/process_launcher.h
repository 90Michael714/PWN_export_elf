/*
 * process_launcher.h — 进程启动器 (fork + PTRACE_TRACEME + exec)
 *
 * 让 elf-tui 可以自己启动目标程序并立即进入调试模式,
 * 不需要外部 gdb/gcore 或手动 attach。
 */

#ifndef PROCESS_LAUNCHER_H
#define PROCESS_LAUNCHER_H

#include <sys/types.h>

struct DebugState;

/*
 * Fork + exec, 子进程在 exec 前停在 SIGSTOP。
 *
 * 调用者在获得 DebugState 后应:
 *   1. 可选: 设断点 (debug_set_breakpoint)
 *   2. debug_continue(ds)  →  子进程 exec  →  停在 _start 或断点
 *
 * 参数:
 *   path    可执行文件路径
 *   argv    参数列表 (以 NULL 结尾, argv[0] 通常 = path)
 *   envp    环境变量 (以 NULL 结尾, 可传 environ)
 *   ds_out  输出的调试状态指针
 *
 * 返回 0 成功, -1 失败。
 */
int debug_launch(const char *path, char *const argv[],
                 char *const envp[], struct DebugState **ds_out);

#endif /* PROCESS_LAUNCHER_H */
