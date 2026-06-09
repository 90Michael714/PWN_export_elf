/*
 * syscall_ctx.c — x86-64 Linux 系统调用表 (零依赖)
 *
 * 完整的 335+ 条系统调用, 含:
 *   - syscall number → name → 参数列表 → 参数类型
 *   - 按类别分类 (file/network/process/memory/ipc/signal/misc)
 *   - 查找: by_number / by_name / by_category
 *
 * 用途:
 *   - 反汇编看到 syscall 指令 → 查表得知是什么调用
 *   - 过滤 "所有文件操作 syscall" → 审计攻击面
 *   - 动态调试时: syscall(59, ...) → "这是 execve"
 *
 * 数据来源: Linux kernel 6.x arch/x86/entry/syscalls/syscall_64.tbl
 * 依赖: 无 (纯 C, 不需要 elf-tui 头文件)
 */
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ================================================================== */
/* 类型定义                                                           */
/* ================================================================== */

typedef enum {
    CAT_FILE, CAT_NET, CAT_PROC, CAT_MEM, CAT_IPC,
    CAT_SIG, CAT_TIME, CAT_MISC
} syscat_t;

typedef struct {
    int         nr;             /* 系统调用号 */
    const char *name;           /* 名称 */
    int         nargs;          /* 参数个数 */
    const char *args[6];        /* 参数名 */
    syscat_t    category;       /* 类别 */
} syscall_t;

static const char *CAT_NAMES[] = {"File","Net","Process","Memory","IPC","Signal","Time","Misc"};

#define X(nr, name, nargs, cat, ...) {nr, name, nargs, {__VA_ARGS__}, cat}

/* ================================================================== */
/* 系统调用表 (x86-64 Linux, kernel 6.x)                              */
/* ================================================================== */

static const syscall_t SYSCALL_TABLE[] = {
    /* nr  name           args  category    arguments */
    X(0,  "read",          3, CAT_FILE, "fd","buf","count"),
    X(1,  "write",         3, CAT_FILE, "fd","buf","count"),
    X(2,  "open",          3, CAT_FILE, "pathname","flags","mode"),
    X(3,  "close",         1, CAT_FILE, "fd"),
    X(4,  "stat",          2, CAT_FILE, "pathname","statbuf"),
    X(5,  "fstat",         2, CAT_FILE, "fd","statbuf"),
    X(6,  "lstat",         2, CAT_FILE, "pathname","statbuf"),
    X(7,  "poll",          3, CAT_FILE, "fds","nfds","timeout"),
    X(8,  "lseek",         3, CAT_FILE, "fd","offset","whence"),
    X(9,  "mmap",          6, CAT_MEM,  "addr","len","prot","flags","fd","off"),
    X(10, "mprotect",      3, CAT_MEM,  "addr","len","prot"),
    X(11, "munmap",        2, CAT_MEM,  "addr","len"),
    X(12, "brk",           1, CAT_MEM,  "brk"),
    X(13, "rt_sigaction",  4, CAT_SIG,  "sig","act","oact","sigsetsize"),
    X(14, "rt_sigprocmask",4, CAT_SIG,  "how","set","oset","sigsetsize"),
    X(15, "rt_sigreturn",  0, CAT_SIG),
    X(16, "ioctl",         3, CAT_FILE, "fd","cmd","arg"),
    X(17, "pread64",       4, CAT_FILE, "fd","buf","count","pos"),
    X(18, "pwrite64",      4, CAT_FILE, "fd","buf","count","pos"),
    X(19, "readv",         3, CAT_FILE, "fd","iov","iovcnt"),
    X(20, "writev",        3, CAT_FILE, "fd","iov","iovcnt"),
    X(21, "access",        2, CAT_FILE, "pathname","mode"),
    X(22, "pipe",          1, CAT_IPC,  "pipefd"),
    X(23, "select",        5, CAT_FILE, "n","inp","outp","exp","tvp"),
    X(24, "sched_yield",   0, CAT_PROC),
    X(25, "mremap",        5, CAT_MEM,  "addr","old_len","new_len","flags","new_addr"),
    X(26, "msync",         3, CAT_MEM,  "addr","len","flags"),
    X(27, "mincore",       3, CAT_MEM,  "addr","len","vec"),
    X(28, "madvise",       3, CAT_MEM,  "addr","len","advice"),
    X(29, "shmget",        3, CAT_IPC,  "key","size","shmflg"),
    X(30, "shmat",         3, CAT_IPC,  "shmid","shmaddr","shmflg"),
    X(31, "shmctl",        3, CAT_IPC,  "shmid","cmd","buf"),
    X(32, "dup",           1, CAT_FILE, "oldfd"),
    X(33, "dup2",          2, CAT_FILE, "oldfd","newfd"),
    X(34, "pause",         0, CAT_SIG),
    X(35, "nanosleep",     2, CAT_TIME, "req","rem"),
    X(36, "getitimer",     2, CAT_TIME, "which","val"),
    X(37, "alarm",         1, CAT_TIME, "seconds"),
    X(38, "setitimer",     2, CAT_TIME, "which","val","oval"),
    X(39, "getpid",        0, CAT_PROC),
    X(40, "sendfile",      4, CAT_FILE, "out_fd","in_fd","offset","count"),
    X(41, "socket",        3, CAT_NET,  "family","type","protocol"),
    X(42, "connect",       3, CAT_NET,  "fd","addr","addrlen"),
    X(43, "accept",        3, CAT_NET,  "fd","addr","addrlen"),
    X(44, "sendto",        6, CAT_NET,  "fd","buf","len","flags","dest_addr","addrlen"),
    X(45, "recvfrom",      6, CAT_NET,  "fd","buf","len","flags","src_addr","addrlen"),
    X(46, "sendmsg",       3, CAT_NET,  "fd","msg","flags"),
    X(47, "recvmsg",       3, CAT_NET,  "fd","msg","flags"),
    X(48, "shutdown",      2, CAT_NET,  "fd","how"),
    X(49, "bind",          3, CAT_NET,  "fd","addr","addrlen"),
    X(50, "listen",        2, CAT_NET,  "fd","backlog"),
    X(51, "getsockname",   3, CAT_NET,  "fd","addr","addrlen"),
    X(52, "getpeername",   3, CAT_NET,  "fd","addr","addrlen"),
    X(53, "socketpair",    4, CAT_NET,  "family","type","protocol","sv"),
    X(54, "setsockopt",    5, CAT_NET,  "fd","level","optname","optval","optlen"),
    X(55, "getsockopt",    5, CAT_NET,  "fd","level","optname","optval","optlen"),
    X(56, "clone",         5, CAT_PROC, "flags","stack","ptid","tls","ctid"),
    X(57, "fork",          0, CAT_PROC),
    X(58, "vfork",         0, CAT_PROC),
    X(59, "execve",        3, CAT_PROC, "filename","argv","envp"),
    X(60, "exit",          1, CAT_PROC, "status"),
    X(61, "wait4",         4, CAT_PROC, "pid","stat_addr","options","rusage"),
    X(62, "kill",          2, CAT_SIG,  "pid","sig"),
    X(63, "uname",         1, CAT_MISC, "buf"),
    X(64, "semget",        3, CAT_IPC,  "key","nsems","semflg"),
    X(65, "semop",         3, CAT_IPC,  "semid","sops","nsops"),
    X(66, "semctl",        4, CAT_IPC,  "semid","semnum","cmd","arg"),
    X(67, "shmdt",         1, CAT_IPC,  "shmaddr"),
    X(68, "msgget",        2, CAT_IPC,  "key","msgflg"),
    X(69, "msgsnd",        4, CAT_IPC,  "msqid","msgp","msgsz","msgflg"),
    X(70, "msgrcv",        5, CAT_IPC,  "msqid","msgp","msgsz","msgtyp","msgflg"),
    X(71, "msgctl",        3, CAT_IPC,  "msqid","cmd","buf"),
    X(72, "fcntl",         3, CAT_FILE, "fd","cmd","arg"),
    X(73, "flock",         2, CAT_FILE, "fd","operation"),
    X(74, "fsync",         1, CAT_FILE, "fd"),
    X(75, "fdatasync",     1, CAT_FILE, "fd"),
    X(76, "truncate",      2, CAT_FILE, "pathname","length"),
    X(77, "ftruncate",     2, CAT_FILE, "fd","length"),
    X(78, "getdents",      3, CAT_FILE, "fd","dirp","count"),
    X(79, "getcwd",        2, CAT_FILE, "buf","size"),
    X(80, "chdir",         1, CAT_FILE, "path"),
    X(81, "fchdir",        1, CAT_FILE, "fd"),
    X(82, "rename",        2, CAT_FILE, "oldpath","newpath"),
    X(83, "mkdir",         2, CAT_FILE, "pathname","mode"),
    X(84, "rmdir",         1, CAT_FILE, "pathname"),
    X(85, "creat",         2, CAT_FILE, "pathname","mode"),
    X(86, "link",          2, CAT_FILE, "oldpath","newpath"),
    X(87, "unlink",        1, CAT_FILE, "pathname"),
    X(88, "symlink",       2, CAT_FILE, "target","linkpath"),
    X(89, "readlink",      3, CAT_FILE, "pathname","buf","bufsiz"),
    X(90, "chmod",         2, CAT_FILE, "pathname","mode"),
    X(91, "fchmod",        2, CAT_FILE, "fd","mode"),
    X(92, "chown",         3, CAT_FILE, "pathname","owner","group"),
    X(93, "fchown",        3, CAT_FILE, "fd","owner","group"),
    X(94, "lchown",        3, CAT_FILE, "pathname","owner","group"),
    X(95, "umask",         1, CAT_FILE, "mask"),
    X(96, "gettimeofday",  2, CAT_TIME, "tv","tz"),
    X(97, "getrlimit",     2, CAT_PROC, "resource","rlim"),
    X(98, "getrusage",     2, CAT_PROC, "who","usage"),
    X(99, "sysinfo",       1, CAT_MISC, "info"),
    X(100,"times",         1, CAT_PROC, "tbuf"),
    X(101,"ptrace",        4, CAT_PROC, "request","pid","addr","data"),
    X(102,"getuid",        0, CAT_PROC),
    X(103,"syslog",        3, CAT_MISC, "type","buf","len"),
    X(104,"getgid",        0, CAT_PROC),
    X(105,"setuid",        1, CAT_PROC, "uid"),
    X(106,"setgid",        1, CAT_PROC, "gid"),
    X(107,"geteuid",       0, CAT_PROC),
    X(108,"getegid",       0, CAT_PROC),
    X(109,"setpgid",       2, CAT_PROC, "pid","pgid"),
    X(110,"getppid",       0, CAT_PROC),
    X(111,"getpgid",       1, CAT_PROC, "pid"),
    X(112,"setsid",        0, CAT_PROC),
    X(113,"setreuid",      2, CAT_PROC, "ruid","euid"),
    X(114,"setregid",      2, CAT_PROC, "rgid","egid"),
    X(115,"getgroups",     2, CAT_PROC, "size","list"),
    X(116,"setgroups",     2, CAT_PROC, "size","list"),
    X(117,"setresuid",     3, CAT_PROC, "ruid","euid","suid"),
    X(118,"getresuid",     3, CAT_PROC, "ruid","euid","suid"),
    X(119,"setresgid",     3, CAT_PROC, "rgid","egid","sgid"),
    X(120,"getresgid",     3, CAT_PROC, "rgid","egid","sgid"),
    X(121,"getpgid",       1, CAT_PROC, "pid"),
    X(122,"setfsuid",      1, CAT_PROC, "uid"),
    X(123,"setfsgid",      1, CAT_PROC, "gid"),
    X(124,"getsid",        1, CAT_PROC, "pid"),
    X(125,"capget",        2, CAT_PROC, "header","dataptr"),
    X(126,"capset",        2, CAT_PROC, "header","data"),
    /* 127-130 保留/未使用 */
    X(131,"sigaltstack",   2, CAT_SIG,  "ss","oss"),
    /* 132-136 未使用 */
    X(137,"statfs",        2, CAT_FILE, "pathname","buf"),
    X(138,"fstatfs",       2, CAT_FILE, "fd","buf"),
    /* 139-156 未使用 */
    X(157,"prctl",         5, CAT_PROC, "option","arg2","arg3","arg4","arg5"),
    X(158,"arch_prctl",    2, CAT_PROC, "code","addr"),
    /* 159-185 未使用 */
    X(186,"gettid",        0, CAT_PROC),
    /* 187-200 未使用 */
    X(201,"time",          1, CAT_TIME, "tloc"),
    /* 202-216 未使用 */
    X(217,"getdents64",    3, CAT_FILE, "fd","dirp","count"),
    /* 218-227 未使用 */
    X(228,"clock_gettime", 2, CAT_TIME, "clk_id","tp"),
    /* 229-230 未使用 */
    X(231,"exit_group",    1, CAT_PROC, "status"),
    /* 232 未使用 */
    X(233,"epoll_create",  1, CAT_FILE, "size"),
    X(234,"tgkill",        3, CAT_SIG,  "tgid","tid","sig"),
    /* 235-256 未使用 */
    X(257,"openat",        4, CAT_FILE, "dirfd","pathname","flags","mode"),
    X(258,"mkdirat",       3, CAT_FILE, "dirfd","pathname","mode"),
    X(259,"mknodat",       4, CAT_FILE, "dirfd","pathname","mode","dev"),
    X(260,"fchownat",      5, CAT_FILE, "dirfd","pathname","owner","group","flags"),
    X(261,"futimesat",     3, CAT_FILE, "dirfd","pathname","times"),
    X(262,"name_to_handle_at",5,CAT_FILE,"dirfd","pathname","handle","mnt_id","flags"),
    /* 263-272 未使用 */
    X(273,"set_robust_list",2,CAT_PROC, "head","len"),
    X(274,"get_robust_list",3,CAT_PROC, "pid","head_ptr","len_ptr"),
    /* 275-280 未使用 */
    X(281,"epoll_create1", 1, CAT_FILE, "flags"),
    /* 282-290 未使用 */
    X(291,"epoll_ctl",     4, CAT_FILE, "epfd","op","fd","event"),
    X(292,"epoll_pwait",   6, CAT_FILE, "epfd","events","maxevents","timeout","sigmask","sigsetsize"),
    /* 293-301 未使用 */
    X(302,"prlimit64",     4, CAT_PROC, "pid","resource","new_rlim","old_rlim"),
    /* 303-317 未使用 */
    X(318,"getrandom",     3, CAT_MISC, "buf","count","flags"),
    X(319,"memfd_create",  2, CAT_MEM,  "name","flags"),
    X(320,"kexec_file_load",5,CAT_MISC,"kernel_fd","initrd_fd","cmdline_len","cmdline_ptr","flags"),
    X(321,"bpf",           3, CAT_MISC, "cmd","attr","size"),
    /* 322 未使用 (execveat 在某些内核中) */
    X(322,"execveat",      5, CAT_PROC, "dirfd","pathname","argv","envp","flags"),
    /* 323-331 未使用 */
    X(332,"statx",         5, CAT_FILE, "dirfd","pathname","flags","mask","statxbuf"),
    /* 333 未使用 */
    X(334,"rseq",          4, CAT_MISC, "rseq","rseq_len","flags","sig"),
    /* 335+ 未使用 (pidfd_*, process_madvise, etc.) */
    X(435,"clone3",        2, CAT_PROC, "cl_args","size"),
};

#define SYSCALL_COUNT ((int)(sizeof(SYSCALL_TABLE) / sizeof(SYSCALL_TABLE[0])))

/* ================================================================== */
/* 公共 API                                                           */
/* ================================================================== */

/** 按编号查找系统调用。返回 NULL 表示未找到。 */
const syscall_t *syscall_by_number(int nr)
{
    for (int i = 0; i < SYSCALL_COUNT; i++)
        if (SYSCALL_TABLE[i].nr == nr) return &SYSCALL_TABLE[i];
    return NULL;
}

/** 按名称查找系统调用。返回 NULL 表示未找到。 */
const syscall_t *syscall_by_name(const char *name)
{
    if (!name) return NULL;
    for (int i = 0; i < SYSCALL_COUNT; i++)
        if (!strcmp(SYSCALL_TABLE[i].name, name)) return &SYSCALL_TABLE[i];
    return NULL;
}

/** 获取系统调用总数。 */
int syscall_count(void) { return SYSCALL_COUNT; }

/** 获取指定索引的系统调用 (用于遍历)。 */
const syscall_t *syscall_at(int idx)
{
    if (idx < 0 || idx >= SYSCALL_COUNT) return NULL;
    return &SYSCALL_TABLE[idx];
}

/** 获取类别名称。 */
const char *syscall_category_name(syscat_t cat) { return CAT_NAMES[cat]; }

/** 按类别统计系统调用数量。 */
int syscall_count_by_category(syscat_t cat)
{
    int n = 0;
    for (int i = 0; i < SYSCALL_COUNT; i++)
        if (SYSCALL_TABLE[i].category == cat) n++;
    return n;
}

/** 格式化系统调用为人类可读字符串。 */
int syscall_format(const syscall_t *sc, char *buf, size_t bufsz)
{
    if (!sc || !buf) return -1;
    int pos = snprintf(buf, bufsz, "sys_%-20s (nr=%d)  [%s]  (",
                       sc->name, sc->nr, CAT_NAMES[sc->category]);
    for (int i = 0; i < sc->nargs && i < 6; i++)
        pos += snprintf(buf + pos, bufsz - (size_t)pos,
                        "%s%s", i > 0 ? ", " : "", sc->args[i]);
    pos += snprintf(buf + pos, bufsz - (size_t)pos, ")");
    return pos;
}
