/*
 * fuzz_engine.h — Fuzz 引擎接口 (elf-tui)
 *
 * 函数级 harnessed fuzzing: 在 ptrace 控制下,
 * 变异输入 → 设置寄存器 → 调用目标函数 → 检测 crash。
 *
 * 依赖: 无 (纯 C 声明, 实现依赖 debug_worker.h)
 */
#ifndef FUZZ_ENGINE_H
#define FUZZ_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ── Fuzz 配置 ───────────────────────────────────────────────── */

typedef enum {
    FUZZ_MUTATE_BITFLIP    = 1 << 0,
    FUZZ_MUTATE_BYTEFLIP   = 1 << 1,
    FUZZ_MUTATE_ARITHMETIC = 1 << 2,
    FUZZ_MUTATE_INTERESTING = 1 << 3,
    FUZZ_MUTATE_SPLICE     = 1 << 4,
    FUZZ_MUTATE_DICTIONARY = 1 << 5,
    FUZZ_MUTATE_HAVOC      = 1 << 6,
    FUZZ_MUTATE_ALL        = 0x7F,
} FuzzMutateStrategy;

typedef struct {
    uint64_t  target_addr;
    uint64_t  return_trap;
    uint64_t  input_addr;
    size_t    input_max_size;

    struct {
        int      is_input;
        int      is_length;
        uint64_t fixed_value;
    } args[6];

    int       strategy_mask;
    size_t    seed_input_size;
    uint8_t  *seed_input;
    int       max_iterations;
    int       timeout_ms;

    const char **dict_tokens;
    int         dict_count;
} FuzzConfig;

/* ── 崩溃记录 ────────────────────────────────────────────────── */

typedef struct {
    int      crash_id;
    uint64_t fault_addr;
    int      signal;
    uint64_t regs[27];
    uint8_t  input[4096];
    size_t   input_size;
    uint8_t  stack_snapshot[256];
    uint64_t rip_snapshot;
    char     crash_type[64];
    int      unique_hash;
} FuzzCrash;

/* ── 运行时统计 ──────────────────────────────────────────────── */

typedef struct {
    int      total_iterations;
    int      total_crashes;
    int      unique_crashes;
    int      execs_per_second;
    int      new_paths;            /* Phase 2: 新发现的执行路径数 */
    int      mut_bitflip_hits;
    int      mut_byteflip_hits;
    int      mut_arith_hits;
    int      mut_interesting_hits;
    int      mut_splice_hits;
    int      mut_dict_hits;
    int      mut_havoc_hits;
    int      basic_blocks_hit;
    int      basic_blocks_total;
} FuzzStats;

/* ── API ─────────────────────────────────────────────────────── */

void fuzz_config_init(FuzzConfig *cfg);
int  fuzz_config_validate(const FuzzConfig *cfg, char *error, size_t err_sz);

int  fuzz_run(FuzzConfig *cfg,
              void (*progress_cb)(const FuzzStats *stats, void *user),
              void (*crash_cb)(const FuzzCrash *crash, void *user),
              void *user);

void fuzz_request_stop(void);
int  fuzz_mutate(uint8_t *buf, size_t len, int strategy_mask);
void fuzz_mutate_set_dict(const char **tokens, int count);
void fuzz_analyze_crash(FuzzCrash *crash);
int  fuzz_crash_is_duplicate(const FuzzCrash *a, const FuzzCrash *b);

/* Phase 2: Coverage-Guided Fuzzing */
void fuzz_coverage_init(void);
int  fuzz_coverage_update(const uint64_t *edges, int count);
int  fuzz_coverage_is_interesting(const uint64_t *edges, int count);
int  fuzz_coverage_counts(int *total_edges, int *covered_edges);
void fuzz_coverage_free(void);

#endif /* FUZZ_ENGINE_H */
