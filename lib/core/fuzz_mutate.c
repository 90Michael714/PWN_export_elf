/*
 * fuzz_mutate.c — 输入变异策略库 (零依赖, 纯 C)
 *
 * 6 种策略: bitflip / byteflip / arithmetic / interesting / splice / havoc
 * 每种策略返回 1=已修改, 0=未修改。策略间零耦合。
 */
#include "core/fuzz_engine.h"
#include <stdlib.h>
#include <string.h>

/* ── 内部随机 ── */
static inline int rr(int lo, int hi) { return lo + (rand() % (hi - lo + 1)); }

/* ── 种子队列 (内部状态) ── */
#define SEED_QUEUE_MAX 32
static uint8_t *seed_data[SEED_QUEUE_MAX];
static size_t   seed_sizes[SEED_QUEUE_MAX];
static int      seed_scores[SEED_QUEUE_MAX];
static int      seed_count = 0;

static const char **g_dict = NULL;
static int          g_dict_count = 0;

void fuzz_mutate_set_dict(const char **tokens, int count) {
    g_dict = tokens; g_dict_count = count;
}

static void seed_add(const uint8_t *buf, size_t len, int score) {
    if (seed_count >= SEED_QUEUE_MAX) {
        int worst = 0;
        for (int i = 1; i < SEED_QUEUE_MAX; i++)
            if (seed_scores[i] < seed_scores[worst]) worst = i;
        free(seed_data[worst]);
        seed_data[worst] = malloc(len);
        if (!seed_data[worst]) return;
        memcpy(seed_data[worst], buf, len);
        seed_sizes[worst] = len;
        seed_scores[worst] = score;
        return;
    }
    seed_data[seed_count] = malloc(len);
    if (!seed_data[seed_count]) return;
    memcpy(seed_data[seed_count], buf, len);
    seed_sizes[seed_count] = len;
    seed_scores[seed_count] = score;
    seed_count++;
}

static int seed_pick(uint8_t *out, size_t maxlen) {
    if (seed_count == 0) return 0;
    int total = 0;
    for (int i = 0; i < seed_count; i++) total += seed_scores[i] + 1;
    int pick = rr(0, total - 1);
    int acc = 0;
    for (int i = 0; i < seed_count; i++) {
        acc += seed_scores[i] + 1;
        if (pick < acc) {
            size_t cp = seed_sizes[i] < maxlen ? seed_sizes[i] : maxlen;
            memcpy(out, seed_data[i], cp);
            return (int)cp;
        }
    }
    return 0;
}

/* ── 策略 1: bitflip ── */
static int mut_bitflip(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    int n = rr(1, len < 32 ? (int)len : 32);
    for (int i = 0; i < n; i++) {
        size_t off = (size_t)rr(0, (int)len - 1);
        int bit = rr(0, 7);
        buf[off] ^= (uint8_t)(1 << bit);
    }
    return 1;
}

/* ── 策略 2: byteflip ── */
static int mut_byteflip(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    int n = rr(1, len < 16 ? (int)len : 16);
    for (int i = 0; i < n; i++) {
        size_t off = (size_t)rr(0, (int)len - 1);
        buf[off] = (uint8_t)rr(0, 255);
    }
    return 1;
}

/* ── 策略 3: arithmetic (小值加减) ── */
static int mut_arithmetic(uint8_t *buf, size_t len) {
    if (len < 2) return mut_byteflip(buf, len);
    int n = rr(1, len < 8 ? (int)len / 2 : 4);
    for (int i = 0; i < n; i++) {
        size_t off = (size_t)rr(0, (int)len - 2);
        int delta = rr(-35, 35);
        int sz = rr(0, 3); /* 0=byte, 1=u16, 2=u32, 3=u64 */
        if (sz == 0) { int8_t v; memcpy(&v, buf+off,1); v=(int8_t)(v+delta); memcpy(buf+off,&v,1); }
        else if (sz == 1 && off+2<=len) {
            int16_t v; memcpy(&v,buf+off,2); v=(int16_t)(v+delta); memcpy(buf+off,&v,2);
        } else if (sz == 2 && off+4<=len) {
            int32_t v; memcpy(&v,buf+off,4); v+=delta; memcpy(buf+off,&v,4);
        } else if (off+8<=len) {
            int64_t v; memcpy(&v,buf+off,8); v+=delta; memcpy(buf+off,&v,8);
        }
    }
    return 1;
}

/* ── 策略 4: interesting values ── */
static int mut_interesting(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    static const uint64_t interesting[] = {
        0, 1, 0x7F, 0x80, 0xFF,
        0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL,
        0x41414141, 0x4141414141414141ULL,
    };
    int nv = (int)(sizeof(interesting)/sizeof(interesting[0]));
    size_t off = (size_t)rr(0, (int)len - 1);
    int pick = rr(0, nv - 1);
    size_t w = (pick >= 6 && pick <= 11) ? 4 : (pick >= 12 ? 8 : (pick <= 5 ? 2 : 1));
    if (off + w > len) w = len - off;
    uint64_t val = interesting[pick];
    memcpy(buf + off, &val, w);
    return 1;
}

/* ── 策略 5: splice ── */
static int mut_splice(uint8_t *buf, size_t len) {
    if (seed_count < 2 || len < 8) return 0;
    int src = rr(0, seed_count - 1);
    int dst_off = rr(0, (int)len - 4);
    int src_off = (int)(seed_sizes[src] > 4 ? (size_t)rr(0, (int)seed_sizes[src] - 4) : 0);
    int splice_len = rr(1, (int)len - dst_off);
    if (src_off + splice_len > (int)seed_sizes[src]) splice_len = (int)seed_sizes[src] - src_off;
    if (splice_len <= 0) return 0;
    memcpy(buf + dst_off, seed_data[src] + src_off, (size_t)splice_len);
    return 1;
}

/* ── 策略 6: dictionary ── */
static int mut_dictionary(uint8_t *buf, size_t len) {
    if (!g_dict || g_dict_count == 0 || len < 2) return 0;
    int pick = rr(0, g_dict_count - 1);
    size_t toklen = strlen(g_dict[pick]);
    if (toklen == 0 || toklen > len) return 0;
    size_t off = (size_t)rr(0, (int)(len - toklen));
    memcpy(buf + off, g_dict[pick], toklen);
    return 1;
}

/* ── 策略 7: havoc (组合多种策略) ── */
static int mut_havoc(uint8_t *buf, size_t len) {
    if (len < 4) return mut_byteflip(buf, len);
    int nops = rr(1, 12);
    for (int op = 0; op < nops; op++) {
        int r = rr(0, 99);
        if      (r < 20) mut_bitflip(buf, len);     /* 20% */
        else if (r < 45) mut_byteflip(buf, len);     /* 25% */
        else if (r < 60) mut_arithmetic(buf, len);    /* 15% */
        else if (r < 75) mut_interesting(buf, len);   /* 15% */
        else if (r < 85) {                            /* 10% delete chunk */
            size_t off = (size_t)rr(0, (int)len - 4);
            size_t dlen = (size_t)rr(1, (int)(len - off) < 32 ? (int)(len - off) : 32);
            memmove(buf + off, buf + off + dlen, len - off - dlen);
            memset(buf + len - dlen, rr(0,255), dlen); /* fill tail */
        }
        else if (r < 95) {                            /* 10% insert random */
            size_t off = (size_t)rr(0, (int)len - 4);
            size_t ilen = (size_t)rr(1, 32);
            for (size_t i = 0; i < ilen && off + i < len; i++)
                buf[off + i] = (uint8_t)rr(0, 255);
        }
        else {                                        /* 10% clone chunk */
            size_t src = (size_t)rr(0, (int)len - 8);
            size_t dst = (size_t)rr(0, (int)len - 8);
            size_t maxc = (src > dst ? len - src : len - dst);
            size_t clen = (size_t)rr(1, maxc > 32 ? 32 : (int)maxc);
            if (clen > 0 && src + clen <= len && dst + clen <= len)
                memmove(buf + dst, buf + src, clen);
        }
    }
    return 1;
}

/* ── 公共入口 ── */

int fuzz_mutate(uint8_t *buf, size_t len, int strategy_mask) {
    if (len == 0) return 0;
    if (strategy_mask == 0) strategy_mask = FUZZ_MUTATE_HAVOC; /* 默认 */

    if (strategy_mask & FUZZ_MUTATE_HAVOC)
        return mut_havoc(buf, len);

    int mutated = 0;
    if (strategy_mask & FUZZ_MUTATE_BITFLIP && rand() % 100 < 30)
        mutated |= mut_bitflip(buf, len);
    if (strategy_mask & FUZZ_MUTATE_BYTEFLIP && rand() % 100 < 25)
        mutated |= mut_byteflip(buf, len);
    if (strategy_mask & FUZZ_MUTATE_ARITHMETIC && rand() % 100 < 20)
        mutated |= mut_arithmetic(buf, len);
    if (strategy_mask & FUZZ_MUTATE_INTERESTING && rand() % 100 < 15)
        mutated |= mut_interesting(buf, len);
    if (strategy_mask & FUZZ_MUTATE_SPLICE && rand() % 100 < 10)
        mutated |= mut_splice(buf, len);
    if (strategy_mask & FUZZ_MUTATE_DICTIONARY && rand() % 100 < 15)
        mutated |= mut_dictionary(buf, len);

    if (!mutated) return mut_byteflip(buf, len); /* 兜底: 至少做一次变异 */
    return 1;
}

/* ── seed management (exposed for engine) ── */
int  fuzz_seed_add(const uint8_t *b, size_t l, int s) { seed_add(b,l,s); return 0; }
int  fuzz_seed_pick(uint8_t *o, size_t m) { return seed_pick(o, m); }
int  fuzz_seed_count(void) { return seed_count; }
void fuzz_seed_reset(void) {
    for (int i = 0; i < seed_count; i++) free(seed_data[i]);
    seed_count = 0;
}
