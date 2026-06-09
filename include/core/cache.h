/*
 * cache.h — 线程安全分析结果缓存
 *
 * 每个分析模块的结果按 key 缓存, 避免重复计算。
 * 打开新文件时全部失效。
 *
 * 设计约束:
 *  - 读写锁: 多读单写, 读操作不阻塞其他读
 *  - 自动淘汰: 超过 MAX_ENTRIES 时 LRU 淘汰
 *  - 零依赖, 纯 pthread + 标准 C
 */

#ifndef CACHE_H
#define CACHE_H

#include <pthread.h>
#include "elf_parser.h"

#define CACHE_MAX_ENTRIES 64
#define CACHE_KEY_LEN     64

/* 缓存条目 */
typedef struct CacheEntry {
    char        key[CACHE_KEY_LEN];
    PanelData   data;           /* 分析结果 (fields 由 cache 拥有) */
    int         valid;
    int         access_count;   /* LRU 计数器 */
    pthread_rwlock_t lock;
} CacheEntry;

/* ================================================================
 * Cache API
 * ================================================================ */

/* 初始化全局缓存 */
void cache_init(void);

/* 销毁全局缓存, 释放所有条目 */
void cache_destroy(void);

/* 查找缓存 (线程安全读). 返回 PanelData* 或 NULL */
PanelData* cache_get(const char *key);

/* 存入缓存 (线程安全写). 接管 data 所有权 */
void cache_put(const char *key, PanelData *data);

/* 失效指定前缀的缓存 (如打开新文件时 cache_invalidate("")) */
void cache_invalidate(const char *prefix);

/* 获取缓存统计 */
int  cache_size(void);

#endif
