/*
 * cache.c — 线程安全分析结果缓存实现
 */

#include "core/cache.h"
#include <stdlib.h>
#include <string.h>

static CacheEntry cache_entries[CACHE_MAX_ENTRIES];
static int        cache_count = 0;
static pthread_rwlock_t cache_rwlock = PTHREAD_RWLOCK_INITIALIZER;

void cache_init(void)
{
    memset(cache_entries, 0, sizeof(cache_entries));
    cache_count = 0;
}

void cache_destroy(void)
{
    pthread_rwlock_wrlock(&cache_rwlock);
    for (int i = 0; i < cache_count; i++) {
        if (cache_entries[i].valid) {
            pthread_rwlock_wrlock(&cache_entries[i].lock);
            fields_free(cache_entries[i].data.fields,
                        cache_entries[i].data.count);
            pthread_rwlock_unlock(&cache_entries[i].lock);
            pthread_rwlock_destroy(&cache_entries[i].lock);
        }
    }
    cache_count = 0;
    pthread_rwlock_unlock(&cache_rwlock);
}

PanelData* cache_get(const char *key)
{
    pthread_rwlock_rdlock(&cache_rwlock);
    for (int i = 0; i < cache_count; i++) {
        if (cache_entries[i].valid &&
            strcmp(cache_entries[i].key, key) == 0) {
            pthread_rwlock_rdlock(&cache_entries[i].lock);
            cache_entries[i].access_count++;
            PanelData *pd = &cache_entries[i].data;
            pthread_rwlock_unlock(&cache_entries[i].lock);
            pthread_rwlock_unlock(&cache_rwlock);
            return pd;
        }
    }
    pthread_rwlock_unlock(&cache_rwlock);
    return NULL;
}

void cache_put(const char *key, PanelData *data)
{
    if (!data) return;

    pthread_rwlock_wrlock(&cache_rwlock);

    /* 检查是否已存在 (覆盖) */
    for (int i = 0; i < cache_count; i++) {
        if (strcmp(cache_entries[i].key, key) == 0) {
            pthread_rwlock_wrlock(&cache_entries[i].lock);
            if (cache_entries[i].valid)
                fields_free(cache_entries[i].data.fields,
                            cache_entries[i].data.count);
            cache_entries[i].data = *data;
            cache_entries[i].valid = 1;
            pthread_rwlock_unlock(&cache_entries[i].lock);
            pthread_rwlock_unlock(&cache_rwlock);
            return;
        }
    }

    /* LRU 淘汰: 超过上限时移除访问次数最少的 */
    if (cache_count >= CACHE_MAX_ENTRIES) {
        int lru_idx = 0, lru_cnt = cache_entries[0].access_count;
        for (int i = 1; i < cache_count; i++) {
            if (cache_entries[i].access_count < lru_cnt) {
                lru_cnt = cache_entries[i].access_count;
                lru_idx = i;
            }
        }
        pthread_rwlock_wrlock(&cache_entries[lru_idx].lock);
        if (cache_entries[lru_idx].valid)
            fields_free(cache_entries[lru_idx].data.fields,
                        cache_entries[lru_idx].data.count);
        pthread_rwlock_unlock(&cache_entries[lru_idx].lock);
        /* 将最后一个条目移到被淘汰位置 */
        cache_entries[lru_idx] = cache_entries[cache_count - 1];
        cache_count--;
    }

    /* 新条目 */
    CacheEntry *e = &cache_entries[cache_count++];
    strncpy(e->key, key, CACHE_KEY_LEN - 1);
    e->key[CACHE_KEY_LEN - 1] = '\0';
    e->data = *data;
    e->valid = 1;
    e->access_count = 1;
    pthread_rwlock_init(&e->lock, NULL);

    pthread_rwlock_unlock(&cache_rwlock);
}

void cache_invalidate(const char *prefix)
{
    pthread_rwlock_wrlock(&cache_rwlock);
    for (int i = 0; i < cache_count; i++) {
        if (strncmp(cache_entries[i].key, prefix, strlen(prefix)) == 0) {
            pthread_rwlock_wrlock(&cache_entries[i].lock);
            if (cache_entries[i].valid)
                fields_free(cache_entries[i].data.fields,
                            cache_entries[i].data.count);
            cache_entries[i].valid = 0;
            pthread_rwlock_unlock(&cache_entries[i].lock);
        }
    }
    pthread_rwlock_unlock(&cache_rwlock);
}

int cache_size(void)
{
    return cache_count;
}
