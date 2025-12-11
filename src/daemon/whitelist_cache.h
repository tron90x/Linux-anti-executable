/*
 * Linux Anti-Executable - In-Memory Whitelist Cache
 *
 * Provides fast O(1) hash lookups to avoid SQLite queries on every execution.
 * Uses a hash table with chaining for collision resolution.
 *
 * Memory optimization strategies:
 * 1. Only store SHA256 hashes (32 bytes each), not full paths
 * 2. Use a bloom filter for quick negative lookups
 * 3. Lazy-load from SQLite on startup
 * 4. Configurable maximum cache size
 */

#ifndef LEXEC_WHITELIST_CACHE_H
#define LEXEC_WHITELIST_CACHE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Initialize the in-memory cache
 * max_entries: Maximum number of entries (0 = unlimited)
 * Returns 0 on success, -1 on error
 */
int cache_init(uint32_t max_entries);

/*
 * Shutdown and free cache memory
 */
void cache_shutdown(void);

/*
 * Load all entries from SQLite into cache
 * Should be called at startup
 * Returns number of entries loaded
 */
int cache_load_from_db(void);

/*
 * Check if hash is in cache (O(1) lookup)
 * Returns 1 if found, 0 if not
 */
int cache_check(const char *hash_hex);

/*
 * Add hash to cache
 * Also updates SQLite if persist is true
 */
int cache_add(const char *hash_hex, const char *path, int persist);

/*
 * Remove hash from cache
 */
int cache_remove(const char *hash_hex);

/*
 * Get cache statistics
 */
typedef struct {
    uint32_t total_entries;     /* Number of cached entries */
    uint32_t hash_table_size;   /* Size of hash table */
    uint32_t collisions;        /* Number of hash collisions */
    uint64_t lookups;           /* Total lookup count */
    uint64_t hits;              /* Cache hits */
    uint64_t misses;            /* Cache misses */
    uint64_t bloom_rejections;  /* Quick rejections by bloom filter */
    size_t memory_bytes;        /* Approximate memory usage */
} cache_stats_t;

void cache_get_stats(cache_stats_t *stats);

/*
 * Clear all entries from cache (but not from SQLite)
 */
void cache_clear(void);

#endif /* LEXEC_WHITELIST_CACHE_H */
