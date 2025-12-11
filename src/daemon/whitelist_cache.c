/*
 * Linux Anti-Executable - In-Memory Whitelist Cache Implementation
 *
 * Uses a hash table for O(1) lookups plus a bloom filter for fast rejection
 * of definitely-not-whitelisted executables.
 */

#include "whitelist_cache.h"
#include "whitelist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* SHA256 hash is 32 bytes (64 hex chars) */
#define HASH_BYTES 32
#define HASH_HEX_LEN 64

/* Default hash table size (prime number for better distribution) */
#define DEFAULT_TABLE_SIZE 65537

/* Bloom filter size in bits (64KB = 524288 bits, ~0.1% false positive at 50K entries) */
#define BLOOM_SIZE_BITS (64 * 1024 * 8)
#define BLOOM_SIZE_BYTES (BLOOM_SIZE_BITS / 8)
#define BLOOM_HASH_FUNCS 7

/* Hash entry (linked list node for chaining) */
typedef struct hash_entry {
    uint8_t hash[HASH_BYTES];           /* Binary SHA256 */
    struct hash_entry *next;            /* Next in chain */
} hash_entry_t;

/* Cache state */
static struct {
    hash_entry_t **table;               /* Hash table */
    uint32_t table_size;                /* Table size */
    uint32_t entry_count;               /* Number of entries */
    uint32_t max_entries;               /* Maximum entries (0 = unlimited) */
    uint32_t collisions;                /* Collision counter */

    uint8_t *bloom;                     /* Bloom filter bitmap */

    uint64_t lookups;                   /* Stats: total lookups */
    uint64_t hits;                      /* Stats: cache hits */
    uint64_t misses;                    /* Stats: cache misses */
    uint64_t bloom_rejections;          /* Stats: bloom filter rejections */

    pthread_rwlock_t lock;              /* Read-write lock */
    int initialized;
} g_cache = {0};

/* Convert hex string to binary */
static void hex_to_bytes(const char *hex, uint8_t *bytes) {
    for (int i = 0; i < HASH_BYTES; i++) {
        unsigned int val;
        sscanf(hex + (i * 2), "%2x", &val);
        bytes[i] = (uint8_t)val;
    }
}

/* Simple hash function for table index (FNV-1a) */
static uint32_t hash_to_index(const uint8_t *hash, uint32_t table_size) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < HASH_BYTES; i++) {
        h ^= hash[i];
        h *= 16777619u;
    }
    return h % table_size;
}

/* Bloom filter hash functions */
static void bloom_hashes(const uint8_t *hash, uint32_t *indices) {
    /* Use different parts of SHA256 for bloom filter indices */
    for (int i = 0; i < BLOOM_HASH_FUNCS; i++) {
        uint32_t h = 0;
        int offset = (i * 4) % HASH_BYTES;
        memcpy(&h, hash + offset, sizeof(h));
        /* Mix with rotation */
        h = h ^ (h >> 16);
        h *= 0x85ebca6b;
        h = h ^ (h >> 13);
        indices[i] = h % BLOOM_SIZE_BITS;
    }
}

static void bloom_add(const uint8_t *hash) {
    uint32_t indices[BLOOM_HASH_FUNCS];
    bloom_hashes(hash, indices);
    for (int i = 0; i < BLOOM_HASH_FUNCS; i++) {
        g_cache.bloom[indices[i] / 8] |= (1 << (indices[i] % 8));
    }
}

static int bloom_check(const uint8_t *hash) {
    uint32_t indices[BLOOM_HASH_FUNCS];
    bloom_hashes(hash, indices);
    for (int i = 0; i < BLOOM_HASH_FUNCS; i++) {
        if (!(g_cache.bloom[indices[i] / 8] & (1 << (indices[i] % 8)))) {
            return 0;  /* Definitely not in set */
        }
    }
    return 1;  /* Possibly in set */
}

int cache_init(uint32_t max_entries) {
    if (g_cache.initialized) {
        return 0;
    }

    g_cache.table_size = DEFAULT_TABLE_SIZE;
    g_cache.max_entries = max_entries;
    g_cache.entry_count = 0;
    g_cache.collisions = 0;
    g_cache.lookups = 0;
    g_cache.hits = 0;
    g_cache.misses = 0;
    g_cache.bloom_rejections = 0;

    /* Allocate hash table */
    g_cache.table = calloc(g_cache.table_size, sizeof(hash_entry_t *));
    if (!g_cache.table) {
        perror("calloc hash table");
        return -1;
    }

    /* Allocate bloom filter */
    g_cache.bloom = calloc(BLOOM_SIZE_BYTES, 1);
    if (!g_cache.bloom) {
        perror("calloc bloom filter");
        free(g_cache.table);
        return -1;
    }

    pthread_rwlock_init(&g_cache.lock, NULL);
    g_cache.initialized = 1;

    printf("Whitelist cache initialized (table: %u, bloom: %u KB)\n",
           g_cache.table_size, BLOOM_SIZE_BYTES / 1024);

    return 0;
}

void cache_shutdown(void) {
    if (!g_cache.initialized) return;

    pthread_rwlock_wrlock(&g_cache.lock);

    /* Free all entries */
    for (uint32_t i = 0; i < g_cache.table_size; i++) {
        hash_entry_t *entry = g_cache.table[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(g_cache.table);
    free(g_cache.bloom);
    g_cache.table = NULL;
    g_cache.bloom = NULL;
    g_cache.initialized = 0;

    pthread_rwlock_unlock(&g_cache.lock);
    pthread_rwlock_destroy(&g_cache.lock);

    printf("Whitelist cache shutdown\n");
}

int cache_check(const char *hash_hex) {
    if (!g_cache.initialized || strlen(hash_hex) != HASH_HEX_LEN) {
        return 0;
    }

    uint8_t hash[HASH_BYTES];
    hex_to_bytes(hash_hex, hash);

    pthread_rwlock_rdlock(&g_cache.lock);
    g_cache.lookups++;

    /* Quick bloom filter check */
    if (!bloom_check(hash)) {
        g_cache.bloom_rejections++;
        g_cache.misses++;
        pthread_rwlock_unlock(&g_cache.lock);
        return 0;
    }

    /* Full hash table lookup */
    uint32_t idx = hash_to_index(hash, g_cache.table_size);
    hash_entry_t *entry = g_cache.table[idx];

    while (entry) {
        if (memcmp(entry->hash, hash, HASH_BYTES) == 0) {
            g_cache.hits++;
            pthread_rwlock_unlock(&g_cache.lock);
            return 1;
        }
        entry = entry->next;
    }

    g_cache.misses++;
    pthread_rwlock_unlock(&g_cache.lock);
    return 0;
}

int cache_add(const char *hash_hex, const char *path, int persist) {
    if (!g_cache.initialized || strlen(hash_hex) != HASH_HEX_LEN) {
        return -1;
    }

    /* Check max entries */
    if (g_cache.max_entries > 0 && g_cache.entry_count >= g_cache.max_entries) {
        fprintf(stderr, "Cache full, cannot add entry\n");
        return -1;
    }

    uint8_t hash[HASH_BYTES];
    hex_to_bytes(hash_hex, hash);

    pthread_rwlock_wrlock(&g_cache.lock);

    uint32_t idx = hash_to_index(hash, g_cache.table_size);

    /* Check if already exists */
    hash_entry_t *entry = g_cache.table[idx];
    while (entry) {
        if (memcmp(entry->hash, hash, HASH_BYTES) == 0) {
            pthread_rwlock_unlock(&g_cache.lock);
            return 0;  /* Already exists */
        }
        entry = entry->next;
    }

    /* Create new entry */
    hash_entry_t *new_entry = malloc(sizeof(hash_entry_t));
    if (!new_entry) {
        pthread_rwlock_unlock(&g_cache.lock);
        return -1;
    }

    memcpy(new_entry->hash, hash, HASH_BYTES);

    /* Add to chain (at head) */
    if (g_cache.table[idx] != NULL) {
        g_cache.collisions++;
    }
    new_entry->next = g_cache.table[idx];
    g_cache.table[idx] = new_entry;
    g_cache.entry_count++;

    /* Update bloom filter */
    bloom_add(hash);

    pthread_rwlock_unlock(&g_cache.lock);

    /* Persist to SQLite if requested */
    if (persist) {
        whitelist_add(hash_hex, path, 0);
    }

    return 0;
}

int cache_remove(const char *hash_hex) {
    if (!g_cache.initialized || strlen(hash_hex) != HASH_HEX_LEN) {
        return -1;
    }

    uint8_t hash[HASH_BYTES];
    hex_to_bytes(hash_hex, hash);

    pthread_rwlock_wrlock(&g_cache.lock);

    uint32_t idx = hash_to_index(hash, g_cache.table_size);
    hash_entry_t *entry = g_cache.table[idx];
    hash_entry_t *prev = NULL;

    while (entry) {
        if (memcmp(entry->hash, hash, HASH_BYTES) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                g_cache.table[idx] = entry->next;
            }
            free(entry);
            g_cache.entry_count--;
            pthread_rwlock_unlock(&g_cache.lock);

            /* Note: Cannot remove from bloom filter (false positives increase) */
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_rwlock_unlock(&g_cache.lock);
    return -1;  /* Not found */
}

void cache_get_stats(cache_stats_t *stats) {
    if (!g_cache.initialized) {
        memset(stats, 0, sizeof(*stats));
        return;
    }

    pthread_rwlock_rdlock(&g_cache.lock);

    stats->total_entries = g_cache.entry_count;
    stats->hash_table_size = g_cache.table_size;
    stats->collisions = g_cache.collisions;
    stats->lookups = g_cache.lookups;
    stats->hits = g_cache.hits;
    stats->misses = g_cache.misses;
    stats->bloom_rejections = g_cache.bloom_rejections;

    /* Calculate memory usage */
    stats->memory_bytes =
        (g_cache.table_size * sizeof(hash_entry_t *)) +     /* Hash table */
        (g_cache.entry_count * sizeof(hash_entry_t)) +       /* Entries */
        BLOOM_SIZE_BYTES;                                     /* Bloom filter */

    pthread_rwlock_unlock(&g_cache.lock);
}

void cache_clear(void) {
    if (!g_cache.initialized) return;

    pthread_rwlock_wrlock(&g_cache.lock);

    for (uint32_t i = 0; i < g_cache.table_size; i++) {
        hash_entry_t *entry = g_cache.table[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        g_cache.table[i] = NULL;
    }

    memset(g_cache.bloom, 0, BLOOM_SIZE_BYTES);
    g_cache.entry_count = 0;
    g_cache.collisions = 0;

    pthread_rwlock_unlock(&g_cache.lock);
}

int cache_load_from_db(void) {
    /* This would iterate SQLite and call cache_add for each entry */
    /* For now, return 0 - actual implementation uses whitelist_iterate() */
    printf("Loading whitelist into memory cache...\n");

    /* The whitelist module should call cache_add when initializing */
    return g_cache.entry_count;
}
