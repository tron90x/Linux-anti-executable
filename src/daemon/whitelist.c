/*
 * Linux Anti-Executable - Whitelist Management Implementation
 *
 * Uses SQLite3 for persistent storage of whitelisted file hashes
 */

#include "whitelist.h"
#include "../common/hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>
#include <linux/limits.h>

static sqlite3 *g_db = NULL;
static int g_learning_mode = 0;

/* Prepared statements for performance */
static sqlite3_stmt *g_stmt_check = NULL;
static sqlite3_stmt *g_stmt_add = NULL;
static sqlite3_stmt *g_stmt_remove = NULL;

static const char *CREATE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS whitelist ("
    "  hash TEXT PRIMARY KEY,"
    "  path TEXT NOT NULL,"
    "  added_time INTEGER NOT NULL,"
    "  added_by INTEGER DEFAULT 0,"
    "  is_system INTEGER DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_path ON whitelist(path);";

int whitelist_init(const char *db_path) {
    int rc;
    char *err_msg = NULL;

    rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    /* Create tables */
    rc = sqlite3_exec(g_db, CREATE_TABLE_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Prepare statements */
    rc = sqlite3_prepare_v2(g_db,
        "SELECT 1 FROM whitelist WHERE hash = ?",
        -1, &g_stmt_check, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare check statement: %s\n",
                sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_prepare_v2(g_db,
        "INSERT OR REPLACE INTO whitelist (hash, path, added_time, is_system) "
        "VALUES (?, ?, ?, ?)",
        -1, &g_stmt_add, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare add statement: %s\n",
                sqlite3_errmsg(g_db));
        return -1;
    }

    rc = sqlite3_prepare_v2(g_db,
        "DELETE FROM whitelist WHERE hash = ?",
        -1, &g_stmt_remove, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare remove statement: %s\n",
                sqlite3_errmsg(g_db));
        return -1;
    }

    printf("Whitelist database initialized: %s\n", db_path);
    printf("Current entries: %lu\n", whitelist_count());

    return 0;
}

void whitelist_close(void) {
    if (g_stmt_check) sqlite3_finalize(g_stmt_check);
    if (g_stmt_add) sqlite3_finalize(g_stmt_add);
    if (g_stmt_remove) sqlite3_finalize(g_stmt_remove);
    if (g_db) sqlite3_close(g_db);

    g_stmt_check = NULL;
    g_stmt_add = NULL;
    g_stmt_remove = NULL;
    g_db = NULL;
}

int whitelist_check(const char *hash) {
    int rc;
    int found = 0;

    if (!g_db || !g_stmt_check) {
        return 0;
    }

    sqlite3_reset(g_stmt_check);
    sqlite3_bind_text(g_stmt_check, 1, hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(g_stmt_check);
    if (rc == SQLITE_ROW) {
        found = 1;
    }

    return found;
}

int whitelist_add(const char *hash, const char *path, int is_system) {
    int rc;
    time_t now = time(NULL);

    if (!g_db || !g_stmt_add) {
        return -1;
    }

    sqlite3_reset(g_stmt_add);
    sqlite3_bind_text(g_stmt_add, 1, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(g_stmt_add, 2, path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(g_stmt_add, 3, (sqlite3_int64)now);
    sqlite3_bind_int(g_stmt_add, 4, is_system);

    rc = sqlite3_step(g_stmt_add);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to add to whitelist: %s\n",
                sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

int whitelist_remove(const char *hash) {
    int rc;

    if (!g_db || !g_stmt_remove) {
        return -1;
    }

    sqlite3_reset(g_stmt_remove);
    sqlite3_bind_text(g_stmt_remove, 1, hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(g_stmt_remove);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to remove from whitelist: %s\n",
                sqlite3_errmsg(g_db));
        return -1;
    }

    return 0;
}

uint64_t whitelist_count(void) {
    sqlite3_stmt *stmt;
    uint64_t count = 0;
    int rc;

    if (!g_db) {
        return 0;
    }

    rc = sqlite3_prepare_v2(g_db,
        "SELECT COUNT(*) FROM whitelist",
        -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = (uint64_t)sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    return count;
}

void whitelist_set_learning_mode(int enabled) {
    g_learning_mode = enabled;
    printf("Learning mode: %s\n", enabled ? "ENABLED" : "DISABLED");
}

int whitelist_get_learning_mode(void) {
    return g_learning_mode;
}

static int is_executable_file(const char *path, struct stat *st) {
    unsigned char magic[4];
    FILE *f;

    /* Must be regular file */
    if (!S_ISREG(st->st_mode)) {
        return 0;
    }

    /* Must have execute permission */
    if (!(st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        return 0;
    }

    /* Check for ELF magic */
    f = fopen(path, "rb");
    if (!f) {
        return 0;
    }

    if (fread(magic, 1, 4, f) != 4) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* ELF magic: 0x7f 'E' 'L' 'F' */
    return (magic[0] == 0x7f && magic[1] == 'E' &&
            magic[2] == 'L' && magic[3] == 'F');
}

int whitelist_scan_directory(const char *dir_path, int recursive) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char path[PATH_MAX];
    char hash[65];
    int count = 0;

    dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        if (lstat(path, &st) == -1) {
            continue;
        }

        /* Recurse into directories */
        if (S_ISDIR(st.st_mode) && recursive) {
            count += whitelist_scan_directory(path, recursive);
            continue;
        }

        /* Check if executable */
        if (is_executable_file(path, &st)) {
            if (hash_file(path, hash) == 0) {
                if (whitelist_add(hash, path, 1) == 0) {
                    count++;
                    if (count % 100 == 0) {
                        printf("Scanned %d executables...\n", count);
                    }
                }
            }
        }
    }

    closedir(dir);
    return count;
}
