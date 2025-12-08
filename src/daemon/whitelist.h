/*
 * Linux Anti-Executable - Whitelist Management
 */

#ifndef LEXEC_WHITELIST_H
#define LEXEC_WHITELIST_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

/*
 * Initialize whitelist database
 * Creates database and tables if they don't exist
 * Returns 0 on success, -1 on error
 */
int whitelist_init(const char *db_path);

/*
 * Close whitelist database
 */
void whitelist_close(void);

/*
 * Check if a hash is in the whitelist
 * Returns 1 if whitelisted, 0 if not
 */
int whitelist_check(const char *hash);

/*
 * Add a file to the whitelist
 * is_system: 1 for auto-added system files
 * Returns 0 on success, -1 on error
 */
int whitelist_add(const char *hash, const char *path, int is_system);

/*
 * Remove a file from the whitelist
 * Returns 0 on success, -1 on error
 */
int whitelist_remove(const char *hash);

/*
 * Get total count of whitelisted entries
 */
uint64_t whitelist_count(void);

/*
 * Set/get learning mode
 * In learning mode, all executables are auto-whitelisted
 */
void whitelist_set_learning_mode(int enabled);
int whitelist_get_learning_mode(void);

/*
 * Scan a directory and add all executables to whitelist
 * Used for initial system scan
 * Returns number of files added
 */
int whitelist_scan_directory(const char *dir_path, int recursive);

#endif /* LEXEC_WHITELIST_H */
