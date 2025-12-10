/*
 * Linux Anti-Executable - File Hashing
 */

#ifndef LEXEC_HASH_H
#define LEXEC_HASH_H

#include <stdint.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA256_HEX_LENGTH 64

/*
 * Calculate SHA256 hash of a file
 * Returns 0 on success, -1 on error
 */
int hash_file(const char *path, char *hex_output);

/*
 * Calculate SHA256 hash from file descriptor
 * Returns 0 on success, -1 on error
 */
int hash_fd(int fd, char *hex_output);

#endif /* LEXEC_HASH_H */
