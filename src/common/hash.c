/*
 * Linux Anti-Executable - SHA256 File Hashing
 *
 * Uses OpenSSL for SHA256 computation
 */

#include "hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 65536

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    hex[len * 2] = '\0';
}

int hash_fd(int fd, char *hex_output) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    off_t original_pos;

    /* Save current position */
    original_pos = lseek(fd, 0, SEEK_CUR);
    if (original_pos == -1) {
        original_pos = 0;
    }

    /* Seek to beginning */
    if (lseek(fd, 0, SEEK_SET) == -1) {
        return -1;
    }

    if (!SHA256_Init(&ctx)) {
        return -1;
    }

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        if (!SHA256_Update(&ctx, buffer, bytes_read)) {
            lseek(fd, original_pos, SEEK_SET);
            return -1;
        }
    }

    if (bytes_read == -1) {
        lseek(fd, original_pos, SEEK_SET);
        return -1;
    }

    if (!SHA256_Final(hash, &ctx)) {
        lseek(fd, original_pos, SEEK_SET);
        return -1;
    }

    /* Restore original position */
    lseek(fd, original_pos, SEEK_SET);

    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, hex_output);
    return 0;
}

int hash_file(const char *path, char *hex_output) {
    int fd;
    int result;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    result = hash_fd(fd, hex_output);
    close(fd);

    return result;
}
