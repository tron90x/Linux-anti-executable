/*
 * Linux Anti-Executable - Fanotify Handler Implementation
 *
 * Uses fanotify to intercept execution attempts AND shared library loading.
 * Key flags:
 *   - FAN_OPEN_EXEC_PERM: Permission event for execve()
 *   - FAN_OPEN_PERM: Permission event for open() (catches .so loading)
 *
 * For .so files: We use FAN_OPEN_PERM and filter by file extension/ELF type
 * to avoid checking every file open on the system.
 */

#define _GNU_SOURCE
#include "fanotify_handler.h"
#include "whitelist.h"
#include "../common/hash.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* Global flag for graceful shutdown */
static volatile sig_atomic_t g_running = 1;

/* Configuration: whether to monitor .so files */
static int g_monitor_shared_libs = 1;

/* Forward declarations */
static int get_path_from_fd(int fd, char *path, size_t path_size);
static int is_elf_file(int fd);
static int is_shared_library(const char *path);
static void handle_permission_event(int fan_fd, struct fanotify_event_metadata *event);

int fanotify_init_exec_monitor(void) {
    int fan_fd;

    /*
     * Initialize fanotify:
     * - FAN_CLOEXEC: Close on exec
     * - FAN_CLASS_CONTENT: We need file descriptors to read content
     * - FAN_NONBLOCK: Non-blocking mode for event loop
     */
    fan_fd = fanotify_init(
        FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK,
        O_RDONLY | O_LARGEFILE
    );

    if (fan_fd == -1) {
        perror("fanotify_init");
        if (errno == EPERM) {
            fprintf(stderr, "Error: CAP_SYS_ADMIN capability required\n");
        }
        return -1;
    }

    return fan_fd;
}

int fanotify_add_mount(int fan_fd, const char *mount_path) {
    int ret;
    uint64_t mask;

    /*
     * Mark the filesystem for monitoring:
     * - FAN_MARK_ADD: Add to mark
     * - FAN_MARK_MOUNT: Monitor entire mount point
     * - FAN_OPEN_EXEC_PERM: Permission events for execution (kernel 5.0+)
     * - FAN_OPEN_PERM: Permission events for file opens (catches .so loading)
     */
    mask = FAN_OPEN_EXEC_PERM;  /* Always monitor execve() */

    if (g_monitor_shared_libs) {
        mask |= FAN_OPEN_PERM;  /* Also monitor open() for .so files */
    }

    ret = fanotify_mark(
        fan_fd,
        FAN_MARK_ADD | FAN_MARK_MOUNT,
        mask,
        AT_FDCWD,
        mount_path
    );

    if (ret == -1) {
        perror("fanotify_mark");
        return -1;
    }

    printf("Monitoring executions on: %s\n", mount_path);
    if (g_monitor_shared_libs) {
        printf("Monitoring shared library loading on: %s\n", mount_path);
    }
    return 0;
}

void fanotify_set_monitor_shared_libs(int enabled) {
    g_monitor_shared_libs = enabled;
}

int fanotify_allow(int fan_fd, int event_fd) {
    struct fanotify_response response;

    response.fd = event_fd;
    response.response = FAN_ALLOW;

    if (write(fan_fd, &response, sizeof(response)) == -1) {
        perror("fanotify allow response");
        return -1;
    }
    return 0;
}

int fanotify_deny(int fan_fd, int event_fd) {
    struct fanotify_response response;

    response.fd = event_fd;
    response.response = FAN_DENY;

    if (write(fan_fd, &response, sizeof(response)) == -1) {
        perror("fanotify deny response");
        return -1;
    }
    return 0;
}

static int get_path_from_fd(int fd, char *path, size_t path_size) {
    char proc_path[64];
    ssize_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    len = readlink(proc_path, path, path_size - 1);

    if (len == -1) {
        return -1;
    }

    path[len] = '\0';
    return 0;
}

static int is_elf_file(int fd) {
    unsigned char magic[4];
    off_t pos;

    /* Save position */
    pos = lseek(fd, 0, SEEK_CUR);

    /* Read ELF magic */
    lseek(fd, 0, SEEK_SET);
    if (read(fd, magic, 4) != 4) {
        lseek(fd, pos, SEEK_SET);
        return 0;
    }

    /* Restore position */
    lseek(fd, pos, SEEK_SET);

    /* Check ELF magic: 0x7f 'E' 'L' 'F' */
    return (magic[0] == 0x7f && magic[1] == 'E' &&
            magic[2] == 'L' && magic[3] == 'F');
}

static int is_shared_library(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext && strcmp(ext, ".so") == 0) {
        return 1;
    }
    /* Check for .so.X.Y.Z pattern */
    if (strstr(path, ".so.") != NULL) {
        return 1;
    }
    return 0;
}

/*
 * Handle FAN_OPEN_PERM events (for .so file loading)
 * We filter here to only check .so files, allowing everything else
 */
static void handle_open_perm_event(int fan_fd, struct fanotify_event_metadata *event) {
    char path[PATH_MAX];
    char hash[SHA256_HEX_LENGTH + 1];

    /* Get the file path */
    if (get_path_from_fd(event->fd, path, sizeof(path)) == -1) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* IMPORTANT: Only check .so files to avoid performance impact */
    if (!is_shared_library(path)) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Verify it's actually an ELF file */
    if (!is_elf_file(event->fd)) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Calculate file hash */
    if (hash_fd(event->fd, hash) == -1) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Check whitelist */
    if (whitelist_check(hash)) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Unknown shared library */
    printf("[BLOCKED] New shared library detected:\n");
    printf("  Path: %s\n", path);
    printf("  Hash: %s\n", hash);
    printf("  PID:  %d (loading process)\n", event->pid);

    if (whitelist_get_learning_mode()) {
        printf("  Action: AUTO-ALLOW (learning mode)\n");
        whitelist_add(hash, path, 0);
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    printf("  Action: DENIED (not in whitelist)\n");
    fanotify_deny(fan_fd, event->fd);
}

/*
 * Handle FAN_OPEN_EXEC_PERM events (for direct execution via execve)
 */
static void handle_exec_perm_event(int fan_fd, struct fanotify_event_metadata *event) {
    char path[PATH_MAX];
    char hash[SHA256_HEX_LENGTH + 1];

    /* Get the file path */
    if (get_path_from_fd(event->fd, path, sizeof(path)) == -1) {
        fprintf(stderr, "Could not resolve path for fd %d\n", event->fd);
        fanotify_allow(fan_fd, event->fd);  /* Allow on error to not break system */
        return;
    }

    /* Skip non-ELF files (scripts handled by interpreter) */
    if (!is_elf_file(event->fd)) {
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Calculate file hash */
    if (hash_fd(event->fd, hash) == -1) {
        fprintf(stderr, "Could not hash file: %s\n", path);
        fanotify_allow(fan_fd, event->fd);  /* Allow on error */
        return;
    }

    /* Check whitelist */
    if (whitelist_check(hash)) {
        /* File is whitelisted */
        printf("[ALLOW] %s (whitelisted)\n", path);
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /*
     * File is NOT whitelisted - this is where we would:
     * 1. Send request to GUI via IPC
     * 2. Wait for user response
     * 3. Allow or deny based on response
     *
     * For this PoC, we'll use a simple console prompt or
     * learning mode (allow and add to whitelist)
     */
    printf("[BLOCKED] New executable detected:\n");
    printf("  Path: %s\n", path);
    printf("  Hash: %s\n", hash);
    printf("  PID:  %d\n", event->pid);

    /* Check if in learning mode */
    if (whitelist_get_learning_mode()) {
        printf("  Action: AUTO-ALLOW (learning mode)\n");
        whitelist_add(hash, path, 0);
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /*
     * In production, we would send to GUI here.
     * For now, deny unknown executables.
     */
    printf("  Action: DENIED (not in whitelist)\n");
    fanotify_deny(fan_fd, event->fd);
}

void fanotify_event_loop(int fan_fd) {
    char buf[4096];
    ssize_t len;
    struct fanotify_event_metadata *event;

    printf("Starting fanotify event loop...\n");
    printf("Monitoring: executables (execve)%s\n",
           g_monitor_shared_libs ? " + shared libraries (.so)" : "");

    while (g_running) {
        len = read(fan_fd, buf, sizeof(buf));

        if (len == -1) {
            if (errno == EAGAIN) {
                /* No events, sleep briefly */
                usleep(10000);  /* 10ms */
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("read fanotify");
            break;
        }

        /* Process each event in the buffer */
        event = (struct fanotify_event_metadata *)buf;

        while (FAN_EVENT_OK(event, len)) {
            if (event->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "Fanotify metadata version mismatch\n");
                break;
            }

            /* Handle execution permission event (execve) */
            if (event->mask & FAN_OPEN_EXEC_PERM) {
                handle_exec_perm_event(fan_fd, event);
            }
            /* Handle open permission event (catches .so loading) */
            else if (event->mask & FAN_OPEN_PERM) {
                handle_open_perm_event(fan_fd, event);
            }

            /* Close the file descriptor */
            if (event->fd >= 0) {
                close(event->fd);
            }

            event = FAN_EVENT_NEXT(event, len);
        }
    }

    printf("Fanotify event loop stopped\n");
}

void fanotify_stop(void) {
    g_running = 0;
}
