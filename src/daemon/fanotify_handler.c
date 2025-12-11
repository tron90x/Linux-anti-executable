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

#include "fanotify_handler.h"
#include "whitelist.h"
#include "whitelist_cache.h"
#include "ipc_server.h"
#include "../common/hash.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* External functions from main.c */
extern int daemon_is_path_excluded(const char *path);
extern int daemon_get_gui_timeout(void);
extern int daemon_get_default_deny(void);
extern int daemon_is_learning_mode(void);

/* Global flag for graceful shutdown */
static volatile sig_atomic_t g_running = 1;

/* Configuration: whether to monitor .so files */
static int g_monitor_shared_libs = 1;

/* Statistics */
static uint64_t g_stat_allowed = 0;
static uint64_t g_stat_denied = 0;
static uint64_t g_stat_cached = 0;

/* Forward declarations */
static int get_path_from_fd(int fd, char *path, size_t path_size);
static int is_elf_file(int fd);
static int is_shared_library(const char *path);
static int get_parent_path(pid_t pid, char *path, size_t path_size);
static int ask_user_permission(const char *path, const char *hash, pid_t pid, int is_so);

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
    g_stat_allowed++;
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
    g_stat_denied++;
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

static int get_parent_path(pid_t pid, char *path, size_t path_size) {
    char proc_path[64];
    ssize_t len;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    len = readlink(proc_path, path, path_size - 1);

    if (len == -1) {
        path[0] = '\0';
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
 * Ask user for permission via IPC to GUI
 * Returns: 1 = allow and whitelist, 0 = allow once, -1 = deny
 */
static int ask_user_permission(const char *path, const char *hash, pid_t pid, int is_so) {
    lexec_exec_request_t request;
    lexec_ipc_response_t response;
    int timeout_ms = daemon_get_gui_timeout();

    /* Build request */
    memset(&request, 0, sizeof(request));
    strncpy(request.path, path, sizeof(request.path) - 1);
    strncpy(request.hash, hash, sizeof(request.hash) - 1);
    request.pid = pid;
    request.is_shared_lib = is_so ? 1 : 0;
    get_parent_path(pid, request.parent_path, sizeof(request.parent_path));

    /* Send to GUI and wait */
    response = ipc_request_permission(&request, timeout_ms);

    switch (response) {
        case LEXEC_RESPONSE_ALLOW_ALWAYS:
            syslog(LOG_INFO, "User ALLOWED (always): %s", path);
            return 1;  /* Allow and whitelist */

        case LEXEC_RESPONSE_ALLOW_ONCE:
            syslog(LOG_INFO, "User ALLOWED (once): %s", path);
            return 0;  /* Allow but don't whitelist */

        case LEXEC_RESPONSE_DENY:
            syslog(LOG_WARNING, "User DENIED: %s", path);
            return -1;

        case LEXEC_RESPONSE_TIMEOUT:
            syslog(LOG_WARNING, "GUI timeout for: %s (default: %s)",
                   path, daemon_get_default_deny() ? "DENY" : "ALLOW");
            return daemon_get_default_deny() ? -1 : 0;

        case LEXEC_RESPONSE_NO_CLIENT:
            syslog(LOG_WARNING, "No GUI connected for: %s (default: %s)",
                   path, daemon_get_default_deny() ? "DENY" : "ALLOW");
            return daemon_get_default_deny() ? -1 : 0;

        default:
            return daemon_get_default_deny() ? -1 : 0;
    }
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

    /* Check if path is excluded */
    if (daemon_is_path_excluded(path)) {
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

    /* Check in-memory cache first (fastest) */
    if (cache_check(hash)) {
        g_stat_cached++;
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Check database whitelist */
    if (whitelist_check(hash)) {
        cache_add(hash, path, 0);  /* Add to cache */
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Unknown shared library - handle according to mode */
    printf("[NEW] Shared library: %s\n", path);

    if (daemon_is_learning_mode()) {
        printf("  Action: AUTO-ALLOW (learning mode)\n");
        whitelist_add(hash, path, 0);
        cache_add(hash, path, 0);
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Ask user via GUI */
    int decision = ask_user_permission(path, hash, event->pid, 1);

    if (decision >= 0) {
        if (decision == 1) {
            /* Add to whitelist */
            whitelist_add(hash, path, 0);
            cache_add(hash, path, 0);
        }
        fanotify_allow(fan_fd, event->fd);
    } else {
        fanotify_deny(fan_fd, event->fd);
    }
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

    /* Check if path is excluded */
    if (daemon_is_path_excluded(path)) {
        fanotify_allow(fan_fd, event->fd);
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

    /* Check in-memory cache first (fastest) */
    if (cache_check(hash)) {
        g_stat_cached++;
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Check database whitelist */
    if (whitelist_check(hash)) {
        cache_add(hash, path, 0);  /* Add to cache for next time */
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Unknown executable */
    printf("[NEW] Executable: %s\n", path);

    if (daemon_is_learning_mode()) {
        printf("  Action: AUTO-ALLOW (learning mode)\n");
        whitelist_add(hash, path, 0);
        cache_add(hash, path, 0);
        fanotify_allow(fan_fd, event->fd);
        return;
    }

    /* Ask user via GUI */
    int decision = ask_user_permission(path, hash, event->pid, 0);

    if (decision >= 0) {
        if (decision == 1) {
            /* Add to whitelist */
            whitelist_add(hash, path, 0);
            cache_add(hash, path, 0);
            printf("  Action: ALLOWED (added to whitelist)\n");
        } else {
            printf("  Action: ALLOWED (once)\n");
        }
        fanotify_allow(fan_fd, event->fd);
    } else {
        printf("  Action: DENIED\n");
        fanotify_deny(fan_fd, event->fd);
    }
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
    printf("Statistics: allowed=%lu denied=%lu cached=%lu\n",
           g_stat_allowed, g_stat_denied, g_stat_cached);
}

void fanotify_stop(void) {
    g_running = 0;
}

void fanotify_get_stats(uint64_t *allowed, uint64_t *denied, uint64_t *cached) {
    if (allowed) *allowed = g_stat_allowed;
    if (denied) *denied = g_stat_denied;
    if (cached) *cached = g_stat_cached;
}
