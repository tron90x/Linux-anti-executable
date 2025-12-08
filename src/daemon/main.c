/*
 * Linux Anti-Executable - Daemon Main Entry Point
 *
 * This daemon monitors all executable file access using fanotify
 * and enforces a whitelist-based execution policy.
 *
 * Requirements:
 * - Linux kernel 5.0+ (for FAN_OPEN_EXEC_PERM)
 * - CAP_SYS_ADMIN capability (or root)
 *
 * Usage:
 *   lexec-daemon [options]
 *
 * Options:
 *   --scan         Perform initial system scan
 *   --learn        Enable learning mode (auto-whitelist)
 *   --foreground   Don't daemonize
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "fanotify_handler.h"
#include "whitelist.h"
#include "../common/protocol.h"

/* Configuration */
static struct {
    int foreground;
    int do_scan;
    int learning_mode;
    char db_path[PATH_MAX];
} g_config = {
    .foreground = 0,
    .do_scan = 0,
    .learning_mode = 0,
    .db_path = "/var/lib/lexec/whitelist.db"
};

/* Global for signal handling */
static volatile sig_atomic_t g_running = 1;
static int g_fan_fd = -1;

/* Directories to scan on first run */
static const char *SCAN_DIRS[] = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    NULL
};

/* Mounts to monitor */
static const char *MONITOR_MOUNTS[] = {
    "/",
    NULL
};

static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    g_running = 0;
}

static void setup_signals(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static int create_directories(void) {
    /* Create /var/lib/lexec */
    if (mkdir("/var/lib/lexec", 0750) == -1 && errno != EEXIST) {
        perror("mkdir /var/lib/lexec");
        return -1;
    }

    /* Create /var/run/lexec for socket */
    if (mkdir("/var/run/lexec", 0750) == -1 && errno != EEXIST) {
        perror("mkdir /var/run/lexec");
        return -1;
    }

    return 0;
}

static void daemonize(void) {
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);  /* Parent exits */
    }

    /* Child becomes session leader */
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    /* Fork again to prevent acquiring a terminal */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Set file permissions */
    umask(0);

    /* Change to root directory */
    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    /* Close standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* Redirect to /dev/null */
    open("/dev/null", O_RDONLY);  /* stdin */
    open("/dev/null", O_WRONLY);  /* stdout */
    open("/dev/null", O_WRONLY);  /* stderr */
}

static void perform_initial_scan(void) {
    int total = 0;

    printf("Performing initial system scan...\n");
    printf("This will whitelist all existing executables.\n\n");

    for (int i = 0; SCAN_DIRS[i] != NULL; i++) {
        printf("Scanning: %s\n", SCAN_DIRS[i]);
        int count = whitelist_scan_directory(SCAN_DIRS[i], 1);
        printf("  Found %d executables\n", count);
        total += count;
    }

    printf("\nInitial scan complete. Whitelisted %d executables.\n", total);
    printf("Total whitelist entries: %lu\n", whitelist_count());
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -s, --scan        Perform initial system scan\n");
    printf("  -l, --learn       Enable learning mode (auto-whitelist new)\n");
    printf("  -f, --foreground  Run in foreground (don't daemonize)\n");
    printf("  -d, --db PATH     Path to whitelist database\n");
    printf("  -h, --help        Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --scan --foreground   First run: scan and watch\n", prog);
    printf("  %s --learn               Learn mode: whitelist new executables\n", prog);
    printf("  %s                       Normal mode: enforce whitelist\n", prog);
}

static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"scan",       no_argument,       0, 's'},
        {"learn",      no_argument,       0, 'l'},
        {"foreground", no_argument,       0, 'f'},
        {"db",         required_argument, 0, 'd'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "slfd:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
            g_config.do_scan = 1;
            break;
        case 'l':
            g_config.learning_mode = 1;
            break;
        case 'f':
            g_config.foreground = 1;
            break;
        case 'd':
            strncpy(g_config.db_path, optarg, PATH_MAX - 1);
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[]) {
    printf("=== Linux Anti-Executable Daemon ===\n\n");

    /* Parse command line */
    parse_args(argc, argv);

    /* Check for root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This daemon requires root privileges.\n");
        fprintf(stderr, "Please run with sudo or as root.\n");
        return EXIT_FAILURE;
    }

    /* Create required directories */
    if (create_directories() == -1) {
        return EXIT_FAILURE;
    }

    /* Setup signal handlers */
    setup_signals();

    /* Initialize whitelist database */
    if (whitelist_init(g_config.db_path) == -1) {
        return EXIT_FAILURE;
    }

    /* Perform initial scan if requested */
    if (g_config.do_scan) {
        perform_initial_scan();
    }

    /* Set learning mode if requested */
    if (g_config.learning_mode) {
        whitelist_set_learning_mode(1);
    }

    /* Initialize fanotify */
    g_fan_fd = fanotify_init_exec_monitor();
    if (g_fan_fd == -1) {
        fprintf(stderr, "Failed to initialize fanotify.\n");
        fprintf(stderr, "Make sure kernel supports FAN_OPEN_EXEC_PERM (5.0+)\n");
        whitelist_close();
        return EXIT_FAILURE;
    }

    /* Add mount points to monitor */
    for (int i = 0; MONITOR_MOUNTS[i] != NULL; i++) {
        if (fanotify_add_mount(g_fan_fd, MONITOR_MOUNTS[i]) == -1) {
            fprintf(stderr, "Warning: Failed to monitor %s\n", MONITOR_MOUNTS[i]);
        }
    }

    /* Daemonize if not in foreground mode */
    if (!g_config.foreground) {
        printf("Daemonizing...\n");
        daemonize();
    }

    printf("\nDaemon started. Monitoring execution attempts.\n");
    printf("Press Ctrl+C to stop (if foreground).\n\n");

    /* Main event loop */
    fanotify_event_loop(g_fan_fd);

    /* Cleanup */
    printf("Shutting down...\n");
    close(g_fan_fd);
    whitelist_close();

    printf("Daemon stopped.\n");
    return EXIT_SUCCESS;
}
