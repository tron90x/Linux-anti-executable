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
 *   --config PATH  Path to configuration file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <grp.h>
#include <pwd.h>

#include "fanotify_handler.h"
#include "whitelist.h"
#include "whitelist_cache.h"
#include "ipc_server.h"
#include "../common/protocol.h"

/* Configuration with defaults */
static struct {
    int foreground;
    int do_scan;
    int learning_mode;
    int log_to_syslog;
    int gui_timeout_ms;
    int default_deny;              /* Deny if no GUI response */
    int monitor_shared_libs;
    char db_path[PATH_MAX];
    char config_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char exclude_paths[4096];      /* Comma-separated */
} g_config = {
    .foreground = 0,
    .do_scan = 0,
    .learning_mode = 0,
    .log_to_syslog = 1,
    .gui_timeout_ms = 30000,       /* 30 seconds */
    .default_deny = 1,             /* Safe default */
    .monitor_shared_libs = 1,
    .db_path = "/var/lib/lexec/whitelist.db",
    .config_path = "/etc/lexec/lexec.conf",
    .socket_path = "/var/run/lexec/lexec.sock",
    .exclude_paths = "/proc,/sys,/dev,/run",
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
    "/opt",
    NULL
};

/* Mounts to monitor */
static const char *MONITOR_MOUNTS[] = {
    "/",
    NULL
};

/* Logging macros - use LEXEC_ prefix to avoid conflict with syslog.h */
#define LEXEC_LOG_INFO(fmt, ...) do { \
    if (g_config.log_to_syslog) syslog(LOG_INFO, fmt, ##__VA_ARGS__); \
    if (g_config.foreground) printf("[INFO] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LEXEC_LOG_WARN(fmt, ...) do { \
    if (g_config.log_to_syslog) syslog(LOG_WARNING, fmt, ##__VA_ARGS__); \
    if (g_config.foreground) printf("[WARN] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LEXEC_LOG_ERR(fmt, ...) do { \
    if (g_config.log_to_syslog) syslog(LOG_ERR, fmt, ##__VA_ARGS__); \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
} while(0)

static void signal_handler(int sig) {
    LEXEC_LOG_INFO("Received signal %d, shutting down...", sig);
    g_running = 0;
    fanotify_stop();
}

static void setup_signals(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Ignore SIGPIPE for socket handling */
    signal(SIGPIPE, SIG_IGN);
}

static int create_directories(void) {
    struct group *grp;

    /* Create /var/lib/lexec */
    if (mkdir("/var/lib/lexec", 0750) == -1 && errno != EEXIST) {
        LEXEC_LOG_ERR("mkdir /var/lib/lexec: %s", strerror(errno));
        return -1;
    }

    /* Create /var/run/lexec for socket with group read access */
    if (mkdir("/var/run/lexec", 0755) == -1 && errno != EEXIST) {
        LEXEC_LOG_ERR("mkdir /var/run/lexec: %s", strerror(errno));
        return -1;
    }

    /* Make socket directory accessible to users (for GUI connection) */
    chmod("/var/run/lexec", 0755);

    return 0;
}

static void daemonize(void) {
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

/* Parse configuration file */
static int parse_config_file(const char *path) {
    FILE *f;
    char line[1024];
    char key[256], value[768];

    f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) {
            LEXEC_LOG_INFO("Config file not found, using defaults: %s", path);
            return 0;
        }
        LEXEC_LOG_ERR("Cannot open config file: %s", path);
        return -1;
    }

    LEXEC_LOG_INFO("Loading configuration from %s", path);

    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        /* Remove trailing newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Parse key = value */
        if (sscanf(p, "%255[^= ] = %767[^\n]", key, value) == 2) {
            /* Trim whitespace from value */
            char *v = value;
            while (*v == ' ' || *v == '\t') v++;

            if (strcmp(key, "database_path") == 0) {
                strncpy(g_config.db_path, v, PATH_MAX - 1);
            } else if (strcmp(key, "socket_path") == 0) {
                strncpy(g_config.socket_path, v, PATH_MAX - 1);
            } else if (strcmp(key, "learning_mode") == 0) {
                g_config.learning_mode = atoi(v);
            } else if (strcmp(key, "gui_timeout") == 0) {
                g_config.gui_timeout_ms = atoi(v) * 1000;
            } else if (strcmp(key, "default_deny") == 0) {
                g_config.default_deny = atoi(v);
            } else if (strcmp(key, "monitor_shared_libs") == 0) {
                g_config.monitor_shared_libs = atoi(v);
            } else if (strcmp(key, "exclude_paths") == 0) {
                strncpy(g_config.exclude_paths, v, sizeof(g_config.exclude_paths) - 1);
            } else if (strcmp(key, "log_to_syslog") == 0) {
                g_config.log_to_syslog = atoi(v);
            }
        }
    }

    fclose(f);
    return 0;
}

/* Check if path should be excluded */
static int is_path_excluded(const char *path) {
    char excludes[4096];
    char *token, *saveptr;

    strncpy(excludes, g_config.exclude_paths, sizeof(excludes) - 1);
    excludes[sizeof(excludes) - 1] = '\0';

    token = strtok_r(excludes, ",", &saveptr);
    while (token) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        if (strncmp(path, token, strlen(token)) == 0) {
            return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

/* Export the exclusion check for fanotify handler */
int daemon_is_path_excluded(const char *path) {
    return is_path_excluded(path);
}

/* Export config for other modules */
int daemon_get_gui_timeout(void) {
    return g_config.gui_timeout_ms;
}

int daemon_get_default_deny(void) {
    return g_config.default_deny;
}

int daemon_is_learning_mode(void) {
    return g_config.learning_mode;
}

static void perform_initial_scan(void) {
    int total = 0;

    LEXEC_LOG_INFO("Performing initial system scan...");
    printf("This will whitelist all existing executables.\n\n");

    for (int i = 0; SCAN_DIRS[i] != NULL; i++) {
        if (is_path_excluded(SCAN_DIRS[i])) {
            printf("Skipping excluded: %s\n", SCAN_DIRS[i]);
            continue;
        }
        printf("Scanning: %s\n", SCAN_DIRS[i]);
        int count = whitelist_scan_directory(SCAN_DIRS[i], 1);
        printf("  Found %d executables\n", count);
        total += count;
    }

    LEXEC_LOG_INFO("Initial scan complete. Whitelisted %d executables.", total);
    printf("Total whitelist entries: %lu\n", whitelist_count());
}

static void print_usage(const char *prog) {
    printf("Linux Anti-Executable Daemon\n\n");
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -s, --scan         Perform initial system scan\n");
    printf("  -l, --learn        Enable learning mode (auto-whitelist new)\n");
    printf("  -f, --foreground   Run in foreground (don't daemonize)\n");
    printf("  -c, --config PATH  Path to configuration file\n");
    printf("  -d, --db PATH      Path to whitelist database\n");
    printf("  -t, --timeout SEC  GUI response timeout (default: 30)\n");
    printf("  -h, --help         Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --scan --foreground   First run: scan and watch\n", prog);
    printf("  %s --learn --foreground  Learn mode: auto-allow new\n", prog);
    printf("  %s                       Normal mode: enforce whitelist\n", prog);
    printf("\n");
    printf("Configuration: %s\n", g_config.config_path);
    printf("Database: %s\n", g_config.db_path);
}

static void parse_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"scan",       no_argument,       0, 's'},
        {"learn",      no_argument,       0, 'l'},
        {"foreground", no_argument,       0, 'f'},
        {"config",     required_argument, 0, 'c'},
        {"db",         required_argument, 0, 'd'},
        {"timeout",    required_argument, 0, 't'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "slfc:d:t:h", long_options, NULL)) != -1) {
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
        case 'c':
            strncpy(g_config.config_path, optarg, PATH_MAX - 1);
            break;
        case 'd':
            strncpy(g_config.db_path, optarg, PATH_MAX - 1);
            break;
        case 't':
            g_config.gui_timeout_ms = atoi(optarg) * 1000;
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

static void print_config(void) {
    printf("Configuration:\n");
    printf("  Database: %s\n", g_config.db_path);
    printf("  Socket: %s\n", g_config.socket_path);
    printf("  Learning mode: %s\n", g_config.learning_mode ? "ON" : "OFF");
    printf("  GUI timeout: %d ms\n", g_config.gui_timeout_ms);
    printf("  Default action: %s\n", g_config.default_deny ? "DENY" : "ALLOW");
    printf("  Monitor .so: %s\n", g_config.monitor_shared_libs ? "ON" : "OFF");
    printf("  Exclude paths: %s\n", g_config.exclude_paths);
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("=== Linux Anti-Executable Daemon ===\n\n");

    /* Parse command line (before config to allow overrides) */
    parse_args(argc, argv);

    /* Load configuration file */
    parse_config_file(g_config.config_path);

    /* Re-parse command line to override config file */
    optind = 1;
    parse_args(argc, argv);

    /* Check for root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This daemon requires root privileges.\n");
        fprintf(stderr, "Please run with sudo or as root.\n");
        return EXIT_FAILURE;
    }

    /* Open syslog */
    if (g_config.log_to_syslog) {
        openlog("lexec-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    /* Print configuration in foreground mode */
    if (g_config.foreground) {
        print_config();
    }

    /* Create required directories */
    if (create_directories() == -1) {
        return EXIT_FAILURE;
    }

    /* Setup signal handlers */
    setup_signals();

    /* Initialize whitelist database */
    if (whitelist_init(g_config.db_path) == -1) {
        LEXEC_LOG_ERR("Failed to initialize whitelist database");
        return EXIT_FAILURE;
    }

    /* Initialize in-memory cache */
    if (cache_init(0) == -1) {
        LEXEC_LOG_ERR("Failed to initialize whitelist cache");
        whitelist_close();
        return EXIT_FAILURE;
    }

    /* Initialize IPC server for GUI communication */
    if (ipc_server_init() == -1) {
        LEXEC_LOG_ERR("Failed to initialize IPC server");
        cache_shutdown();
        whitelist_close();
        return EXIT_FAILURE;
    }

    /* Perform initial scan if requested */
    if (g_config.do_scan) {
        perform_initial_scan();
    }

    /* Set learning mode if requested */
    if (g_config.learning_mode) {
        whitelist_set_learning_mode(1);
        LEXEC_LOG_INFO("Learning mode ENABLED - new executables will be auto-whitelisted");
    }

    /* Initialize fanotify */
    g_fan_fd = fanotify_init_exec_monitor();
    if (g_fan_fd == -1) {
        LEXEC_LOG_ERR("Failed to initialize fanotify");
        LEXEC_LOG_ERR("Make sure kernel supports FAN_OPEN_EXEC_PERM (5.0+)");
        ipc_server_shutdown();
        cache_shutdown();
        whitelist_close();
        return EXIT_FAILURE;
    }

    /* Configure shared library monitoring */
    fanotify_set_monitor_shared_libs(g_config.monitor_shared_libs);

    /* Add mount points to monitor */
    for (int i = 0; MONITOR_MOUNTS[i] != NULL; i++) {
        if (fanotify_add_mount(g_fan_fd, MONITOR_MOUNTS[i]) == -1) {
            LEXEC_LOG_WARN("Failed to monitor %s", MONITOR_MOUNTS[i]);
        }
    }

    /* Daemonize if not in foreground mode */
    if (!g_config.foreground) {
        LEXEC_LOG_INFO("Daemonizing...");
        daemonize();
    }

    LEXEC_LOG_INFO("Daemon started. Monitoring execution attempts.");
    if (g_config.foreground) {
        printf("Press Ctrl+C to stop.\n\n");
    }

    /* Main event loop */
    fanotify_event_loop(g_fan_fd);

    /* Cleanup */
    LEXEC_LOG_INFO("Shutting down...");
    close(g_fan_fd);
    ipc_server_shutdown();
    cache_shutdown();
    whitelist_close();

    if (g_config.log_to_syslog) {
        closelog();
    }

    LEXEC_LOG_INFO("Daemon stopped.");
    return EXIT_SUCCESS;
}
