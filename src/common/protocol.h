/*
 * Linux Anti-Executable - IPC Protocol Definitions
 *
 * Defines the communication protocol between daemon and GUI
 */

#ifndef LEXEC_PROTOCOL_H
#define LEXEC_PROTOCOL_H

#include <stdint.h>
#include <sys/types.h>

#define LEXEC_SOCKET_PATH "/var/run/lexec/lexec.sock"
#define LEXEC_DB_PATH "/var/lib/lexec/whitelist.db"
#define LEXEC_CONFIG_PATH "/etc/lexec/lexec.conf"

#define LEXEC_MAX_PATH 4096
#define LEXEC_HASH_SIZE 64  /* SHA256 hex string */

/* Message types from daemon to GUI */
typedef enum {
    MSG_EXEC_REQUEST = 1,    /* New executable wants to run */
    MSG_STATUS_UPDATE,       /* Daemon status change */
    MSG_SCAN_PROGRESS,       /* Initial scan progress */
} lexec_msg_type_t;

/* Message types from GUI to daemon */
typedef enum {
    MSG_ALLOW_ONCE = 100,    /* Allow this execution only */
    MSG_ALLOW_ALWAYS,        /* Add to whitelist */
    MSG_DENY,                /* Block execution */
    MSG_QUERY_STATUS,        /* Request daemon status */
    MSG_START_SCAN,          /* Trigger initial scan */
} lexec_response_type_t;

/* Execution request sent to GUI */
typedef struct {
    uint32_t request_id;
    pid_t pid;                           /* Process attempting execution */
    uid_t uid;                           /* User ID */
    char path[LEXEC_MAX_PATH];           /* Full path to executable */
    char hash[LEXEC_HASH_SIZE + 1];      /* SHA256 hash */
    char cmdline[LEXEC_MAX_PATH];        /* Command line */
    char parent_path[LEXEC_MAX_PATH];    /* Parent process path */
    uint8_t is_shared_lib;               /* 1 if .so file */
} lexec_exec_request_t;

/* Response from GUI */
typedef struct {
    uint32_t request_id;
    lexec_response_type_t response;
} lexec_exec_response_t;

/* Whitelist entry */
typedef struct {
    char hash[LEXEC_HASH_SIZE + 1];
    char path[LEXEC_MAX_PATH];           /* Original path (informational) */
    time_t added_time;
    uid_t added_by;
    uint8_t is_system;                   /* Auto-whitelisted system file */
} lexec_whitelist_entry_t;

/* Daemon status */
typedef struct {
    uint8_t running;
    uint8_t learning_mode;               /* Allow all, just log */
    uint64_t total_allowed;
    uint64_t total_denied;
    uint64_t whitelist_count;
} lexec_status_t;

#endif /* LEXEC_PROTOCOL_H */
