/*
 * Linux Anti-Executable - IPC Server (Daemon Side)
 *
 * Handles communication between daemon and GUI client.
 * The GUI runs in user session and has access to the display.
 * The daemon sends permission requests to GUI and waits for responses.
 *
 * Architecture:
 *   Daemon (root, no display) <--Unix Socket--> GUI (user session, has display)
 */

#ifndef LEXEC_IPC_SERVER_H
#define LEXEC_IPC_SERVER_H

#include "../common/protocol.h"
#include <stdint.h>

/*
 * Initialize IPC server
 * Creates Unix socket at LEXEC_SOCKET_PATH
 * Returns 0 on success, -1 on error
 */
int ipc_server_init(void);

/*
 * Shutdown IPC server
 */
void ipc_server_shutdown(void);

/*
 * Check if a GUI client is connected
 */
int ipc_has_client(void);

/*
 * Send permission request to GUI and wait for response
 *
 * Parameters:
 *   request - The execution request details
 *   timeout_ms - Timeout in milliseconds (0 = no timeout)
 *
 * Returns:
 *   LEXEC_RESPONSE_ALLOW_ONCE - Allow this execution only
 *   LEXEC_RESPONSE_ALLOW_ALWAYS - Allow and add to whitelist
 *   LEXEC_RESPONSE_DENY - Deny execution
 *   LEXEC_RESPONSE_TIMEOUT - No response within timeout
 *   LEXEC_RESPONSE_NO_CLIENT - No GUI client connected
 */
typedef enum {
    LEXEC_RESPONSE_ALLOW_ONCE = 1,
    LEXEC_RESPONSE_ALLOW_ALWAYS = 2,
    LEXEC_RESPONSE_DENY = 3,
    LEXEC_RESPONSE_TIMEOUT = -1,
    LEXEC_RESPONSE_NO_CLIENT = -2,
} lexec_ipc_response_t;

lexec_ipc_response_t ipc_request_permission(
    const lexec_exec_request_t *request,
    int timeout_ms
);

/*
 * Get number of pending requests
 */
int ipc_pending_count(void);

#endif /* LEXEC_IPC_SERVER_H */
