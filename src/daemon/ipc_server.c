/*
 * Linux Anti-Executable - IPC Server Implementation
 *
 * Manages Unix socket communication with GUI client.
 * Uses non-blocking I/O with poll() for responsiveness.
 */

#include "ipc_server.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

/* Server state */
static struct {
    int server_fd;              /* Listening socket */
    int client_fd;              /* Connected GUI client (-1 if none) */
    pthread_mutex_t lock;       /* Protects client_fd */
    pthread_t accept_thread;    /* Thread accepting connections */
    volatile int running;       /* Server running flag */
    uint32_t next_request_id;   /* Request ID counter */
} g_server = {
    .server_fd = -1,
    .client_fd = -1,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .running = 0,
    .next_request_id = 1,
};

/* Pending request tracking */
typedef struct {
    uint32_t request_id;
    lexec_ipc_response_t response;
    int completed;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
} pending_request_t;

#define MAX_PENDING_REQUESTS 64
static pending_request_t g_pending[MAX_PENDING_REQUESTS];
static int g_pending_count = 0;
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;

static void *accept_thread_func(void *arg);
static void *client_reader_thread(void *arg);

int ipc_server_init(void) {
    struct sockaddr_un addr;
    int ret;

    /* Remove old socket file if exists */
    unlink(LEXEC_SOCKET_PATH);

    /* Create directory if needed */
    mkdir("/var/run/lexec", 0755);

    /* Create socket */
    g_server.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server.server_fd == -1) {
        perror("socket");
        return -1;
    }

    /* Bind to path */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LEXEC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    ret = bind(g_server.server_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        perror("bind");
        close(g_server.server_fd);
        return -1;
    }

    /* Allow user group to connect */
    chmod(LEXEC_SOCKET_PATH, 0660);

    /* Listen for connections */
    if (listen(g_server.server_fd, 5) == -1) {
        perror("listen");
        close(g_server.server_fd);
        return -1;
    }

    /* Start accept thread */
    g_server.running = 1;
    if (pthread_create(&g_server.accept_thread, NULL, accept_thread_func, NULL) != 0) {
        perror("pthread_create");
        close(g_server.server_fd);
        return -1;
    }

    printf("IPC server started on %s\n", LEXEC_SOCKET_PATH);
    return 0;
}

void ipc_server_shutdown(void) {
    g_server.running = 0;

    if (g_server.server_fd >= 0) {
        close(g_server.server_fd);
        g_server.server_fd = -1;
    }

    pthread_mutex_lock(&g_server.lock);
    if (g_server.client_fd >= 0) {
        close(g_server.client_fd);
        g_server.client_fd = -1;
    }
    pthread_mutex_unlock(&g_server.lock);

    pthread_join(g_server.accept_thread, NULL);
    unlink(LEXEC_SOCKET_PATH);

    printf("IPC server stopped\n");
}

int ipc_has_client(void) {
    int has;
    pthread_mutex_lock(&g_server.lock);
    has = (g_server.client_fd >= 0);
    pthread_mutex_unlock(&g_server.lock);
    return has;
}

static void *accept_thread_func(void *arg) {
    (void)arg;
    struct pollfd pfd;

    while (g_server.running) {
        pfd.fd = g_server.server_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);  /* 1 second timeout */
        if (ret <= 0) continue;

        int client = accept(g_server.server_fd, NULL, NULL);
        if (client == -1) continue;

        printf("GUI client connected\n");

        pthread_mutex_lock(&g_server.lock);
        /* Close old client if any */
        if (g_server.client_fd >= 0) {
            close(g_server.client_fd);
        }
        g_server.client_fd = client;
        pthread_mutex_unlock(&g_server.lock);

        /* Start reader thread for this client */
        pthread_t reader;
        pthread_create(&reader, NULL, client_reader_thread, (void *)(intptr_t)client);
        pthread_detach(reader);
    }

    return NULL;
}

static void *client_reader_thread(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    lexec_exec_response_t response;

    while (g_server.running) {
        ssize_t n = read(client_fd, &response, sizeof(response));
        if (n <= 0) {
            printf("GUI client disconnected\n");
            pthread_mutex_lock(&g_server.lock);
            if (g_server.client_fd == client_fd) {
                g_server.client_fd = -1;
            }
            pthread_mutex_unlock(&g_server.lock);
            close(client_fd);
            break;
        }

        if (n == sizeof(response)) {
            /* Find pending request and signal it */
            pthread_mutex_lock(&g_pending_lock);
            for (int i = 0; i < g_pending_count; i++) {
                if (g_pending[i].request_id == response.request_id) {
                    pthread_mutex_lock(&g_pending[i].mutex);
                    g_pending[i].response = (lexec_ipc_response_t)response.response;
                    g_pending[i].completed = 1;
                    pthread_cond_signal(&g_pending[i].cond);
                    pthread_mutex_unlock(&g_pending[i].mutex);
                    break;
                }
            }
            pthread_mutex_unlock(&g_pending_lock);
        }
    }

    return NULL;
}

lexec_ipc_response_t ipc_request_permission(
    const lexec_exec_request_t *request,
    int timeout_ms
) {
    lexec_exec_request_t req_copy;
    pending_request_t *pending = NULL;
    lexec_ipc_response_t result;
    int client_fd;
    struct timespec ts;

    /* Check if client connected */
    pthread_mutex_lock(&g_server.lock);
    client_fd = g_server.client_fd;
    pthread_mutex_unlock(&g_server.lock);

    if (client_fd < 0) {
        return LEXEC_RESPONSE_NO_CLIENT;
    }

    /* Prepare request with unique ID */
    memcpy(&req_copy, request, sizeof(req_copy));
    req_copy.request_id = __sync_fetch_and_add(&g_server.next_request_id, 1);

    /* Allocate pending slot */
    pthread_mutex_lock(&g_pending_lock);
    if (g_pending_count >= MAX_PENDING_REQUESTS) {
        pthread_mutex_unlock(&g_pending_lock);
        return LEXEC_RESPONSE_TIMEOUT;
    }
    pending = &g_pending[g_pending_count++];
    pending->request_id = req_copy.request_id;
    pending->response = LEXEC_RESPONSE_TIMEOUT;
    pending->completed = 0;
    pthread_mutex_init(&pending->mutex, NULL);
    pthread_cond_init(&pending->cond, NULL);
    pthread_mutex_unlock(&g_pending_lock);

    /* Send request to client */
    ssize_t n = write(client_fd, &req_copy, sizeof(req_copy));
    if (n != sizeof(req_copy)) {
        result = LEXEC_RESPONSE_NO_CLIENT;
        goto cleanup;
    }

    /* Wait for response with timeout */
    pthread_mutex_lock(&pending->mutex);

    if (timeout_ms > 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }

        while (!pending->completed) {
            int ret = pthread_cond_timedwait(&pending->cond, &pending->mutex, &ts);
            if (ret == ETIMEDOUT) {
                break;
            }
        }
    } else {
        while (!pending->completed) {
            pthread_cond_wait(&pending->cond, &pending->mutex);
        }
    }

    result = pending->completed ? pending->response : LEXEC_RESPONSE_TIMEOUT;
    pthread_mutex_unlock(&pending->mutex);

cleanup:
    /* Remove from pending list */
    pthread_mutex_lock(&g_pending_lock);
    for (int i = 0; i < g_pending_count; i++) {
        if (g_pending[i].request_id == req_copy.request_id) {
            pthread_mutex_destroy(&g_pending[i].mutex);
            pthread_cond_destroy(&g_pending[i].cond);
            /* Shift remaining entries */
            memmove(&g_pending[i], &g_pending[i + 1],
                    (g_pending_count - i - 1) * sizeof(pending_request_t));
            g_pending_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_pending_lock);

    return result;
}

int ipc_pending_count(void) {
    int count;
    pthread_mutex_lock(&g_pending_lock);
    count = g_pending_count;
    pthread_mutex_unlock(&g_pending_lock);
    return count;
}
