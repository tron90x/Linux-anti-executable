/*
 * Linux Anti-Executable - GUI Client
 *
 * GTK4-based user interface with system tray support.
 *
 * Features:
 * - Allow/deny prompts for unknown executables
 * - System tray icon with status indicator
 * - Settings menu accessible from tray
 * - Whitelist management
 *
 * Architecture:
 * - Runs in user session (has display access)
 * - Connects to daemon via Unix socket
 * - Receives permission requests from daemon
 * - Shows dialogs and sends responses back
 *
 * IMPORTANT: This GUI must run in the user's session to access the display.
 * The daemon (running as root) sends requests via IPC, and this client
 * displays dialogs on the user's screen.
 */

#include <gtk/gtk.h>
#include <glib-unix.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "../common/protocol.h"

/* Application state */
static struct {
    GtkApplication *app;
    GtkWindow *main_window;
    GtkWidget *status_label;
    GtkWidget *stats_label;

    int daemon_socket;
    GIOChannel *socket_channel;
    guint socket_watch_id;

    gboolean connected;
    gboolean minimized_to_tray;

    /* Stats */
    uint64_t allowed_count;
    uint64_t denied_count;
} g_app = {
    .daemon_socket = -1,
    .connected = FALSE,
    .minimized_to_tray = FALSE,
    .allowed_count = 0,
    .denied_count = 0,
};

/* Forward declarations */
static int connect_to_daemon(void);
static void disconnect_from_daemon(void);
static gboolean on_socket_readable(GIOChannel *source, GIOCondition cond, gpointer data);
static void show_permission_dialog(lexec_exec_request_t *request);
static void send_response(uint32_t request_id, int response);
static void update_status_display(void);

/*
 * Connect to daemon via Unix socket
 */
static int connect_to_daemon(void) {
    struct sockaddr_un addr;
    int sock;
    int flags;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LEXEC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(sock);
        return -1;
    }

    /* Set non-blocking */
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    g_app.daemon_socket = sock;
    g_app.connected = TRUE;

    /* Setup GLib IO watch */
    g_app.socket_channel = g_io_channel_unix_new(sock);
    g_io_channel_set_encoding(g_app.socket_channel, NULL, NULL);
    g_app.socket_watch_id = g_io_add_watch(
        g_app.socket_channel,
        G_IO_IN | G_IO_HUP | G_IO_ERR,
        on_socket_readable,
        NULL
    );

    printf("Connected to daemon\n");
    return 0;
}

static void disconnect_from_daemon(void) {
    if (g_app.socket_watch_id > 0) {
        g_source_remove(g_app.socket_watch_id);
        g_app.socket_watch_id = 0;
    }
    if (g_app.socket_channel) {
        g_io_channel_unref(g_app.socket_channel);
        g_app.socket_channel = NULL;
    }
    if (g_app.daemon_socket >= 0) {
        close(g_app.daemon_socket);
        g_app.daemon_socket = -1;
    }
    g_app.connected = FALSE;
    printf("Disconnected from daemon\n");
}

/*
 * Send response back to daemon
 */
static void send_response(uint32_t request_id, int response) {
    lexec_exec_response_t resp;

    if (!g_app.connected) return;

    resp.request_id = request_id;
    resp.response = response;

    ssize_t n = write(g_app.daemon_socket, &resp, sizeof(resp));
    if (n != sizeof(resp)) {
        fprintf(stderr, "Failed to send response\n");
    }
}

/*
 * Dialog response callback
 */
static void on_dialog_response(GtkDialog *dialog, int response_id, gpointer user_data) {
    uint32_t request_id = GPOINTER_TO_UINT(user_data);
    int daemon_response;

    switch (response_id) {
        case 1:  /* Allow Once */
            daemon_response = MSG_ALLOW_ONCE;
            g_app.allowed_count++;
            break;
        case 2:  /* Allow Always */
            daemon_response = MSG_ALLOW_ALWAYS;
            g_app.allowed_count++;
            break;
        case 3:  /* Deny */
        default:
            daemon_response = MSG_DENY;
            g_app.denied_count++;
            break;
    }

    send_response(request_id, daemon_response);
    update_status_display();
    gtk_window_destroy(GTK_WINDOW(dialog));
}

/*
 * Show permission dialog for unknown executable
 * This is the critical dialog that appears when a new executable is detected
 */
static void show_permission_dialog(lexec_exec_request_t *request) {
    GtkWidget *dialog;
    GtkWidget *content_area;
    GtkWidget *grid;
    GtkWidget *icon;
    GtkWidget *label;
    char buffer[4096];
    const char *type_str;

    /* Determine type */
    type_str = request->is_shared_lib ? "Shared Library" : "Executable";

    /* Create dialog - note: no parent window required for system-wide dialogs */
    dialog = gtk_dialog_new_with_buttons(
        "Security Alert - Unknown Program",
        NULL,  /* No parent - appears on top of everything */
        GTK_DIALOG_MODAL,
        "Allow Once", 1,
        "Allow Always", 2,
        "Deny", 3,
        NULL
    );

    /* Make it stay on top and grab focus */
    gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_urgency_hint(GTK_WINDOW(dialog), TRUE);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 15);
    gtk_widget_set_margin_start(grid, 20);
    gtk_widget_set_margin_end(grid, 20);
    gtk_widget_set_margin_top(grid, 20);
    gtk_widget_set_margin_bottom(grid, 20);

    /* Warning icon */
    icon = gtk_image_new_from_icon_name("dialog-warning");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 64);
    gtk_grid_attach(GTK_GRID(grid), icon, 0, 0, 1, 5);

    /* Title */
    snprintf(buffer, sizeof(buffer),
        "<b><big>Unknown %s Detected</big></b>\n"
        "<span color='#666'>A program not in your whitelist is trying to run.</span>",
        type_str);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 0, 1, 1);

    /* File path */
    snprintf(buffer, sizeof(buffer), "<b>Path:</b>\n<tt>%s</tt>", request->path);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 60);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 1, 1, 1);

    /* SHA256 hash */
    snprintf(buffer, sizeof(buffer), "<b>SHA256:</b>\n<tt><small>%s</small></tt>", request->hash);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 2, 1, 1);

    /* Parent process info */
    snprintf(buffer, sizeof(buffer),
        "<b>Launched by:</b> %s\n<b>Process ID:</b> %d",
        request->parent_path[0] ? request->parent_path : "(unknown)",
        request->pid);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 3, 1, 1);

    /* Warning note */
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label),
        "<small><span color='#888'>"
        "• <b>Allow Once</b>: Run this time only, ask again next time\n"
        "• <b>Allow Always</b>: Add to whitelist, never ask again\n"
        "• <b>Deny</b>: Block this program from running"
        "</span></small>");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 4, 1, 1);

    gtk_box_append(GTK_BOX(content_area), grid);

    /* Connect response signal */
    g_signal_connect(dialog, "response",
        G_CALLBACK(on_dialog_response),
        GUINT_TO_POINTER(request->request_id));

    /* Set default button to Deny (safer) */
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), 3);

    /* Present dialog */
    gtk_window_present(GTK_WINDOW(dialog));

    /* Play alert sound */
    /* gtk_widget_error_bell(dialog); */
}

/*
 * Handle data from daemon socket
 */
static gboolean on_socket_readable(GIOChannel *source, GIOCondition cond, gpointer data) {
    (void)source;
    (void)data;

    if (cond & (G_IO_HUP | G_IO_ERR)) {
        printf("Daemon connection lost\n");
        disconnect_from_daemon();
        update_status_display();

        /* Try to reconnect after delay */
        g_timeout_add_seconds(5, (GSourceFunc)connect_to_daemon, NULL);
        return G_SOURCE_REMOVE;
    }

    if (cond & G_IO_IN) {
        lexec_exec_request_t request;
        ssize_t n = read(g_app.daemon_socket, &request, sizeof(request));

        if (n == sizeof(request)) {
            printf("Received permission request: %s\n", request.path);
            show_permission_dialog(&request);
        } else if (n == 0) {
            /* Connection closed */
            disconnect_from_daemon();
            update_status_display();
            g_timeout_add_seconds(5, (GSourceFunc)connect_to_daemon, NULL);
            return G_SOURCE_REMOVE;
        }
    }

    return G_SOURCE_CONTINUE;
}

/*
 * Update status display in main window
 */
static void update_status_display(void) {
    if (g_app.status_label) {
        const char *status = g_app.connected ?
            "<span color='green'>● Connected to daemon</span>" :
            "<span color='red'>● Disconnected from daemon</span>";
        gtk_label_set_markup(GTK_LABEL(g_app.status_label), status);
    }

    if (g_app.stats_label) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),
            "Allowed: %lu | Denied: %lu",
            g_app.allowed_count, g_app.denied_count);
        gtk_label_set_text(GTK_LABEL(g_app.stats_label), buffer);
    }
}

/*
 * Reconnect button callback
 */
static void on_reconnect_clicked(GtkButton *button, gpointer data) {
    (void)button;
    (void)data;

    if (!g_app.connected) {
        if (connect_to_daemon() == 0) {
            update_status_display();
        }
    }
}

/*
 * Window close request - minimize to tray instead of closing
 */
static gboolean on_window_close_request(GtkWindow *window, gpointer data) {
    (void)data;
    gtk_widget_set_visible(GTK_WIDGET(window), FALSE);
    g_app.minimized_to_tray = TRUE;
    return TRUE;  /* Prevent actual close */
}

/*
 * Build the main window
 */
static void build_main_window(GtkApplication *app) {
    GtkWidget *window;
    GtkWidget *header;
    GtkWidget *vbox;
    GtkWidget *frame;
    GtkWidget *grid;
    GtkWidget *label;
    GtkWidget *button;

    /* Main window */
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Linux Anti-Executable");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 400);
    g_app.main_window = GTK_WINDOW(window);

    /* Handle close to minimize instead */
    g_signal_connect(window, "close-request", G_CALLBACK(on_window_close_request), NULL);

    /* Header bar */
    header = gtk_header_bar_new();
    gtk_window_set_titlebar(GTK_WINDOW(window), header);

    /* Settings button in header */
    button = gtk_button_new_from_icon_name("open-menu-symbolic");
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), button);

    /* Main content */
    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 20);
    gtk_widget_set_margin_start(vbox, 30);
    gtk_widget_set_margin_end(vbox, 30);
    gtk_widget_set_margin_top(vbox, 30);
    gtk_widget_set_margin_bottom(vbox, 30);
    gtk_window_set_child(GTK_WINDOW(window), vbox);

    /* Title */
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label),
        "<big><b>Linux Anti-Executable</b></big>\n"
        "<span color='#666'>Protecting your system from unauthorized executables</span>");
    gtk_box_append(GTK_BOX(vbox), label);

    /* Status frame */
    frame = gtk_frame_new("Status");
    gtk_box_append(GTK_BOX(vbox), frame);

    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 20);
    gtk_widget_set_margin_start(grid, 15);
    gtk_widget_set_margin_end(grid, 15);
    gtk_widget_set_margin_top(grid, 15);
    gtk_widget_set_margin_bottom(grid, 15);
    gtk_frame_set_child(GTK_FRAME(frame), grid);

    /* Connection status */
    label = gtk_label_new("Daemon:");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);

    g_app.status_label = gtk_label_new(NULL);
    gtk_widget_set_halign(g_app.status_label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), g_app.status_label, 1, 0, 1, 1);

    /* Stats */
    label = gtk_label_new("Session:");
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 0, 1, 1, 1);

    g_app.stats_label = gtk_label_new("Allowed: 0 | Denied: 0");
    gtk_widget_set_halign(g_app.stats_label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), g_app.stats_label, 1, 1, 1, 1);

    /* Reconnect button */
    button = gtk_button_new_with_label("Reconnect");
    g_signal_connect(button, "clicked", G_CALLBACK(on_reconnect_clicked), NULL);
    gtk_grid_attach(GTK_GRID(grid), button, 2, 0, 1, 1);

    /* Info frame */
    frame = gtk_frame_new("Information");
    gtk_box_append(GTK_BOX(vbox), frame);

    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label),
        "<small>"
        "This application monitors and controls which programs can run on your system.\n\n"
        "• The daemon runs in the background as a system service\n"
        "• When an unknown program tries to run, you'll see a prompt\n"
        "• Programs you allow are added to your whitelist\n"
        "• Close this window to minimize to the system tray"
        "</small>");
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_margin_start(label, 15);
    gtk_widget_set_margin_end(label, 15);
    gtk_widget_set_margin_top(label, 15);
    gtk_widget_set_margin_bottom(label, 15);
    gtk_frame_set_child(GTK_FRAME(frame), label);

    update_status_display();
}

/*
 * Application activation
 */
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

    /* Only build window once */
    if (g_app.main_window == NULL) {
        build_main_window(app);
    }

    /* Try to connect to daemon */
    if (!g_app.connected) {
        if (connect_to_daemon() != 0) {
            printf("Could not connect to daemon (will retry)\n");
            /* Retry every 5 seconds */
            g_timeout_add_seconds(5, (GSourceFunc)connect_to_daemon, NULL);
        }
        update_status_display();
    }

    /* Show window if not minimized */
    if (!g_app.minimized_to_tray) {
        gtk_window_present(g_app.main_window);
    }
}

/*
 * Application shutdown
 */
static void on_shutdown(GtkApplication *app, gpointer user_data) {
    (void)app;
    (void)user_data;
    disconnect_from_daemon();
}

/*
 * Main entry point
 */
int main(int argc, char *argv[]) {
    int status;

    /* Create application */
    g_app.app = gtk_application_new(
        "org.lexec.gui",
        G_APPLICATION_DEFAULT_FLAGS
    );

    g_signal_connect(g_app.app, "activate", G_CALLBACK(on_activate), NULL);
    g_signal_connect(g_app.app, "shutdown", G_CALLBACK(on_shutdown), NULL);

    /* Run */
    status = g_application_run(G_APPLICATION(g_app.app), argc, argv);

    g_object_unref(g_app.app);
    return status;
}
