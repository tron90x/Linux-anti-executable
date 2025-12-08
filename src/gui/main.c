/*
 * Linux Anti-Executable - GUI Client
 *
 * GTK4-based user interface for:
 * - Displaying allow/deny prompts for unknown executables
 * - Managing the whitelist
 * - Viewing activity logs
 *
 * Communicates with lexec-daemon via Unix socket
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "../common/protocol.h"

/* Global application state */
static struct {
    GtkApplication *app;
    GtkWindow *main_window;
    int daemon_socket;
    GIOChannel *socket_channel;
} g_state = {0};

/* Forward declarations */
static void show_allow_deny_dialog(lexec_exec_request_t *request);
static int connect_to_daemon(void);
static void on_socket_data(GIOChannel *source, GIOCondition condition, gpointer data);

/*
 * Create the allow/deny dialog for a new executable
 */
static void show_allow_deny_dialog(lexec_exec_request_t *request) {
    GtkWidget *dialog;
    GtkWidget *content_area;
    GtkWidget *grid;
    GtkWidget *icon;
    GtkWidget *label;
    char buffer[4096];

    dialog = gtk_dialog_new_with_buttons(
        "Unknown Executable Detected",
        g_state.main_window,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "Allow Once", 1,
        "Allow Always", 2,
        "Deny", 3,
        NULL
    );

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_widget_set_margin_start(grid, 20);
    gtk_widget_set_margin_end(grid, 20);
    gtk_widget_set_margin_top(grid, 20);
    gtk_widget_set_margin_bottom(grid, 20);

    /* Warning icon */
    icon = gtk_image_new_from_icon_name("dialog-warning");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 64);
    gtk_grid_attach(GTK_GRID(grid), icon, 0, 0, 1, 4);

    /* Title */
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label),
        "<b><big>A program is trying to run that is not in your whitelist.</big></b>");
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 0, 1, 1);

    /* Path */
    snprintf(buffer, sizeof(buffer), "<b>Path:</b> %s", request->path);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 1, 1, 1);

    /* Hash */
    snprintf(buffer, sizeof(buffer), "<b>SHA256:</b> <tt>%.16s...</tt>", request->hash);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 2, 1, 1);

    /* Parent process */
    snprintf(buffer, sizeof(buffer), "<b>Launched by:</b> %s (PID: %d)",
             request->parent_path, request->pid);
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), buffer);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label, 1, 3, 1, 1);

    gtk_box_append(GTK_BOX(content_area), grid);

    /* Store request ID for response */
    g_object_set_data(G_OBJECT(dialog), "request_id",
                      GINT_TO_POINTER(request->request_id));

    /* Handle response */
    g_signal_connect(dialog, "response", G_CALLBACK(gtk_window_destroy), NULL);

    gtk_window_present(GTK_WINDOW(dialog));
}

/*
 * Connect to the daemon via Unix socket
 */
static int connect_to_daemon(void) {
    struct sockaddr_un addr;
    int sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LEXEC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect to daemon");
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Build the main application window
 */
static void build_main_window(GtkApplication *app) {
    GtkWidget *window;
    GtkWidget *header;
    GtkWidget *notebook;
    GtkWidget *status_page;
    GtkWidget *whitelist_page;
    GtkWidget *log_page;
    GtkWidget *label;

    /* Create main window */
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Linux Anti-Executable");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    g_state.main_window = GTK_WINDOW(window);

    /* Header bar */
    header = gtk_header_bar_new();
    gtk_window_set_titlebar(GTK_WINDOW(window), header);

    /* Notebook for tabs */
    notebook = gtk_notebook_new();
    gtk_window_set_child(GTK_WINDOW(window), notebook);

    /* Status tab */
    status_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(status_page, 20);
    gtk_widget_set_margin_end(status_page, 20);
    gtk_widget_set_margin_top(status_page, 20);

    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), "<big><b>Daemon Status</b></big>");
    gtk_box_append(GTK_BOX(status_page), label);

    label = gtk_label_new("Connecting to daemon...");
    gtk_box_append(GTK_BOX(status_page), label);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), status_page,
                            gtk_label_new("Status"));

    /* Whitelist tab */
    whitelist_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    label = gtk_label_new("Whitelist management - Coming soon");
    gtk_box_append(GTK_BOX(whitelist_page), label);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), whitelist_page,
                            gtk_label_new("Whitelist"));

    /* Log tab */
    log_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    label = gtk_label_new("Activity log - Coming soon");
    gtk_box_append(GTK_BOX(log_page), label);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), log_page,
                            gtk_label_new("Activity Log"));

    gtk_window_present(GTK_WINDOW(window));
}

/*
 * Application activation callback
 */
static void on_activate(GtkApplication *app, gpointer user_data) {
    (void)user_data;

    build_main_window(app);

    /* Try to connect to daemon */
    g_state.daemon_socket = connect_to_daemon();
    if (g_state.daemon_socket == -1) {
        GtkWidget *dialog = gtk_message_dialog_new(
            g_state.main_window,
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_WARNING,
            GTK_BUTTONS_OK,
            "Could not connect to lexec-daemon.\n\n"
            "Make sure the daemon is running:\n"
            "  sudo systemctl start lexec-daemon"
        );
        g_signal_connect(dialog, "response", G_CALLBACK(gtk_window_destroy), NULL);
        gtk_window_present(GTK_WINDOW(dialog));
    }
}

/*
 * Application shutdown callback
 */
static void on_shutdown(GtkApplication *app, gpointer user_data) {
    (void)app;
    (void)user_data;

    if (g_state.daemon_socket >= 0) {
        close(g_state.daemon_socket);
    }
}

int main(int argc, char *argv[]) {
    int status;

    g_state.app = gtk_application_new("org.lexec.gui",
                                      G_APPLICATION_DEFAULT_FLAGS);

    g_signal_connect(g_state.app, "activate", G_CALLBACK(on_activate), NULL);
    g_signal_connect(g_state.app, "shutdown", G_CALLBACK(on_shutdown), NULL);

    status = g_application_run(G_APPLICATION(g_state.app), argc, argv);

    g_object_unref(g_state.app);

    return status;
}
