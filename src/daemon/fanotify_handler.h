/*
 * Linux Anti-Executable - Fanotify Handler
 */

#ifndef LEXEC_FANOTIFY_H
#define LEXEC_FANOTIFY_H

#include <sys/fanotify.h>

/*
 * Initialize fanotify with execution permission events
 * Returns fanotify fd on success, -1 on error
 */
int fanotify_init_exec_monitor(void);

/*
 * Add mount point to monitor
 * Returns 0 on success, -1 on error
 */
int fanotify_add_mount(int fan_fd, const char *mount_path);

/*
 * Process fanotify events in a loop
 * This function blocks and processes events until stopped
 */
void fanotify_event_loop(int fan_fd);

/*
 * Send allow response for an event
 */
int fanotify_allow(int fan_fd, int event_fd);

/*
 * Send deny response for an event
 */
int fanotify_deny(int fan_fd, int event_fd);

/*
 * Enable/disable shared library (.so) monitoring
 * Must be called before fanotify_add_mount()
 * Default: enabled
 */
void fanotify_set_monitor_shared_libs(int enabled);

/*
 * Stop the event loop gracefully
 */
void fanotify_stop(void);

#endif /* LEXEC_FANOTIFY_H */
