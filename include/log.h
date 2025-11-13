/*
 * log.h
 * Purpose: Declares the logging interface, severity levels, and helper macros
 * for the epoll-echo daemon. All logging flows to stdout/stderr so journald
 * can capture the stream without additional glue code. This header exposes the
 * configuration hooks consumed by CLI parsing (`-v/-vv/-q`) and the fast-path
 * LOG_* convenience macros used throughout the server.
 */

#ifndef EPOLL_ECHO_LOG_H
#define EPOLL_ECHO_LOG_H

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

/*
 * log_set_level
 * new_level: Absolute severity threshold; only messages at or below this level
 *            (e.g., ERROR < WARN < INFO < DEBUG) are emitted.
 * Effect: Updates the global log filter. Not thread-safe; call during startup.
 */
void log_set_level(log_level_t new_level);

/*
 * log_set_verbosity
 * verb_delta: Relative delta from default INFO. CLI uses: -q => -1 (WARN),
 *             -qq => -2 (ERROR), -v/-vv => +1 (DEBUG).
 * Effect: Converts the delta into a concrete severity threshold via
 *         log_set_level. Values outside the supported range are clamped.
 */
void log_set_verbosity(int verb_delta);

/*
 * log_get_level
 * Returns the currently active severity threshold. Useful for tests or future
 * dynamic adjustments. Read-only and thread-safe.
 */
log_level_t log_get_level(void);

/*
 * log_printf
 * level: Severity associated with this message.
 * fmt,...: printf-style format string and arguments that describe the message.
 * Effect: Emits the message to stdout (INFO/DEBUG) or stderr (WARN/ERROR) with
 *         a fixed textual prefix so journald/systemd capture stays parseable.
 */
void log_printf(log_level_t level, const char *fmt, ...) EPOLL_ECHO_ATTR_PRINTF(2, 3);

#define LOG_ERROR(fmt, ...) log_printf(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) log_printf(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_printf(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_printf(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_LOG_H */
