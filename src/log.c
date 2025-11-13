/*
 * log.c
 * Purpose: Implements the leveled logging backend shared across the
 * epoll-echo daemon. Messages are prefixed with fixed strings, routed to
 * stdout (INFO/DEBUG) or stderr (WARN/ERROR), and filtered according to the
 * CLI-controlled verbosity setting. Journald captures both streams, so no
 * further integration work is required.
 */

#include "log.h"

#include <stdarg.h>
#include <stdio.h>

static log_level_t g_level = LOG_LEVEL_INFO;

static const char *log_level_to_prefix(log_level_t level)
{
    switch (level) {
    case LOG_LEVEL_DEBUG:
        return "DEBUG";
    case LOG_LEVEL_INFO:
        return "INFO ";
    case LOG_LEVEL_WARN:
        return "WARN ";
    case LOG_LEVEL_ERROR:
    default:
        return "ERROR";
    }
}

static FILE *log_stream_for_level(log_level_t level)
{
    return (level <= LOG_LEVEL_WARN) ? stderr : stdout;
}

/*
 * log_set_level
 * new_level: Absolute severity filter. Messages above this level are dropped.
 */
void log_set_level(log_level_t new_level)
{
    if (new_level < LOG_LEVEL_ERROR) {
        new_level = LOG_LEVEL_ERROR;
    } else if (new_level > LOG_LEVEL_DEBUG) {
        new_level = LOG_LEVEL_DEBUG;
    }

    g_level = new_level;
}

/*
 * log_set_verbosity
 * verb_delta: Relative adjustment from default INFO (-2 => ERROR, -1 => WARN,
 *             0 => INFO, >=1 => DEBUG).
 */
void log_set_verbosity(int verb_delta)
{
    if (verb_delta <= -2) {
        log_set_level(LOG_LEVEL_ERROR);
        return;
    }

    if (verb_delta == -1) {
        log_set_level(LOG_LEVEL_WARN);
        return;
    }

    if (verb_delta >= 1) {
        log_set_level(LOG_LEVEL_DEBUG);
        return;
    }

    log_set_level(LOG_LEVEL_INFO);
}

/*
 * log_get_level
 * Returns the current severity filter. Helpful for tests/diagnostics.
 */
log_level_t log_get_level(void)
{
    return g_level;
}

/*
 * log_printf
 * level: Severity of this message.
 * fmt,...: Standard printf-style message body.
 * Behavior: Emits `LEVEL message\n` to stdout/stderr when permitted by the
 * current filter. Guarded against NULL format strings and respects
 * EINTR-signal-safe FILE API expectations by staying on stdio.
 */
void log_printf(log_level_t level, const char *fmt, ...)
{
    if (!fmt || level > g_level) {
        return;
    }

    FILE *stream = log_stream_for_level(level);
    const char *prefix = log_level_to_prefix(level);

    va_list ap;
    va_start(ap, fmt);
    fprintf(stream, "%s ", prefix);
    vfprintf(stream, fmt, ap);
    fputc('\n', stream);
    va_end(ap);
}
