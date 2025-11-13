/*
 * timeutil.c
 * Purpose: Implements the UTC timestamp formatter used by /time responses
 * and any other user-facing timestamps. Ensures a consistent
 * `YYYY-MM-DD HH:MM:SS` string derived from CLOCK_REALTIME.
 */

#include "timeutil.h"

/*
 * timeutil_format_utc
 * out: Caller-provided buffer of TIMEUTIL_TIMESTAMP_BUF_LEN bytes.
 * Returns: 0 on success, -1 on failure with errno preserved.
 * Behavior: Fetches CLOCK_REALTIME, converts to UTC via gmtime_r, and formats
 *           the timestamp as "%F %T". Retries clock_gettime on EINTR to
 *           guard against signal interruptions between timerfd/signalfd ops.
 */
int timeutil_format_utc(char out[TIMEUTIL_TIMESTAMP_BUF_LEN])
{
    if (!out) {
        errno = EINVAL;
        return -1;
    }

    struct timespec ts;
    for (;;) {
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }

    struct tm tm_utc;
    if (!gmtime_r(&ts.tv_sec, &tm_utc)) {
        errno = EINVAL;
        return -1;
    }

    size_t written =
        strftime(out, TIMEUTIL_TIMESTAMP_BUF_LEN, "%F %T", &tm_utc);
    if (written != TIMEUTIL_TIMESTAMP_LEN) {
        errno = EOVERFLOW;
        return -1;
    }

    return 0;
}
