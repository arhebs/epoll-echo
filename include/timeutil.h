/*
 * timeutil.h
 * Purpose: Declares the UTC time-formatting helpers shared by /time command
 * handlers and potential log messages. These helpers guarantee a consistent
 * `YYYY-MM-DD HH:MM:SS` layout derived from CLOCK_REALTIME in UTC.
 */

#ifndef EPOLL_ECHO_TIMEUTIL_H
#define EPOLL_ECHO_TIMEUTIL_H

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TIMEUTIL_TIMESTAMP_LEN 19
#define TIMEUTIL_TIMESTAMP_BUF_LEN (TIMEUTIL_TIMESTAMP_LEN + 1)

int timeutil_format_utc(char out[TIMEUTIL_TIMESTAMP_BUF_LEN]) EPOLL_ECHO_ATTR_NODISCARD;

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_TIMEUTIL_H */
