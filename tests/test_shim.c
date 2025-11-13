// test_shim.c
// Purpose: Shared LD_PRELOAD helpers for the shell-based integration tests.
// Provides two hooks:
//   * recvmsg: Optionally flags datagrams as truncated when
//     EPOLL_ECHO_TEST_FORCE_TRUNC is set (with optional min size filter).
//   * clock_gettime/time: Scales CLOCK_REALTIME when
//     EPOLL_ECHO_TEST_TIME_SCALE>1 to fast-forward UDP stats aging tests.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef time_t (*time_fn)(time_t *);

static recvmsg_fn real_recvmsg = NULL;
static clock_gettime_fn real_clock_gettime = NULL;
static time_fn real_time_fn = NULL;

static int truncation_enabled = -1;
static ssize_t truncation_min = 0;

static int time_scale_factor = 0; /* 0 => uninitialized, 1 => passthrough */
static bool time_base_initialized = false;
static struct timespec time_base_real;
static struct timespec time_base_adjusted;

static void init_real_recvmsg(void)
{
    if (!real_recvmsg) {
        real_recvmsg = (recvmsg_fn)dlsym(RTLD_NEXT, "recvmsg");
    }
}

static void init_real_clock(void)
{
    if (!real_clock_gettime) {
        real_clock_gettime =
            (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");
    }
}

static void init_real_time(void)
{
    if (!real_time_fn) {
        real_time_fn = (time_fn)dlsym(RTLD_NEXT, "time");
    }
}

static void init_truncation_controls(void)
{
    if (truncation_enabled != -1) {
        return;
    }

    const char *flag = getenv("EPOLL_ECHO_TEST_FORCE_TRUNC");
    truncation_enabled = (flag && *flag && strcmp(flag, "0") != 0) ? 1 : 0;
    if (!truncation_enabled) {
        return;
    }

    const char *min_env = getenv("EPOLL_ECHO_TEST_TRUNC_MIN_BYTES");
    if (!min_env || !*min_env) {
        truncation_min = 0;
        return;
    }

    char *end = NULL;
    long long value = strtoll(min_env, &end, 10);
    if (end && *end == '\0' && value > 0) {
        truncation_min = (ssize_t)value;
    } else {
        truncation_min = 0;
    }
}

static void init_time_scale(void)
{
    if (time_scale_factor != 0) {
        return;
    }

    time_scale_factor = 1;
    const char *env = getenv("EPOLL_ECHO_TEST_TIME_SCALE");
    if (!env || !*env) {
        return;
    }

    char *end = NULL;
    long value = strtol(env, &end, 10);
    if (end && *end == '\0' && value > 1) {
        time_scale_factor = (int)value;
    }
}

static void apply_time_scaling(struct timespec *tp)
{
    if (!tp) {
        return;
    }

    init_time_scale();
    if (time_scale_factor <= 1) {
        return;
    }

    if (!time_base_initialized) {
        time_base_real = *tp;
        time_base_adjusted = *tp;
        time_base_initialized = true;
        return;
    }

    long sec_delta = tp->tv_sec - time_base_real.tv_sec;
    long nsec_delta = tp->tv_nsec - time_base_real.tv_nsec;
    if (nsec_delta < 0) {
        sec_delta -= 1;
        nsec_delta += 1000000000L;
    }

    long long scaled_sec = (long long)sec_delta * time_scale_factor;
    long long scaled_nsec = (long long)nsec_delta * time_scale_factor;

    scaled_sec += scaled_nsec / 1000000000LL;
    scaled_nsec %= 1000000000LL;
    if (scaled_nsec < 0) {
        scaled_nsec += 1000000000LL;
        scaled_sec -= 1;
    }

    long long new_sec = (long long)time_base_adjusted.tv_sec + scaled_sec;
    long long new_nsec = (long long)time_base_adjusted.tv_nsec + scaled_nsec;
    if (new_nsec >= 1000000000LL) {
        new_sec += 1;
        new_nsec -= 1000000000LL;
    }

    tp->tv_sec = (time_t)new_sec;
    tp->tv_nsec = (long)new_nsec;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    init_real_recvmsg();
    if (!real_recvmsg) {
        errno = ENOSYS;
        return -1;
    }

    ssize_t rc = real_recvmsg(sockfd, msg, flags);
    if (rc < 0 || !msg) {
        return rc;
    }

    init_truncation_controls();
    if (truncation_enabled == 1) {
        if (truncation_min <= 0 || rc >= truncation_min) {
            msg->msg_flags |= MSG_TRUNC;
        }
    }

    return rc;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
    init_real_clock();
    if (!real_clock_gettime) {
        errno = ENOSYS;
        return -1;
    }

    int rc = real_clock_gettime(clk_id, tp);
    if (rc == 0 && tp && clk_id == CLOCK_REALTIME) {
        apply_time_scaling(tp);
    }
    return rc;
}

time_t time(time_t *tloc)
{
    init_real_time();
    if (!real_time_fn) {
        errno = ENOSYS;
        return (time_t)-1;
    }

    time_t now = real_time_fn(NULL);
    struct timespec ts = {
        .tv_sec = now,
        .tv_nsec = 0,
    };
    apply_time_scaling(&ts);
    now = ts.tv_sec;

    if (tloc) {
        *tloc = now;
    }
    return now;
}
