/*
 * loop.c
 * Purpose: Implements the epoll-backed event loop along with helpers to
 * register, modify, and remove descriptors. This module owns the epoll fd,
 * dispatches readiness notifications to module-provided callbacks, and
 * manages lifecycle edge cases such as deleting descriptors from inside the
 * callback that is currently executing.
 */

#include "loop.h"

#include "common.h"
#include "log.h"

#include <errno.h>
#include <string.h>

#define LOOP_EPOLL_MAX_EVENTS 64
#define LOOP_SOURCE_MIN_CAP 16

struct loop_source {
    int fd;
    uint32_t events;
    loop_event_cb callback;
    void *userdata;
    bool in_callback;
    bool pending_delete;
    bool destroy_enqueued;
};

struct loop_context {
    int epoll_fd;
    int wake_fd;
    int signal_fd;
    int timer_fd;
    bool should_exit;
    bool shutdown_requested;
    bool running;
    bool processing_batch;
    bool signal_mask_installed;
    sigset_t signal_mask;
    sigset_t signal_mask_prev;
    loop_on_tick_cb tick_hook;
    void *tick_userdata;
    struct epoll_event *event_buf;
    size_t event_buf_len;
    struct loop_source **sources;
    size_t sources_len;
    struct loop_source **deferred;
    size_t deferred_len;
    size_t deferred_cap;
};

static struct loop_source *loop_lookup_source(struct loop_context *ctx, int fd);
static int loop_ensure_capacity(struct loop_context *ctx, int fd);
static void loop_destroy_source(struct loop_source *source);
static const char *loop_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN]);
static void loop_wakeup_cb(struct loop_context *ctx,
                           int fd,
                           uint32_t events,
                           void *userdata);
static int loop_setup_wakeup(struct loop_context *ctx);
static int loop_setup_signals(struct loop_context *ctx);
static void loop_signal_cb(struct loop_context *ctx,
                           int fd,
                           uint32_t events,
                           void *userdata);
static void loop_process_signal_info(struct loop_context *ctx,
                                     const struct signalfd_siginfo *info);
static void loop_cleanup_signals(struct loop_context *ctx);
static void loop_restore_signal_mask(struct loop_context *ctx);
static int loop_setup_timer(struct loop_context *ctx);
static void loop_timer_cb(struct loop_context *ctx,
                          int fd,
                          uint32_t events,
                          void *userdata);
static void loop_dispatch_tick(struct loop_context *ctx, uint64_t expirations);
static void loop_cleanup_timer(struct loop_context *ctx);
static uint64_t loop_now_epoch_sec(void);
static void loop_schedule_destroy(struct loop_context *ctx,
                                  struct loop_source *source);
static int loop_deferred_push(struct loop_context *ctx,
                              struct loop_source *source);
static void loop_flush_deferred(struct loop_context *ctx);

static void loop_wakeup_cb(struct loop_context *ctx,
                           int fd,
                           uint32_t events,
                           void *userdata)
{
    (void)ctx;
    (void)userdata;

    if (events & EPOLLIN) {
        for (;;) {
            uint64_t value;
            ssize_t rc = read(fd, &value, sizeof(value));
            if (rc == (ssize_t)sizeof(value)) {
                break; /* Counter drained; epoll readiness cleared. */
            }
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc < 0 && errno == EAGAIN) {
                break;
            }
            if (rc < 0) {
                char errbuf[EPOLL_ECHO_ERRBUF_LEN];
                LOG_WARN("loop wake read failed: %s", loop_errstr(errno, errbuf));
            }
            break;
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        LOG_WARN("loop wake fd received events %#x", events);
    }
}

static int loop_setup_wakeup(struct loop_context *ctx)
{
    ctx->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->wake_fd < 0) {
        return -1;
    }

    if (loop_add(ctx, ctx->wake_fd, EPOLLIN, loop_wakeup_cb, NULL) != 0) {
        int err = errno;
        epoll_echo_close_fd(&ctx->wake_fd);
        errno = err;
        return -1;
    }

    return 0;
}

static void loop_restore_signal_mask(struct loop_context *ctx)
{
    if (!ctx || !ctx->signal_mask_installed) {
        return;
    }

    if (sigprocmask(SIG_SETMASK, &ctx->signal_mask_prev, NULL) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("failed to restore signal mask: %s", loop_errstr(errno, errbuf));
    }

    ctx->signal_mask_installed = false;
}

static void loop_cleanup_signals(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->signal_fd >= 0) {
        (void)loop_del(ctx, ctx->signal_fd);
        epoll_echo_close_fd(&ctx->signal_fd);
    }

    loop_restore_signal_mask(ctx);
}

static void loop_process_signal_info(struct loop_context *ctx,
                                     const struct signalfd_siginfo *info)
{
    if (!ctx || !info) {
        return;
    }

    int signo = (int)info->ssi_signo;
    if (signo == SIGINT || signo == SIGTERM) {
        const char *name = strsignal(signo);
        LOG_INFO("received %s (%d); initiating shutdown",
                 name ? name : "signal", signo);
        loop_request_shutdown(ctx);
        return;
    }

    LOG_WARN("signalfd delivered unexpected signal %d", signo);
}

static void loop_signal_cb(struct loop_context *ctx,
                           int fd,
                           uint32_t events,
                           void *userdata)
{
    (void)userdata;

    if (!ctx) {
        return;
    }

    if (events & EPOLLIN) {
        for (;;) {
            struct signalfd_siginfo info;
            ssize_t rc = read(fd, &info, sizeof(info));
            if (rc == (ssize_t)sizeof(info)) {
                loop_process_signal_info(ctx, &info);
                continue;
            }
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc < 0 && epoll_echo_errno_would_block(errno)) {
                break;
            }
            if (rc == 0) {
                LOG_WARN("signalfd read returned 0 bytes");
                break;
            }
            if (rc > 0 && rc < (ssize_t)sizeof(info)) {
                LOG_WARN("signalfd short read (%zd bytes)", rc);
                break;
            }
            if (rc < 0) {
                char errbuf[EPOLL_ECHO_ERRBUF_LEN];
                LOG_WARN("signalfd read failed: %s", loop_errstr(errno, errbuf));
                break;
            }
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        LOG_WARN("signalfd fd=%d reported events %#x", fd, events);
    }
}

static int loop_setup_signals(struct loop_context *ctx)
{
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }

    sigset_t mask;
    if (sigemptyset(&mask) != 0) {
        return -1;
    }
    if (sigaddset(&mask, SIGINT) != 0) {
        return -1;
    }
    if (sigaddset(&mask, SIGTERM) != 0) {
        return -1;
    }

    sigset_t prev_mask;
    if (sigprocmask(SIG_BLOCK, &mask, &prev_mask) != 0) {
        return -1;
    }

    ctx->signal_mask = mask;
    ctx->signal_mask_prev = prev_mask;
    ctx->signal_mask_installed = true;

    ctx->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (ctx->signal_fd < 0) {
        int err = errno;
        loop_restore_signal_mask(ctx);
        errno = err;
        return -1;
    }

    if (loop_add(ctx, ctx->signal_fd, EPOLLIN, loop_signal_cb, NULL) != 0) {
        int err = errno;
        epoll_echo_close_fd(&ctx->signal_fd);
        loop_restore_signal_mask(ctx);
        errno = err;
        return -1;
    }

    return 0;
}

static void loop_cleanup_timer(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->timer_fd >= 0) {
        (void)loop_del(ctx, ctx->timer_fd);
        epoll_echo_close_fd(&ctx->timer_fd);
    }
}

static uint64_t loop_now_epoch_sec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)ts.tv_sec;
    }

    char errbuf[EPOLL_ECHO_ERRBUF_LEN];
    LOG_WARN("clock_gettime(CLOCK_REALTIME) failed: %s", loop_errstr(errno, errbuf));

    time_t fallback = time(NULL);
    if (fallback < 0) {
        fallback = 0;
    }
    return (uint64_t)fallback;
}

static void loop_dispatch_tick(struct loop_context *ctx, uint64_t expirations)
{
    if (!ctx || !ctx->tick_hook || expirations == 0) {
        return;
    }

    loop_on_tick_cb hook = ctx->tick_hook;
    void *userdata = ctx->tick_userdata;

    for (uint64_t i = 0; i < expirations; ++i) {
        hook(ctx, loop_now_epoch_sec(), userdata);
    }
}

static void loop_timer_cb(struct loop_context *ctx,
                          int fd,
                          uint32_t events,
                          void *userdata)
{
    (void)userdata;

    if (!ctx) {
        return;
    }

    if (events & EPOLLIN) {
        for (;;) {
            uint64_t expirations = 0;
            ssize_t rc = read(fd, &expirations, sizeof(expirations));
            if (rc == (ssize_t)sizeof(expirations)) {
                loop_dispatch_tick(ctx, expirations);
                break;
            }
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc < 0 && epoll_echo_errno_would_block(errno)) {
                break;
            }
            if (rc == 0) {
                LOG_WARN("timerfd read returned 0 bytes");
                break;
            }
            if (rc > 0 && rc < (ssize_t)sizeof(expirations)) {
                LOG_WARN("timerfd short read (%zd bytes)", rc);
                break;
            }

            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_WARN("timerfd read failed: %s", loop_errstr(errno, errbuf));
            break;
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        LOG_WARN("timerfd fd=%d reported events %#x", fd, events);
    }
}

static int loop_setup_timer(struct loop_context *ctx)
{
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }

    ctx->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ctx->timer_fd < 0) {
        return -1;
    }

    struct itimerspec spec = {
        .it_interval =
            {
                .tv_sec = EPOLL_ECHO_TIMER_TICK_SEC,
                .tv_nsec = 0,
            },
        .it_value =
            {
                .tv_sec = EPOLL_ECHO_TIMER_TICK_SEC,
                .tv_nsec = 0,
            },
    };

    if (timerfd_settime(ctx->timer_fd, 0, &spec, NULL) != 0) {
        int err = errno;
        epoll_echo_close_fd(&ctx->timer_fd);
        errno = err;
        return -1;
    }

    if (loop_add(ctx, ctx->timer_fd, EPOLLIN, loop_timer_cb, NULL) != 0) {
        int err = errno;
        epoll_echo_close_fd(&ctx->timer_fd);
        errno = err;
        return -1;
    }

    return 0;
}
int loop_init(struct loop_context **ctx_out)
{
    if (!ctx_out) {
        errno = EINVAL;
        return -1;
    }

    struct loop_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }

    ctx->wake_fd = -1;
    ctx->signal_fd = -1;
    ctx->timer_fd = -1;
    int saved_errno = 0;

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        saved_errno = errno;
        goto fail;
    }

    ctx->event_buf_len = LOOP_EPOLL_MAX_EVENTS;
    ctx->event_buf = calloc(ctx->event_buf_len, sizeof(*ctx->event_buf));
    if (!ctx->event_buf) {
        saved_errno = errno;
        goto fail;
    }

    ctx->sources = NULL;
    ctx->sources_len = 0;
    ctx->deferred = NULL;
    ctx->deferred_len = 0;
    ctx->deferred_cap = 0;

    if (loop_setup_wakeup(ctx) != 0) {
        saved_errno = errno;
        goto fail;
    }

    if (loop_setup_signals(ctx) != 0) {
        saved_errno = errno;
        goto fail;
    }

    if (loop_setup_timer(ctx) != 0) {
        saved_errno = errno;
        goto fail;
    }

    *ctx_out = ctx;
    return 0;

fail:
    loop_cleanup_timer(ctx);
    loop_cleanup_signals(ctx);
    if (ctx->sources) {
        for (size_t i = 0; i < ctx->sources_len; ++i) {
            loop_destroy_source(ctx->sources[i]);
        }
        free(ctx->sources);
    }
    free(ctx->event_buf);
    free(ctx->deferred);
    epoll_echo_close_fd(&ctx->wake_fd);
    epoll_echo_close_fd(&ctx->epoll_fd);
    free(ctx);
    errno = saved_errno;
    return -1;
}

int loop_add(struct loop_context *ctx,
             int fd,
             uint32_t events,
             loop_event_cb cb,
             void *userdata)
{
    if (!ctx || fd < 0 || events == 0 || !cb) {
        errno = EINVAL;
        return -1;
    }

    if (loop_lookup_source(ctx, fd)) {
        errno = EEXIST;
        return -1;
    }

    if (loop_ensure_capacity(ctx, fd) != 0) {
        return -1;
    }

    struct loop_source *source = calloc(1, sizeof(*source));
    if (!source) {
        return -1;
    }

    source->fd = fd;
    source->events = events;
    source->callback = cb;
    source->userdata = userdata;

    struct epoll_event ev = {
        .events = events,
        .data.ptr = source,
    };

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        int err = errno;
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_ERROR("epoll_ctl ADD(fd=%d) failed: %s", fd, loop_errstr(err, errbuf));
        free(source);
        errno = err;
        return -1;
    }

    ctx->sources[fd] = source;
    return 0;
}

int loop_mod(struct loop_context *ctx, int fd, uint32_t events)
{
    if (!ctx || fd < 0 || events == 0) {
        errno = EINVAL;
        return -1;
    }

    struct loop_source *source = loop_lookup_source(ctx, fd);
    if (!source) {
        errno = ENOENT;
        return -1;
    }

    source->events = events;

    struct epoll_event ev = {
        .events = events,
        .data.ptr = source,
    };

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        int err = errno;
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_ERROR("epoll_ctl MOD(fd=%d) failed: %s", fd, loop_errstr(err, errbuf));
        errno = err;
        return -1;
    }

    return 0;
}

int loop_del(struct loop_context *ctx, int fd)
{
    if (!ctx || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    struct loop_source *source = loop_lookup_source(ctx, fd);
    if (!source) {
        errno = ENOENT;
        return -1;
    }

    struct epoll_event ev = {
        .events = source->events,
        .data.ptr = source,
    };

    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, &ev) != 0) {
        int err = errno;
        if (err != EBADF && err != ENOENT) {
            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_WARN("epoll_ctl DEL(fd=%d) failed: %s", fd, loop_errstr(err, errbuf));
            errno = err;
            return -1;
        }
        errno = 0;
    }

    ctx->sources[fd] = NULL;
    loop_schedule_destroy(ctx, source);
    return 0;
}

void loop_run(struct loop_context *ctx)
{
    if (!ctx || ctx->epoll_fd < 0 || !ctx->event_buf) {
        return;
    }

    ctx->running = true;

    while (!ctx->should_exit) {
        int ready = epoll_wait(ctx->epoll_fd,
                               ctx->event_buf,
                               (int)ctx->event_buf_len,
                               -1);

        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }

            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_ERROR("epoll_wait failed: %s", loop_errstr(errno, errbuf));
            ctx->processing_batch = false;
            break;
        }

        ctx->processing_batch = (ready > 0);

        if (ready == 0) {
            ctx->processing_batch = false;
            continue;
        }

        ctx->deferred_len = 0;

        for (int i = 0; i < ready; ++i) {
            struct epoll_event *ev = &ctx->event_buf[i];
            struct loop_source *source = ev->data.ptr;
            if (!source || !source->callback) {
                continue;
            }

            if (source->pending_delete) {
                loop_schedule_destroy(ctx, source);
                continue;
            }

            source->in_callback = true;
            source->callback(ctx, source->fd, ev->events, source->userdata);
            source->in_callback = false;

            if (source->pending_delete) {
                loop_schedule_destroy(ctx, source);
            }
        }

        ctx->processing_batch = false;
        loop_flush_deferred(ctx);
    }

    ctx->running = false;
    loop_flush_deferred(ctx);
}

void loop_shutdown(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    ctx->should_exit = true;

    if (ctx->wake_fd >= 0) {
        uint64_t one = 1;
        ssize_t rc;
        do {
            rc = write(ctx->wake_fd, &one, sizeof(one));
        } while (rc < 0 && errno == EINTR);

        if (rc < 0 && errno != EAGAIN) {
            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_WARN("loop wake signal failed: %s", loop_errstr(errno, errbuf));
        }
    }
}

void loop_request_shutdown(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (!ctx->shutdown_requested) {
        ctx->shutdown_requested = true;
    }

    loop_shutdown(ctx);
}

bool loop_shutdown_requested(const struct loop_context *ctx)
{
    return ctx ? ctx->shutdown_requested : false;
}

void loop_set_tick_hook(struct loop_context *ctx,
                        loop_on_tick_cb hook,
                        void *userdata)
{
    if (!ctx) {
        return;
    }

    ctx->tick_hook = hook;
    ctx->tick_userdata = hook ? userdata : NULL;
}

void loop_free(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    ctx->should_exit = true;

    if (ctx->wake_fd >= 0) {
        (void)loop_del(ctx, ctx->wake_fd);
        epoll_echo_close_fd(&ctx->wake_fd);
    }

    loop_cleanup_timer(ctx);
    loop_cleanup_signals(ctx);

    if (ctx->sources) {
        for (size_t i = 0; i < ctx->sources_len; ++i) {
            if (ctx->sources[i]) {
                loop_destroy_source(ctx->sources[i]);
            }
        }
        free(ctx->sources);
    }

    loop_flush_deferred(ctx);
    free(ctx->deferred);

    free(ctx->event_buf);
    epoll_echo_close_fd(&ctx->epoll_fd);
    free(ctx);
}

static struct loop_source *loop_lookup_source(struct loop_context *ctx, int fd)
{
    if (!ctx || fd < 0) {
        return NULL;
    }

    size_t index = (size_t)fd;
    if (index >= ctx->sources_len) {
        return NULL;
    }

    return ctx->sources[index];
}

static int loop_ensure_capacity(struct loop_context *ctx, int fd)
{
    size_t needed = (size_t)fd + 1;
    if (needed <= ctx->sources_len) {
        return 0;
    }

    size_t new_len = ctx->sources_len ? ctx->sources_len : LOOP_SOURCE_MIN_CAP;
    while (new_len < needed) {
        if (new_len > SIZE_MAX / 2) {
            errno = ENOMEM;
            return -1;
        }
        new_len *= 2;
    }

    if (new_len > SIZE_MAX / sizeof(*ctx->sources)) {
        errno = ENOMEM;
        return -1;
    }

    struct loop_source **tmp = realloc(ctx->sources,
                                       new_len * sizeof(*ctx->sources));
    if (!tmp) {
        return -1;
    }

    for (size_t i = ctx->sources_len; i < new_len; ++i) {
        tmp[i] = NULL;
    }

    ctx->sources = tmp;
    ctx->sources_len = new_len;
    return 0;
}

static void loop_destroy_source(struct loop_source *source)
{
    if (!source) {
        return;
    }

    memset(source, 0, sizeof(*source));
    free(source);
}

static void loop_schedule_destroy(struct loop_context *ctx,
                                  struct loop_source *source)
{
    if (!source) {
        return;
    }

    source->pending_delete = true;

    if (!ctx || (!ctx->processing_batch && !source->in_callback)) {
        loop_destroy_source(source);
        return;
    }

    if (source->destroy_enqueued) {
        return;
    }

    if (loop_deferred_push(ctx, source) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_ERROR("loop deferred free failed: %s", loop_errstr(errno, errbuf));
        if (!source->in_callback && !ctx->processing_batch) {
            loop_destroy_source(source);
        }
        return;
    }

    source->destroy_enqueued = true;
}

static const char *loop_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN])
{
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    char *msg = strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN);
    return msg ? msg : "(unknown error)";
#else
    if (strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN) != 0) {
        snprintf(buf, EPOLL_ECHO_ERRBUF_LEN, "errno=%d", err);
    }
    return buf;
#endif
}

static int loop_deferred_push(struct loop_context *ctx,
                              struct loop_source *source)
{
    if (!ctx) {
        errno = EINVAL;
        return -1;
    }

    if (ctx->deferred_len == ctx->deferred_cap) {
        size_t new_cap = ctx->deferred_cap ? ctx->deferred_cap * 2 : LOOP_SOURCE_MIN_CAP;
        struct loop_source **tmp = realloc(ctx->deferred,
                                           new_cap * sizeof(*ctx->deferred));
        if (!tmp) {
            return -1;
        }
        ctx->deferred = tmp;
        ctx->deferred_cap = new_cap;
    }

    ctx->deferred[ctx->deferred_len++] = source;
    return 0;
}

static void loop_flush_deferred(struct loop_context *ctx)
{
    if (!ctx) {
        return;
    }

    size_t write_idx = 0;
    for (size_t i = 0; i < ctx->deferred_len; ++i) {
        struct loop_source *source = ctx->deferred[i];
        if (!source) {
            continue;
        }

        if (source->in_callback) {
            ctx->deferred[write_idx++] = source;
            continue;
        }

        source->destroy_enqueued = false;
        loop_destroy_source(source);
    }

    ctx->deferred_len = write_idx;
}
