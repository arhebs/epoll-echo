/*
 * common.h
 * Purpose: Provides process-wide constants, utility macros, and lightweight
 * inline helpers that are shared across the epoll-echo modules. Keeping these
 * helpers here ensures consistent defaults (ports, limits, timing) and avoids
 * duplicating defensive idioms such as close-with-retry semantics.
 */

#ifndef EPOLL_ECHO_COMMON_H
#define EPOLL_ECHO_COMMON_H

#include "platform.h"

#define EPOLL_ECHO_PROGRAM_NAME "epoll-echo"
#define EPOLL_ECHO_CREDENTIALS_DIR_ENV "CREDENTIALS_DIRECTORY"
#define EPOLL_ECHO_CREDENTIAL_TOKEN_BASENAME "shutdown.token"

#define EPOLL_ECHO_DEFAULT_PORT 12345
#define EPOLL_ECHO_DEFAULT_BACKLOG 128
#define EPOLL_ECHO_DEFAULT_MAX_TCP 1024
#define EPOLL_ECHO_DEFAULT_MAX_LINE 4096
#define EPOLL_ECHO_TCP_WQ_LIMIT_BYTES ((size_t)64 * 1024) /* per-conn cap */

#define EPOLL_ECHO_UDP_PEER_WINDOW_SEC 60
#define EPOLL_ECHO_TIMER_TICK_SEC 1
#define EPOLL_ECHO_ERRBUF_LEN 128

#define EPOLL_ECHO_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

#define EPOLL_ECHO_MIN(a, b)                                                \
    ({                                                                      \
        __typeof__(a) _min_a = (a);                                         \
        __typeof__(b) _min_b = (b);                                         \
        _min_a < _min_b ? _min_a : _min_b;                                  \
    })

#define EPOLL_ECHO_MAX(a, b)                                                \
    ({                                                                      \
        __typeof__(a) _max_a = (a);                                         \
        __typeof__(b) _max_b = (b);                                         \
        _max_a > _max_b ? _max_a : _max_b;                                  \
    })

#define EPOLL_ECHO_CLAMP(val, lo, hi)                                       \
    ({                                                                      \
        __typeof__(val) _clamp_val = (val);                                 \
        __typeof__(lo) _clamp_lo = (lo);                                    \
        __typeof__(hi) _clamp_hi = (hi);                                    \
        _clamp_val < _clamp_lo ? _clamp_lo                                  \
                               : (_clamp_val > _clamp_hi ? _clamp_hi        \
                                                        : _clamp_val);      \
    })

#define EPOLL_ECHO_BITMASK(width)                                           \
    ({                                                                      \
        __typeof__(width) _mask_w = (width);                                \
        _mask_w >= 64 ? UINT64_MAX : ((1ULL << _mask_w) - 1ULL);            \
    })

/*
 * epoll_echo_close_fd
 * Input:
 *   fd - Pointer to an integer file descriptor that may currently refer to an
 *        open kernel object. Safe to pass NULL.
 * Output:
 *   Ensures the descriptor is closed (retrying on EINTR) and stores -1 back
 *   into the pointed-to variable so callers cannot accidentally reuse it.
 * Notes:
 *   - Intended for shutdown paths where best-effort cleanup is sufficient.
 *   - Errors other than EINTR are ignored because the descriptor is considered
 *     defunct either way.
 */
static inline void epoll_echo_close_fd(int *fd)
{
    if (fd == NULL || *fd < 0) {
        return;
    }

    for (;;) {
        if (close(*fd) == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }

    *fd = -1;
}

/*
 * epoll_echo_errno_would_block
 * Input:
 *   err - errno value captured immediately after a syscall failure.
 * Returns:
 *   true when the error indicates that the operation would block on a
 *   non-blocking descriptor (EAGAIN/EWOULDBLOCK); false otherwise.
 * Notes:
 *   Centralizing this logic reduces duplicated conditionals sprinkled across
 *   the I/O loops and makes the intended retry semantics obvious.
 */
static inline bool epoll_echo_errno_would_block(int err)
{
    return err == EAGAIN || err == EWOULDBLOCK;
}

/*
 * epoll_echo_errno_retryable
 * Input:
 *   err - errno captured from a syscall.
 * Returns:
 *   true when the operation should be retried immediately (currently EINTR).
 */
static inline bool epoll_echo_errno_retryable(int err)
{
    return err == EINTR;
}

/*
 * struct epoll_echo_config
 * Purpose: Captures CLI-derived configuration knobs for the daemon so that
 * the parsed values can be handed to the networking modules after argument
 * validation. The structure intentionally mirrors the top-level flags from
 * PROJECT_REQUEST.md to keep the translation logic trivial.
 */
struct epoll_echo_config {
    uint16_t tcp_port;          /* TCP listener port (0 => kernel assigned). */
    uint16_t udp_port;          /* UDP listener port (0 => kernel assigned). */
    int backlog;                /* listen(2) backlog hint. */
    uint32_t max_tcp;           /* Maximum concurrent TCP clients. */
    size_t max_line;            /* Per-line limit enforced by TCP parser. */
    int verbosity_delta;        /* Relative adjustment for log verbosity. */
    char *shutdown_token_file;  /* Optional file path holding the token. */
};

/*
 * epoll_echo_config_init
 * cfg: Output pointer that receives the default CLI state.
 * Effect: Seeds sensible defaults so parse_cli() can selectively override
 *         fields without worrying about uninitialized data.
 */
static inline void epoll_echo_config_init(struct epoll_echo_config *cfg)
{
    if (!cfg) {
        return;
    }

    cfg->tcp_port = EPOLL_ECHO_DEFAULT_PORT;
    cfg->udp_port = EPOLL_ECHO_DEFAULT_PORT;
    cfg->backlog = EPOLL_ECHO_DEFAULT_BACKLOG;
    cfg->max_tcp = EPOLL_ECHO_DEFAULT_MAX_TCP;
    cfg->max_line = EPOLL_ECHO_DEFAULT_MAX_LINE;
    cfg->verbosity_delta = 0;
    cfg->shutdown_token_file = NULL;
}

/*
 * epoll_echo_config_reset
 * cfg: Configuration structure to sanitize (nullable).
 * Effect: Releases heap-backed members so repeated parse attempts or orderly
 *         shutdown paths do not leak the token file path.
 */
static inline void epoll_echo_config_reset(struct epoll_echo_config *cfg)
{
    if (!cfg) {
        return;
    }

    free(cfg->shutdown_token_file);
    cfg->shutdown_token_file = NULL;
}

#endif /* EPOLL_ECHO_COMMON_H */
