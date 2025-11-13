/*
 * net.c
 * Purpose: Implements the networking helpers that create the TCP/UDP listening
 * sockets for epoll-echo. Handles dual-stack (IPv6 + IPv4 fallback) policy,
 * enforces non-blocking/close-on-exec semantics, and exposes opaque listener
 * handles that higher-level modules can register with epoll.
 */

#include "net.h"

#include "log.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NET_LISTENER_MAX_FDS 2

static struct net_listener *net_prebound_tcp;
static struct net_listener *net_prebound_udp;

struct net_listener_fd {
    int fd;
    bool is_ipv6;
};

struct net_listener {
    net_listener_kind_t kind;
    uint16_t port;
    bool dual_stack;
    size_t fd_count;
    struct net_listener_fd fd_entries[NET_LISTENER_MAX_FDS];
};

static struct net_listener *net_listener_alloc(net_listener_kind_t kind);
static int net_listener_add_fd(struct net_listener *listener, int fd, bool is_ipv6);
static struct net_listener **net_prebound_slot(net_listener_kind_t kind);
static struct net_listener *net_listener_take_prebound(net_listener_kind_t kind);
static void net_close_all_fds(const int fds[], size_t fd_count);
static void net_close_unclaimed_fds(const int fds[],
                                    const bool claimed[],
                                    size_t fd_count);
static const char *net_kind_label(net_listener_kind_t kind);
static const char *net_strerror(int err, char buf[EPOLL_ECHO_ERRBUF_LEN]);
static int net_make_socket(int family, int type, int protocol);
static int net_apply_common_opts(int fd);
static bool net_try_disable_v6only(int fd);
static int net_bind_ipv6(int fd, uint16_t port);
static int net_bind_ipv4(int fd, uint16_t port);
static int net_finish_socket(int fd, bool is_udp, int backlog);
static int net_query_bound_port(int fd, uint16_t *port_out);
static int net_open_ipv6_listener(uint16_t port,
                                  bool is_udp,
                                  int backlog,
                                  uint16_t *port_out,
                                  bool *dual_stack,
                                  int socktype,
                                  int protocol);
static int net_open_ipv4_listener(uint16_t port,
                                  bool is_udp,
                                  int backlog,
                                  uint16_t *port_out,
                                  int socktype,
                                  int protocol);
static int net_setup_listener(struct net_listener *listener,
                              uint16_t requested_port,
                              int backlog,
                              bool is_udp);
static void net_log_listener(const struct net_listener *listener,
                             bool is_ipv6,
                             bool fallback);
static int net_listener_apply_fd_flags(int fd);
static int net_listener_extract_inet_info(int fd,
                                          bool *is_ipv6_out,
                                          uint16_t *port_out,
                                          bool *dual_stack_candidate);

/*
 * net_tcp_config_init
 * cfg: Output pointer for TCP defaults.
 */
void net_tcp_config_init(struct net_tcp_config *cfg)
{
    if (!cfg) {
        return;
    }

    cfg->port = EPOLL_ECHO_DEFAULT_PORT;
    cfg->backlog = EPOLL_ECHO_DEFAULT_BACKLOG;
}

/*
 * net_udp_config_init
 * cfg: Output pointer for UDP defaults.
 */
void net_udp_config_init(struct net_udp_config *cfg)
{
    if (!cfg) {
        return;
    }

    cfg->port = EPOLL_ECHO_DEFAULT_PORT;
}

/*
 * net_listener_create_tcp
 * Creates a TCP listener honoring backlog/dual-stack requirements.
 */
int net_listener_create_tcp(const struct net_tcp_config *cfg,
                            struct net_listener **listener_out)
{
    if (!cfg || !listener_out) {
        errno = EINVAL;
        return -1;
    }

    struct net_listener *prebound = net_listener_take_prebound(NET_LISTENER_TCP);
    if (prebound) {
        *listener_out = prebound;
        return 0;
    }

    struct net_listener *listener = net_listener_alloc(NET_LISTENER_TCP);
    if (!listener) {
        return -1;
    }

    int backlog = cfg->backlog > 0 ? cfg->backlog : EPOLL_ECHO_DEFAULT_BACKLOG;

    if (net_setup_listener(listener, cfg->port, backlog, false) != 0) {
        int saved = errno;
        net_listener_destroy(listener);
        errno = saved;
        return -1;
    }

    *listener_out = listener;
    return 0;
}

/*
 * net_listener_create_udp
 * Creates a UDP listener with the same dual-stack fallback behavior.
 */
int net_listener_create_udp(const struct net_udp_config *cfg,
                            struct net_listener **listener_out)
{
    if (!cfg || !listener_out) {
        errno = EINVAL;
        return -1;
    }

    struct net_listener *prebound = net_listener_take_prebound(NET_LISTENER_UDP);
    if (prebound) {
        *listener_out = prebound;
        return 0;
    }

    struct net_listener *listener = net_listener_alloc(NET_LISTENER_UDP);
    if (!listener) {
        return -1;
    }

    if (net_setup_listener(listener, cfg->port, 0, true) != 0) {
        int saved = errno;
        net_listener_destroy(listener);
        errno = saved;
        return -1;
    }

    *listener_out = listener;
    return 0;
}

/*
 * net_listener_fd_count
 */
size_t net_listener_fd_count(const struct net_listener *listener)
{
    return listener ? listener->fd_count : 0;
}

/*
 * net_listener_fd_at
 */
int net_listener_fd_at(const struct net_listener *listener, size_t index)
{
    if (!listener || index >= listener->fd_count) {
        errno = EINVAL;
        return -1;
    }

    return listener->fd_entries[index].fd;
}

/*
 * net_listener_port
 */
uint16_t net_listener_port(const struct net_listener *listener)
{
    return listener ? listener->port : 0;
}

/*
 * net_listener_kind
 */
net_listener_kind_t net_listener_kind(const struct net_listener *listener)
{
    return listener ? listener->kind : NET_LISTENER_TCP;
}

/*
 * net_listener_has_dual_stack
 */
bool net_listener_has_dual_stack(const struct net_listener *listener)
{
    return listener ? listener->dual_stack : false;
}

/*
 * net_listener_close
 */
void net_listener_close(struct net_listener *listener)
{
    if (!listener) {
        return;
    }

    for (size_t i = 0; i < listener->fd_count; ++i) {
        epoll_echo_close_fd(&listener->fd_entries[i].fd);
    }
}

/*
 * net_listener_destroy
 */
void net_listener_destroy(struct net_listener *listener)
{
    if (!listener) {
        return;
    }

    net_listener_close(listener);
    free(listener);
}

static struct net_listener **net_prebound_slot(net_listener_kind_t kind)
{
    return (kind == NET_LISTENER_UDP) ? &net_prebound_udp : &net_prebound_tcp;
}

static struct net_listener *net_listener_take_prebound(net_listener_kind_t kind)
{
    struct net_listener **slot = net_prebound_slot(kind);
    struct net_listener *listener = *slot;
    *slot = NULL;
    return listener;
}

int net_listener_register_prebound(struct net_listener *listener)
{
    if (!listener) {
        errno = EINVAL;
        return -1;
    }

    struct net_listener **slot = net_prebound_slot(listener->kind);
    if (*slot) {
        errno = EEXIST;
        return -1;
    }

    *slot = listener;
    return 0;
}

static void net_close_all_fds(const int fds[], size_t fd_count)
{
    if (!fds) {
        return;
    }

    for (size_t i = 0; i < fd_count; ++i) {
        int tmp = fds[i];
        epoll_echo_close_fd(&tmp);
    }
}

static void net_close_unclaimed_fds(const int fds[],
                                    const bool claimed[],
                                    size_t fd_count)
{
    if (!fds || !claimed) {
        return;
    }

    for (size_t i = 0; i < fd_count; ++i) {
        if (!claimed[i]) {
            int tmp = fds[i];
            epoll_echo_close_fd(&tmp);
        }
    }
}

int net_listener_adopt_inet(net_listener_kind_t kind,
                            const int fds[],
                            size_t fd_count,
                            struct net_listener **listener_out)
{
    if (!fds || !listener_out || fd_count == 0) {
        errno = EINVAL;
        return -1;
    }

    if (fd_count > NET_LISTENER_MAX_FDS) {
        errno = E2BIG;
        net_close_all_fds(fds, fd_count);
        return -1;
    }

    struct net_listener *listener = net_listener_alloc(kind);
    if (!listener) {
        net_close_all_fds(fds, fd_count);
        return -1;
    }

    bool claimed[NET_LISTENER_MAX_FDS];
    memset(claimed, 0, sizeof(claimed));
    bool saw_ipv4 = false;
    bool saw_ipv6 = false;
    bool dual_stack_candidate = false;
    bool port_set = false;
    uint16_t bound_port = 0;

    for (size_t i = 0; i < fd_count; ++i) {
        if (net_listener_apply_fd_flags(fds[i]) != 0) {
            goto fail;
        }

        bool is_ipv6 = false;
        uint16_t fd_port = 0;
        if (net_listener_extract_inet_info(fds[i],
                                           &is_ipv6,
                                           &fd_port,
                                           &dual_stack_candidate) != 0) {
            goto fail;
        }

        if (!port_set) {
            bound_port = fd_port;
            port_set = true;
        } else if (bound_port != fd_port) {
            errno = EINVAL;
            goto fail;
        }

        if (net_listener_add_fd(listener, fds[i], is_ipv6) != 0) {
            goto fail;
        }

        claimed[i] = true;
        if (is_ipv6) {
            saw_ipv6 = true;
        } else {
            saw_ipv4 = true;
        }
    }

    if (!port_set) {
        errno = EINVAL;
        goto fail;
    }

    listener->port = bound_port;
    listener->dual_stack = dual_stack_candidate && !saw_ipv4;

    if (saw_ipv6) {
        net_log_listener(listener, true, saw_ipv4);
    }
    if (saw_ipv4) {
        net_log_listener(listener, false, saw_ipv6);
    }

    *listener_out = listener;
    return 0;

fail:
    {
        int saved = errno;
        net_listener_destroy(listener);
        net_close_unclaimed_fds(fds, claimed, fd_count);
        errno = saved;
    }
    return -1;
}

/*
 * net_listener_alloc
 * Allocates and initializes a listener container.
 */
static struct net_listener *net_listener_alloc(net_listener_kind_t kind)
{
    struct net_listener *listener = calloc(1, sizeof(*listener));
    if (!listener) {
        return NULL;
    }

    listener->kind = kind;
    listener->port = 0;
    listener->dual_stack = false;
    listener->fd_count = 0;
    for (size_t i = 0; i < NET_LISTENER_MAX_FDS; ++i) {
        listener->fd_entries[i].fd = -1;
        listener->fd_entries[i].is_ipv6 = false;
    }

    return listener;
}

/*
 * net_listener_add_fd
 * Appends a socket descriptor to the listener's list.
 */
static int net_listener_add_fd(struct net_listener *listener, int fd, bool is_ipv6)
{
    if (!listener) {
        errno = EINVAL;
        return -1;
    }

    if (listener->fd_count >= NET_LISTENER_MAX_FDS) {
        errno = ENOSPC;
        return -1;
    }

    listener->fd_entries[listener->fd_count].fd = fd;
    listener->fd_entries[listener->fd_count].is_ipv6 = is_ipv6;
    listener->fd_count++;
    return 0;
}

/*
 * net_kind_label
 * Helper for log messages.
 */
static const char *net_kind_label(net_listener_kind_t kind)
{
    switch (kind) {
    case NET_LISTENER_UDP:
        return "udp";
    case NET_LISTENER_TCP:
    default:
        return "tcp";
    }
}

/*
 * net_strerror
 * Converts errno values into log-friendly strings.
 */
static const char *net_strerror(int err, char buf[EPOLL_ECHO_ERRBUF_LEN])
{
    if (!buf) {
        return "unknown";
    }

#if defined(_GNU_SOURCE)
    return strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN);
#else
    if (strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN) != 0) {
        (void)snprintf(buf, EPOLL_ECHO_ERRBUF_LEN, "errno %d", err);
    }
    return buf;
#endif
}

/*
 * net_make_socket
 * Creates a socket with SOCK_NONBLOCK | SOCK_CLOEXEC applied atomically.
 */
static int net_make_socket(int family, int type, int protocol)
{
    return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
}

/*
 * net_apply_common_opts
 * Currently sets SO_REUSEADDR, leaving room for future options.
 */
static int net_apply_common_opts(int fd)
{
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        return -1;
    }

    return 0;
}

/*
 * net_try_disable_v6only
 * Attempts to turn off IPV6_V6ONLY so IPv4-mapped traffic can share the socket.
 */
static bool net_try_disable_v6only(int fd)
{
    int zero = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero)) != 0) {
        int err = errno;
        char buf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("net: failed to clear IPV6_V6ONLY (%s); IPv4 fallback will be used",
                 net_strerror(err, buf));
        errno = err;
        return false;
    }

    int value = 1;
    socklen_t len = sizeof(value);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &len) == 0 && value == 0) {
        return true;
    }

    LOG_WARN("net: kernel kept IPV6_V6ONLY enabled; IPv4 fallback required");
    return false;
}

/*
 * net_bind_ipv6
 * Binds an IPv6 socket to the requested port on all interfaces.
 */
static int net_bind_ipv6(int fd, uint16_t port)
{
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/*
 * net_bind_ipv4
 * Binds an IPv4 socket to all interfaces.
 */
static int net_bind_ipv4(int fd, uint16_t port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

/*
 * net_finish_socket
 * Runs listen() for TCP sockets; UDP sockets simply return success.
 */
static int net_finish_socket(int fd, bool is_udp, int backlog)
{
    if (is_udp) {
        return 0;
    }

    /* Kernel clamps backlog to net.core.somaxconn; caller-configured value wins otherwise. */
    return listen(fd, backlog);
}

/*
 * net_query_bound_port
 * Retrieves the kernel-assigned port (handles the port=0 case).
 */
static int net_query_bound_port(int fd, uint16_t *port_out)
{
    if (!port_out) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0) {
        return -1;
    }

    uint16_t port = 0;
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        port = ntohs(sin->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        port = ntohs(sin6->sin6_port);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }

    *port_out = port;
    return 0;
}

/*
 * net_open_ipv6_listener
 * Creates/binds/listens on an IPv6 socket, toggling dual-stack if possible.
 */
static int net_open_ipv6_listener(uint16_t port,
                                  bool is_udp,
                                  int backlog,
                                  uint16_t *port_out,
                                  bool *dual_stack,
                                  int socktype,
                                  int protocol)
{
    int fd = net_make_socket(AF_INET6, socktype, protocol);
    if (fd < 0) {
        return -1;
    }

    if (net_apply_common_opts(fd) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    bool is_dual = net_try_disable_v6only(fd);

    if (net_bind_ipv6(fd, port) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (net_finish_socket(fd, is_udp, backlog) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (port_out && net_query_bound_port(fd, port_out) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (dual_stack) {
        *dual_stack = is_dual;
    }

    return fd;
}

/*
 * net_open_ipv4_listener
 * Creates/binds/listens on an IPv4 socket.
 */
static int net_open_ipv4_listener(uint16_t port,
                                  bool is_udp,
                                  int backlog,
                                  uint16_t *port_out,
                                  int socktype,
                                  int protocol)
{
    int fd = net_make_socket(AF_INET, socktype, protocol);
    if (fd < 0) {
        return -1;
    }

    if (net_apply_common_opts(fd) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (net_bind_ipv4(fd, port) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (net_finish_socket(fd, is_udp, backlog) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    if (port_out && net_query_bound_port(fd, port_out) != 0) {
        int saved = errno;
        epoll_echo_close_fd(&fd);
        errno = saved;
        return -1;
    }

    return fd;
}

/*
 * net_setup_listener
 * Drives the dual-stack setup flow for TCP or UDP listeners.
 */
static int net_setup_listener(struct net_listener *listener,
                              uint16_t requested_port,
                              int backlog,
                              bool is_udp)
{
    if (!listener) {
        errno = EINVAL;
        return -1;
    }

    const int socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    const int protocol = is_udp ? IPPROTO_UDP : IPPROTO_TCP;
    uint16_t bound_port = requested_port;
    bool dual_stack = false;

    int fd6 = net_open_ipv6_listener(requested_port,
                                     is_udp,
                                     backlog,
                                     &bound_port,
                                     &dual_stack,
                                     socktype,
                                     protocol);
    if (fd6 >= 0) {
        if (net_listener_add_fd(listener, fd6, true) != 0) {
            int saved = errno;
            epoll_echo_close_fd(&fd6);
            errno = saved;
            return -1;
        }

        listener->dual_stack = dual_stack;
        listener->port = bound_port;
        net_log_listener(listener, true, false);
    } else {
        int err = errno;
        char buf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("net: IPv6 %s socket unavailable (%s); relying on IPv4",
                 net_kind_label(listener->kind), net_strerror(err, buf));
        listener->dual_stack = false;
        bound_port = requested_port;
    }

    bool need_ipv4 = (fd6 < 0) || !listener->dual_stack;
    if (need_ipv4) {
        uint16_t ipv4_port = bound_port;
        if (ipv4_port == 0) {
            ipv4_port = requested_port;
        }

        int fd4 = net_open_ipv4_listener(ipv4_port,
                                         is_udp,
                                         backlog,
                                         &bound_port,
                                         socktype,
                                         protocol);
        if (fd4 < 0) {
            int saved = errno;
            if (fd6 >= 0) {
                net_listener_close(listener);
            }
            errno = saved;
            return -1;
        }

        if (net_listener_add_fd(listener, fd4, false) != 0) {
            int saved = errno;
            epoll_echo_close_fd(&fd4);
            if (fd6 >= 0) {
                net_listener_close(listener);
            }
            errno = saved;
            return -1;
        }

        listener->port = bound_port;
        listener->dual_stack = false;
        net_log_listener(listener, false, fd6 >= 0);
    }

    if (listener->fd_count == 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    return 0;
}

/*
 * net_log_listener
 * Emits INFO logs describing each bound socket for diagnostics.
 */
static void net_log_listener(const struct net_listener *listener,
                             bool is_ipv6,
                             bool fallback)
{
    if (!listener) {
        return;
    }

    const char *proto = net_kind_label(listener->kind);
    const char *stack = listener->dual_stack ? "dual-stack" : "single-stack";

    if (is_ipv6) {
        LOG_INFO("net: listening on [::]:%u (%s, %s)",
                 listener->port,
                 proto,
                 stack);
    } else {
        LOG_INFO("net: listening on 0.0.0.0:%u (%s%s)",
                 listener->port,
                 proto,
                 fallback ? ", ipv4 fallback" : "");
    }
}

static int net_listener_apply_fd_flags(int fd)
{
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if ((flags & O_NONBLOCK) == 0) {
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            return -1;
        }
    }

    int cloexec = fcntl(fd, F_GETFD, 0);
    if (cloexec < 0) {
        return -1;
    }

    if ((cloexec & FD_CLOEXEC) == 0) {
        if (fcntl(fd, F_SETFD, cloexec | FD_CLOEXEC) != 0) {
            return -1;
        }
    }

    return 0;
}

static int net_listener_extract_inet_info(int fd,
                                          bool *is_ipv6_out,
                                          uint16_t *port_out,
                                          bool *dual_stack_candidate)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        return -1;
    }

    bool is_ipv6 = false;
    uint16_t port = 0;
    bool dual_candidate = false;

    if (addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)&addr;
        port = ntohs(sa6->sin6_port);
        is_ipv6 = true;

        int v6only = 1;
        socklen_t optlen = sizeof(v6only);
        if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen) == 0 &&
            v6only == 0) {
            dual_candidate = true;
        }
    } else if (addr.ss_family == AF_INET) {
        const struct sockaddr_in *sa4 = (const struct sockaddr_in *)&addr;
        port = ntohs(sa4->sin_port);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (is_ipv6_out) {
        *is_ipv6_out = is_ipv6;
    }
    if (port_out) {
        *port_out = port;
    }
    if (dual_stack_candidate && dual_candidate) {
        *dual_stack_candidate = true;
    }

    return 0;
}
