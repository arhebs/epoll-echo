/*
 * net.h
 * Purpose: Declares the networking helper APIs used to create and manage the
 * TCP and UDP listening sockets for epoll-echo. The helpers abstract the
 * dual-stack (IPv6 + IPv4 fallback) logic, enforce SO_REUSEADDR and
 * non-blocking creation, and provide an opaque listener handle that later
 * modules can register with epoll.
 */

#ifndef EPOLL_ECHO_NET_H
#define EPOLL_ECHO_NET_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct net_listener;

typedef enum {
    NET_LISTENER_TCP = 0,
    NET_LISTENER_UDP
} net_listener_kind_t;

struct net_tcp_config {
    uint16_t port;  /* Requested TCP listen port; 0 lets the kernel pick. */
    int backlog;    /* listen(2) backlog; clamped to sane defaults if <= 0. */
};

struct net_udp_config {
    uint16_t port;  /* Requested UDP port; 0 lets the kernel pick. */
};

/*
 * net_tcp_config_init
 * cfg: Output pointer that receives default TCP listen options.
 * Effect: Seeds the structure with PROJECT_REQUEST defaults so CLI parsing
 *         can selectively override fields without worrying about uninitialized
 *         data.
 */
void net_tcp_config_init(struct net_tcp_config *cfg);

/*
 * net_udp_config_init
 * cfg: Output pointer that receives default UDP options.
 * Effect: Sets the UDP port to the shared default so callers can opt into a
 *         dedicated port only when necessary.
 */
void net_udp_config_init(struct net_udp_config *cfg);

/*
 * net_listener_create_tcp
 * cfg: Desired TCP listen configuration (port/backlog).
 * listener_out: Receives an opaque listener handle on success.
 * Returns: 0 on success, -1 with errno set on failure (e.g., bind errors).
 * Notes: Applies SO_REUSEADDR, creates sockets with SOCK_NONBLOCK|SOCK_CLOEXEC,
 *        and handles IPv6 dual-stack with IPv4 fallback when required.
 */
int net_listener_create_tcp(const struct net_tcp_config *cfg,
                            struct net_listener **listener_out);

/*
 * net_listener_create_udp
 * cfg: Desired UDP listen configuration (port only).
 * listener_out: Receives the created UDP listener handle.
 * Returns: 0 on success, -1 with errno preserved on failure.
 */
int net_listener_create_udp(const struct net_udp_config *cfg,
                            struct net_listener **listener_out);

/*
 * net_listener_adopt_inet
 * kind: Indicates whether the descriptors represent TCP or UDP sockets.
 * fds/fd_count: Array of already-opened AF_INET/AF_INET6 sockets to adopt.
 * listener_out: Receives the opaque listener handle on success.
 * Returns: 0 on success, -1 on failure (errno preserved).
 * Notes: The function takes ownership of the descriptors on success. On
 *        failure, the descriptors are closed to avoid leaking activation
 *        sockets.
 */
int net_listener_adopt_inet(net_listener_kind_t kind,
                            const int fds[],
                            size_t fd_count,
                            struct net_listener **listener_out);

/*
 * net_listener_register_prebound
 * listener: A listener previously returned by net_listener_adopt_inet().
 * Returns: 0 on success, -1 if a prebound listener of that kind already
 *          exists or arguments are invalid.
 * Notes: Ownership transfers to the net module immediately. The next call to
 *        net_listener_create_*() of the same kind consumes the registered
 *        listener instead of opening new sockets.
 */
int net_listener_register_prebound(struct net_listener *listener);

/*
 * net_listener_fd_count
 * listener: Listener returned by the create helpers.
 * Returns: Number of underlying sockets (1 for dual-stack, 2 when IPv4
 *          fallback was needed). Returns 0 for NULL.
 */
size_t net_listener_fd_count(const struct net_listener *listener)
    EPOLL_ECHO_ATTR_PURE;

/*
 * net_listener_fd_at
 * listener: Listener handle.
 * index: Position of the desired socket (0 <= index < count).
 * Returns: File descriptor on success or -1 with errno=EINVAL for invalid
 *          arguments. Ownership remains with the listener until closed.
 */
int net_listener_fd_at(const struct net_listener *listener, size_t index);

/*
 * net_listener_port
 * listener: Listener handle.
 * Returns: Host-order port that the listener ultimately bound. When callers
 *          requested port 0, this exposes the kernel-assigned value.
 */
uint16_t net_listener_port(const struct net_listener *listener)
    EPOLL_ECHO_ATTR_PURE;

/*
 * net_listener_kind
 * listener: Listener handle.
 * Returns: NET_LISTENER_TCP or NET_LISTENER_UDP, aiding dispatch decisions.
 */
net_listener_kind_t net_listener_kind(const struct net_listener *listener)
    EPOLL_ECHO_ATTR_PURE;

/*
 * net_listener_has_dual_stack
 * listener: Listener handle.
 * Returns: true when the IPv6 socket successfully disabled IPV6_V6ONLY,
 *          meaning IPv4 clients share the same socket; false otherwise.
 */
bool net_listener_has_dual_stack(const struct net_listener *listener)
    EPOLL_ECHO_ATTR_PURE;

/*
 * net_listener_close
 * listener: Listener handle.
 * Effect: Closes all underlying sockets but leaves the structure allocated so
 *         callers can inspect metadata (useful during shutdown sequences).
 */
void net_listener_close(struct net_listener *listener);

/*
 * net_listener_destroy
 * listener: Listener handle.
 * Effect: Closes any open sockets and frees the listener structure. Safe to
 *         pass NULL.
 */
void net_listener_destroy(struct net_listener *listener);

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_NET_H */
