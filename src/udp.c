/*
 * udp.c
 * Purpose: Implements the UDP listener lifecycle and datagram I/O path for
 * epoll-echo. This includes socket creation via the net helpers, epoll
 * registration, recvmsg-based draining (with truncation detection), and the
 * plumbing that feeds the UDP stats window.
 */

#include "udp.h"

#include "cmd.h"
#include "common.h"
#include "log.h"
#include "loop.h"
#include "stats.h"

#include <errno.h>

#define UDP_SERVER_DEFAULT_BUF (64 * 1024)
static const char UDP_TRUNCATION_MSG[] = "ERR datagram-truncated\n";
#define UDP_TRUNCATION_MSG_LEN (sizeof(UDP_TRUNCATION_MSG) - 1)

struct udp_listener_entry {
    struct udp_server *server;
    int fd;
    bool registered;
};

struct udp_server {
    struct udp_server_config cfg;
    struct net_listener *listener;
    struct udp_listener_entry *entries;
    size_t entry_count;
    struct loop_context *loop;
    struct ep_stats *stats;
    struct stats_udp_window *udp_window;
    uint16_t bound_port;
    bool dual_stack;
    bool listeners_registered;
    bool tick_hook_installed;
    char *recv_buf;
    size_t recv_buf_len;
};

static void udp_server_unregister_listeners(struct udp_server *server);
static void udp_listener_cb(struct loop_context *ctx,
                            int fd,
                            uint32_t events,
                            void *userdata);
static void udp_listener_handle_read(struct udp_server *server, int fd);
static bool udp_listener_recv_once(struct udp_server *server, int fd);
static void udp_dispatch_datagram(struct udp_server *server,
                                  int fd,
                                  const struct sockaddr_storage *peer,
                                  socklen_t peer_len,
                                  size_t payload_len,
                                  bool truncated);
static void udp_record_peer(struct udp_server *server,
                            const struct sockaddr_storage *peer,
                            socklen_t peer_len);
static void udp_send_response(int fd,
                              const struct sockaddr_storage *peer,
                              socklen_t peer_len,
                              const char *buf,
                              size_t len);
static const char *udp_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN]);
static void udp_tick_hook(struct loop_context *ctx,
                          uint64_t now_epoch_sec,
                          void *userdata);
static void udp_server_enable_tick_hook(struct udp_server *server);
static void udp_server_disable_tick_hook(struct udp_server *server);

/*
 * udp_server_config_init
 * cfg: Output pointer receiving the default UDP configuration.
 * Effect: Seeds the structure with default port + buffer size so callers can
 *         override specific fields after CLI parsing.
 */
void udp_server_config_init(struct udp_server_config *cfg)
{
    if (!cfg) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));
    net_udp_config_init(&cfg->net);
    cfg->recv_buffer_size = UDP_SERVER_DEFAULT_BUF;
}

/*
 * udp_server_init
 * server_out: Output pointer that receives the allocated server handle.
 * cfg: Desired UDP configuration (NULL => defaults).
 * stats: Shared stats structure for peer tracking (required).
 * Returns: 0 on success or -1 with errno preserved.
 */
int udp_server_init(struct udp_server **server_out,
                    const struct udp_server_config *cfg,
                    struct ep_stats *stats)
{
    if (!server_out || !stats) {
        errno = EINVAL;
        return -1;
    }

    struct udp_server_config local_cfg;
    if (!cfg) {
        udp_server_config_init(&local_cfg);
        cfg = &local_cfg;
    }

    if (cfg->recv_buffer_size == 0) {
        local_cfg = *cfg;
        local_cfg.recv_buffer_size = UDP_SERVER_DEFAULT_BUF;
        cfg = &local_cfg;
    }

    struct udp_server *server = calloc(1, sizeof(*server));
    if (!server) {
        return -1;
    }

    server->cfg = *cfg;
    server->stats = stats;
    if (stats) {
        cmd_set_stats(stats);
    }

    if (net_listener_create_udp(&server->cfg.net, &server->listener) != 0) {
        int err = errno;
        free(server);
        errno = err;
        return -1;
    }

    server->bound_port = net_listener_port(server->listener);
    server->dual_stack = net_listener_has_dual_stack(server->listener);

    server->recv_buf_len = server->cfg.recv_buffer_size;
    server->recv_buf = malloc(server->recv_buf_len);
    if (!server->recv_buf) {
        int err = errno;
        net_listener_destroy(server->listener);
        free(server);
        errno = err;
        return -1;
    }

    if (stats_udp_window_create(&server->udp_window) != 0) {
        int err = errno;
        free(server->recv_buf);
        net_listener_destroy(server->listener);
        free(server);
        errno = err;
        return -1;
    }

    *server_out = server;
    return 0;
}

/*
 * udp_server_register
 * server: Initialized UDP server handle.
 * loop: Event loop that owns the epoll instance.
 * Effect: Registers every UDP socket (dual-stack + fallback IPv4) for EPOLLIN
 *         so datagrams can be drained as they arrive.
 */
int udp_server_register(struct udp_server *server, struct loop_context *loop)
{
    if (!server || !loop) {
        errno = EINVAL;
        return -1;
    }

    server->loop = loop;

    if (!server->listener) {
        errno = EINVAL;
        return -1;
    }

    if (server->listeners_registered) {
        return 0;
    }

    size_t fd_count = net_listener_fd_count(server->listener);
    if (fd_count == 0) {
        LOG_ERROR("udp: listener reported zero file descriptors");
        errno = EINVAL;
        return -1;
    }

    server->entries = calloc(fd_count, sizeof(*server->entries));
    if (!server->entries) {
        LOG_ERROR("udp: failed to allocate listener entries");
        return -1;
    }

    server->entry_count = fd_count;

    for (size_t i = 0; i < fd_count; ++i) {
        int fd = net_listener_fd_at(server->listener, i);
        if (fd < 0) {
            LOG_ERROR("udp: invalid listener index %zu", i);
            udp_server_unregister_listeners(server);
            free(server->entries);
            server->entries = NULL;
            server->entry_count = 0;
            return -1;
        }

        struct udp_listener_entry *entry = &server->entries[i];
        entry->server = server;
        entry->fd = fd;

        if (loop_add(loop, fd, EPOLLIN, udp_listener_cb, entry) != 0) {
            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_ERROR("udp: failed to register fd=%d: %s",
                      fd,
                      udp_errstr(errno, errbuf));
            udp_server_unregister_listeners(server);
            free(server->entries);
            server->entries = NULL;
            server->entry_count = 0;
            return -1;
        }

        entry->registered = true;
    }

    server->listeners_registered = true;
    udp_server_enable_tick_hook(server);
    return 0;
}

/*
 * udp_server_free
 * server: UDP server handle (nullable).
 * Effect: Unregisters sockets, releases buffers, destroys the listener, and
 *         frees the server structure.
 */
void udp_server_free(struct udp_server *server)
{
    if (!server) {
        return;
    }

    udp_server_disable_tick_hook(server);
    udp_server_unregister_listeners(server);
    free(server->entries);
    server->entries = NULL;
    server->entry_count = 0;

    stats_udp_window_destroy(server->udp_window);
    server->udp_window = NULL;

    free(server->recv_buf);
    server->recv_buf = NULL;
    server->recv_buf_len = 0;

    net_listener_destroy(server->listener);
    server->listener = NULL;

    free(server);
}

static void udp_server_unregister_listeners(struct udp_server *server)
{
    if (!server || !server->entries) {
        return;
    }

    for (size_t i = 0; i < server->entry_count; ++i) {
        struct udp_listener_entry *entry = &server->entries[i];
        if (!entry->registered || entry->fd < 0) {
            continue;
        }

        if (server->loop) {
            (void)loop_del(server->loop, entry->fd);
        }
        entry->registered = false;
    }

    server->listeners_registered = false;
}

static void udp_listener_cb(struct loop_context *ctx,
                            int fd,
                            uint32_t events,
                            void *userdata)
{
    (void)ctx;

    struct udp_listener_entry *entry = userdata;
    if (!entry || !entry->server) {
        return;
    }

    if (events & EPOLLIN) {
        udp_listener_handle_read(entry->server, fd);
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        LOG_WARN("udp: fd=%d delivered unexpected events %#x", fd, events);
    }
}

static void udp_listener_handle_read(struct udp_server *server, int fd)
{
    if (!server) {
        return;
    }

    while (udp_listener_recv_once(server, fd)) {
        continue;
    }
}

static bool udp_listener_recv_once(struct udp_server *server, int fd)
{
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));

    struct iovec iov = {
        .iov_base = server->recv_buf,
        .iov_len = server->recv_buf_len,
    };

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        ssize_t nread = recvmsg(fd, &msg, 0);
        if (nread >= 0) {
            socklen_t peer_len = msg.msg_namelen <= sizeof(peer)
                                      ? msg.msg_namelen
                                      : (socklen_t)sizeof(peer);
            bool truncated = (msg.msg_flags & MSG_TRUNC) != 0;
            udp_dispatch_datagram(server,
                                  fd,
                                  &peer,
                                  peer_len,
                                  (size_t)nread,
                                  truncated);
            return true;
        }

        int err = errno;
        if (epoll_echo_errno_retryable(err)) {
            continue;
        }

        if (epoll_echo_errno_would_block(err)) {
            return false;
        }

        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("udp: recvmsg failed on fd=%d: %s",
                 fd,
                 udp_errstr(err, errbuf));
        return false;
    }
}

static void udp_dispatch_datagram(struct udp_server *server,
                                  int fd,
                                  const struct sockaddr_storage *peer,
                                  socklen_t peer_len,
                                  size_t payload_len,
                                  bool truncated)
{
    if (!server || !peer) {
        return;
    }

    udp_record_peer(server, peer, peer_len);

    if (truncated) {
        udp_send_response(fd,
                          peer,
                          peer_len,
                          UDP_TRUNCATION_MSG,
                          UDP_TRUNCATION_MSG_LEN);
        return;
    }

    if (payload_len == 0) {
        /* Echo the empty datagram back to maintain symmetry. */
        udp_send_response(fd, peer, peer_len, NULL, 0);
        return;
    }

    char cmd_buf[CMD_RESPONSE_MAX];
    size_t cmd_len = 0;
    cmd_result_t cmd_rc = cmd_handle_udp(peer,
                                         peer_len,
                                         server->recv_buf,
                                         payload_len,
                                         cmd_buf,
                                         sizeof(cmd_buf),
                                         &cmd_len);
    if (cmd_rc == CMD_RESULT_HANDLED) {
        udp_send_response(fd, peer, peer_len, cmd_buf, cmd_len);
        return;
    }
    if (cmd_rc == CMD_RESULT_ERROR) {
        LOG_WARN("udp: failed to handle command; dropping datagram");
        return;
    }

    udp_send_response(fd,
                      peer,
                      peer_len,
                      server->recv_buf,
                      payload_len);
}

static void udp_record_peer(struct udp_server *server,
                            const struct sockaddr_storage *peer,
                            socklen_t peer_len)
{
    if (!server || !server->udp_window || !server->stats || !peer) {
        return;
    }

    uint64_t now = (uint64_t)time(NULL);
    if (stats_udp_window_record_peer(server->udp_window,
                                     server->stats,
                                     peer,
                                     peer_len,
                                     now) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("udp: failed to record peer: %s",
                 udp_errstr(errno, errbuf));
    }
}

static void udp_send_response(int fd,
                              const struct sockaddr_storage *peer,
                              socklen_t peer_len,
                              const char *buf,
                              size_t len)
{
    if (!peer) {
        return;
    }

    struct iovec iov = {
        .iov_base = (void *)(buf ? buf : ""),
        .iov_len = buf ? len : 0,
    };

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)peer;
    msg.msg_namelen = peer_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
        if (sent >= 0 || len == 0) {
            return;
        }

        int err = errno;
        if (epoll_echo_errno_retryable(err)) {
            continue;
        }

        if (epoll_echo_errno_would_block(err)) {
            LOG_WARN("udp: sendmsg would block; dropping response");
            return;
        }

        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("udp: sendmsg failed: %s", udp_errstr(err, errbuf));
        return;
    }
}

static const char *udp_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN])
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

static void udp_tick_hook(struct loop_context *ctx,
                          uint64_t now_epoch_sec,
                          void *userdata)
{
    (void)ctx;

    struct udp_server *server = userdata;
    if (!server || !server->udp_window || !server->stats) {
        return;
    }

    if (stats_udp_window_handle_tick(server->udp_window,
                                     server->stats,
                                     now_epoch_sec) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("udp: failed to age peers: %s",
                 udp_errstr(errno, errbuf));
    }
}

static void udp_server_enable_tick_hook(struct udp_server *server)
{
    if (!server || !server->loop || server->tick_hook_installed) {
        return;
    }

    loop_set_tick_hook(server->loop, udp_tick_hook, server);
    server->tick_hook_installed = true;
}

static void udp_server_disable_tick_hook(struct udp_server *server)
{
    if (!server || !server->loop || !server->tick_hook_installed) {
        return;
    }

    loop_set_tick_hook(server->loop, NULL, NULL);
    server->tick_hook_installed = false;
}
