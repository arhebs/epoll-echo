/*
 * tcp.c
 * Purpose: Implements the TCP listener and accept path for epoll-echo. This
 * step wires the net helpers into the epoll loop, tracks accepted connections,
 * and enforces the max-clients policy. Read/write handling will be layered on
 * in later plan steps, so connection callbacks currently drain data best-effort
 * to avoid spinning the loop.
 */

#include "tcp.h"

#include "cmd.h"
#include "common.h"
#include "log.h"
#include "loop.h"
#include "net.h"
#include "stats.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct tcp_listener_entry {
    struct tcp_server *server;
    int fd;
    bool registered;
};

struct tcp_wq_item {
    struct tcp_wq_item *next;
    size_t len;
    size_t sent;
    char data[];
};

struct tcp_server {
    struct tcp_server_config cfg;
    struct net_listener *listener;
    struct loop_context *loop;
    struct ep_stats *stats;
    struct tcp_listener_entry *listener_entries;
    size_t listener_entry_count;
    bool listeners_registered;
    uint16_t bound_port;
    bool dual_stack;
    struct tcp_conn *conn_head;
    uint32_t conn_count;
};

static void tcp_listener_cb(struct loop_context *ctx,
                            int fd,
                            uint32_t events,
                            void *userdata);
static void tcp_conn_event_cb(struct loop_context *ctx,
                              int fd,
                              uint32_t events,
                              void *userdata);
static void tcp_server_unregister_listeners(struct tcp_server *server);
static void tcp_listener_accept_ready(struct tcp_server *server, int listener_fd);
static void tcp_handle_accept_error(int err);
static bool tcp_server_at_capacity(const struct tcp_server *server);
static void tcp_send_busy_and_close(int client_fd);
static int tcp_conn_add(struct tcp_server *server,
                        int client_fd,
                        const struct sockaddr_storage *addr,
                        socklen_t addr_len);
static void tcp_conn_attach(struct tcp_conn *conn);
static void tcp_conn_detach(struct tcp_conn *conn, bool update_stats);
static void tcp_conn_destroy(struct tcp_conn *conn, bool update_stats);
static bool tcp_conn_handle_read(struct tcp_conn *conn);
static bool tcp_conn_process_bytes(struct tcp_conn *conn,
                                   const char *data,
                                   size_t len);
static bool tcp_conn_copy_range(struct tcp_conn *conn,
                                const char **cursor,
                                const char *limit);
static bool tcp_conn_handle_overflow(struct tcp_conn *conn);
static bool tcp_conn_emit_line(struct tcp_conn *conn);
static bool tcp_conn_dispatch_line(struct tcp_conn *conn,
                                   const char *line,
                                   size_t len,
                                   bool had_cr);
bool tcp_conn_send(struct tcp_conn *conn, const char *buf, size_t len);
static bool tcp_conn_flush_write_queue(struct tcp_conn *conn);
static bool tcp_conn_queue_bytes(struct tcp_conn *conn,
                                 const char *buf,
                                 size_t len);
static void tcp_conn_write_queue_clear(struct tcp_conn *conn);
static bool tcp_conn_apply_epollout(struct tcp_conn *conn, bool enable);
static const char *tcp_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN]);

void tcp_server_config_init(struct tcp_server_config *cfg)
{
    if (!cfg) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));
    net_tcp_config_init(&cfg->net);
    cfg->max_clients = EPOLL_ECHO_DEFAULT_MAX_TCP;
    cfg->max_line = EPOLL_ECHO_DEFAULT_MAX_LINE;
}

int tcp_server_init(struct tcp_server **server_out,
                    const struct tcp_server_config *cfg,
                    struct ep_stats *stats)
{
    if (!server_out) {
        errno = EINVAL;
        return -1;
    }

    struct tcp_server_config local_cfg;
    if (!cfg) {
        tcp_server_config_init(&local_cfg);
        cfg = &local_cfg;
    }

    struct tcp_server *server = calloc(1, sizeof(*server));
    if (!server) {
        return -1;
    }

    server->cfg = *cfg;
    if (server->cfg.max_clients == 0) {
        server->cfg.max_clients = EPOLL_ECHO_DEFAULT_MAX_TCP;
    }
    if (server->cfg.max_line == 0) {
        server->cfg.max_line = EPOLL_ECHO_DEFAULT_MAX_LINE;
    }

    server->stats = stats;
    if (stats) {
        cmd_set_stats(stats);
    }

    if (net_listener_create_tcp(&server->cfg.net, &server->listener) != 0) {
        int err = errno;
        free(server);
        errno = err;
        return -1;
    }

    server->bound_port = net_listener_port(server->listener);
    server->dual_stack = net_listener_has_dual_stack(server->listener);

    *server_out = server;
    return 0;
}

int tcp_server_register(struct tcp_server *server, struct loop_context *loop)
{
    if (!server || !loop) {
        errno = EINVAL;
        return -1;
    }

    cmd_set_loop(loop);
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
        LOG_ERROR("tcp: listener returned zero fds");
        errno = EINVAL;
        return -1;
    }

    server->listener_entries = calloc(fd_count, sizeof(*server->listener_entries));
    if (!server->listener_entries) {
        LOG_ERROR("tcp: failed to allocate listener entries");
        return -1;
    }

    server->listener_entry_count = fd_count;

    for (size_t i = 0; i < fd_count; ++i) {
        int fd = net_listener_fd_at(server->listener, i);
        if (fd < 0) {
            LOG_ERROR("tcp: invalid listener fd index %zu", i);
            tcp_server_unregister_listeners(server);
            free(server->listener_entries);
            server->listener_entries = NULL;
            server->listener_entry_count = 0;
            return -1;
        }

        struct tcp_listener_entry *entry = &server->listener_entries[i];
        entry->server = server;
        entry->fd = fd;

        if (loop_add(loop, fd, EPOLLIN, tcp_listener_cb, entry) != 0) {
            char errbuf[EPOLL_ECHO_ERRBUF_LEN];
            LOG_ERROR("tcp: failed to register listener fd=%d: %s",
                      fd,
                      tcp_errstr(errno, errbuf));
            tcp_server_unregister_listeners(server);
            free(server->listener_entries);
            server->listener_entries = NULL;
            server->listener_entry_count = 0;
            return -1;
        }

        entry->registered = true;
    }

    server->listeners_registered = true;

    LOG_INFO("tcp: listening on port %u (%s)",
             (unsigned)server->bound_port,
             server->dual_stack ? "dual-stack IPv6+IPv4" : "separate IPv4/IPv6");

    return 0;
}

void tcp_server_free(struct tcp_server *server)
{
    if (!server) {
        return;
    }

    struct tcp_conn *conn = server->conn_head;
    while (conn) {
        struct tcp_conn *next = conn->next;
        tcp_conn_destroy(conn, true);
        conn = next;
    }

    tcp_server_unregister_listeners(server);

    free(server->listener_entries);
    net_listener_destroy(server->listener);
    free(server);
}

static void tcp_server_unregister_listeners(struct tcp_server *server)
{
    if (!server || !server->listener_entries) {
        return;
    }

    for (size_t i = 0; i < server->listener_entry_count; ++i) {
        struct tcp_listener_entry *entry = &server->listener_entries[i];
        if (!entry->registered) {
            continue;
        }

        if (server->loop) {
            (void)loop_del(server->loop, entry->fd);
        }

        entry->registered = false;
    }

    server->listeners_registered = false;
}

static void tcp_listener_cb(struct loop_context *ctx,
                            int fd,
                            uint32_t events,
                            void *userdata)
{
    (void)ctx;

    struct tcp_listener_entry *entry = userdata;
    if (!entry || !entry->server) {
        return;
    }

    if (events & EPOLLIN) {
        tcp_listener_accept_ready(entry->server, fd);
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        LOG_WARN("tcp: listener fd=%d reported events %#x", fd, events);
    }
}

static void tcp_listener_accept_ready(struct tcp_server *server, int listener_fd)
{
    for (;;) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept4(listener_fd,
                                (struct sockaddr *)&addr,
                                &addr_len,
                                SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (client_fd < 0) {
            int err = errno;
            if (err == EINTR) {
                continue;
            }
            if (epoll_echo_errno_would_block(err)) {
                break;
            }

            tcp_handle_accept_error(err);
            break;
        }

        if (tcp_server_at_capacity(server)) {
            LOG_WARN("tcp: at capacity (%u clients); rejecting connection",
                     server->cfg.max_clients);
            tcp_send_busy_and_close(client_fd);
            continue;
        }

        if (tcp_conn_add(server, client_fd, &addr, addr_len) != 0) {
            epoll_echo_close_fd(&client_fd);
        }
    }
}

static void tcp_handle_accept_error(int err)
{
    char errbuf[EPOLL_ECHO_ERRBUF_LEN];
    LOG_WARN("tcp: accept4 failed: %s", tcp_errstr(err, errbuf));
}

static bool tcp_server_at_capacity(const struct tcp_server *server)
{
    if (!server || server->cfg.max_clients == 0) {
        return false;
    }

    return server->conn_count >= server->cfg.max_clients;
}

static void tcp_send_busy_and_close(int client_fd)
{
    static const char msg[] = "server busy\n";
    size_t sent = 0;

    while (sent < sizeof(msg) - 1) {
        ssize_t rc = send(client_fd,
                          msg + sent,
                          (sizeof(msg) - 1) - sent,
                          MSG_NOSIGNAL);
        if (rc > 0) {
            sent += (size_t)rc;
            continue;
        }

        if (rc == 0) {
            break; /* peer closed; nothing else to send */
        }

        int err = errno;
        if (epoll_echo_errno_retryable(err)) {
            continue;
        }
        if (epoll_echo_errno_would_block(err)) {
            break; /* write would block on non-blocking fd */
        }
        break;
    }

    epoll_echo_close_fd(&client_fd);
}

static int tcp_conn_add(struct tcp_server *server,
                        int client_fd,
                        const struct sockaddr_storage *addr,
                        socklen_t addr_len)
{
    if (!server || !server->loop || client_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    struct tcp_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        return -1;
    }

    conn->fd = client_fd;
    conn->server = server;
    size_t max_line = server->cfg.max_line ? server->cfg.max_line
                                           : EPOLL_ECHO_DEFAULT_MAX_LINE;
    if (max_line > SIZE_MAX - 1) {
        free(conn);
        errno = EOVERFLOW;
        return -1;
    }
    conn->rbuf = calloc(max_line + 1, sizeof(*conn->rbuf));
    if (!conn->rbuf) {
        free(conn);
        return -1;
    }
    conn->rbuf_cap = max_line;

    if (addr && addr_len <= sizeof(conn->peer_addr)) {
        memcpy(&conn->peer_addr, addr, addr_len);
        conn->peer_addr_len = addr_len;
    }

    if (loop_add(server->loop,
                 conn->fd,
                 LOOP_EVENT_DEFAULT,
                 tcp_conn_event_cb,
                 conn) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_ERROR("tcp: failed to register conn fd=%d: %s",
                  conn->fd,
                  tcp_errstr(errno, errbuf));
        free(conn->rbuf);
        free(conn);
        return -1;
    }

    conn->registered = true;
    conn->epollout_enabled = false;
    tcp_conn_attach(conn);
    return 0;
}

static void tcp_conn_attach(struct tcp_conn *conn)
{
    if (!conn || !conn->server) {
        return;
    }

    struct tcp_server *server = conn->server;

    conn->next = server->conn_head;
    if (server->conn_head) {
        server->conn_head->prev = conn;
    }
    server->conn_head = conn;
    conn->linked = true;

    if (server->conn_count < UINT32_MAX) {
        server->conn_count++;
    }

    if (server->stats) {
        stats_note_tcp_connected(server->stats);
    }
}

static void tcp_conn_detach(struct tcp_conn *conn, bool update_stats)
{
    if (!conn || !conn->linked || !conn->server) {
        return;
    }

    struct tcp_server *server = conn->server;

    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        server->conn_head = conn->next;
    }

    if (conn->next) {
        conn->next->prev = conn->prev;
    }

    conn->prev = conn->next = NULL;
    conn->linked = false;

    if (server->conn_count > 0) {
        server->conn_count--;
    }

    if (update_stats && server->stats) {
        stats_note_tcp_disconnected(server->stats);
    }
}

static void tcp_conn_destroy(struct tcp_conn *conn, bool update_stats)
{
    if (!conn) {
        return;
    }

    struct tcp_server *server = conn->server;

    if (conn->registered && server && server->loop) {
        (void)loop_del(server->loop, conn->fd);
        conn->registered = false;
    }

    epoll_echo_close_fd(&conn->fd);
    tcp_conn_write_queue_clear(conn);
    tcp_conn_detach(conn, update_stats);
    free(conn->rbuf);
    free(conn);
}

static const char *tcp_errstr(int err, char buf[EPOLL_ECHO_ERRBUF_LEN])
{
#if defined(_GNU_SOURCE)
    return strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN);
#else
    if (strerror_r(err, buf, EPOLL_ECHO_ERRBUF_LEN) != 0) {
        snprintf(buf, EPOLL_ECHO_ERRBUF_LEN, "errno=%d", err);
    }
    return buf;
#endif
}

static void tcp_conn_event_cb(struct loop_context *ctx,
                              int fd,
                              uint32_t events,
                              void *userdata)
{
    (void)ctx;
    (void)fd;

    struct tcp_conn *conn = userdata;
    if (!conn) {
        return;
    }

    bool alive = true;
    if (events & EPOLLIN) {
        alive = tcp_conn_handle_read(conn);
    }

    if (alive && (events & EPOLLOUT)) {
        alive = tcp_conn_flush_write_queue(conn);
    }

    if (!alive) {
        tcp_conn_destroy(conn, true);
        return;
    }

    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        (void)tcp_conn_handle_read(conn);
        tcp_conn_destroy(conn, true);
        return;
    }
}

/*
 * tcp_conn_handle_read
 * Input:
 *   conn - Connection to service (must be non-NULL and non-blocking).
 * Returns:
 *   true if the descriptor remains open after draining; false when the caller
 *   should tear the connection down (peer closed, fatal error, or protocol
 *   violation such as consecutive overflows).
 * Notes:
 *   Drains the socket until EAGAIN to honor level-triggered epoll semantics
 *   and delegates parsing to tcp_conn_process_bytes().
 */
static bool tcp_conn_handle_read(struct tcp_conn *conn)
{
    if (!conn) {
        return false;
    }

    char buf[1024];
    for (;;) {
        ssize_t rc = recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rc > 0) {
            if (!tcp_conn_process_bytes(conn, buf, (size_t)rc)) {
                return false;
            }
            continue;
        }
        if (rc == 0) {
            LOG_DEBUG("tcp: peer fd=%d closed read side", conn->fd);
            return false;
        }
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        if (rc < 0 && epoll_echo_errno_would_block(errno)) {
            break;
        }

        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("tcp: recv failed on fd=%d: %s",
                 conn->fd,
                 tcp_errstr(errno, errbuf));
        return false;
    }

    return true;
}

/*
 * tcp_conn_process_bytes
 * Inputs:
 *   conn  - Connection state that owns the incremental read buffer.
 *   data  - Newly read payload chunk.
 *   len   - Number of bytes in the chunk.
 * Returns:
 *   true when processing can continue, false when the caller should close the
 *   connection (e.g., second overflow or send failure).
 * Notes:
 *   Handles line-splitting, CR trimming, and the resync window that discards
 *   bytes after an overflow until the next LF arrives.
 */
static bool tcp_conn_process_bytes(struct tcp_conn *conn,
                                   const char *data,
                                   size_t len)
{
    if (!conn || !data || len == 0) {
        return true;
    }

    const char *cursor = data;
    const char *end = data + len;

    while (cursor < end) {
        if (conn->resync) {
            const char *lf = memchr(cursor, '\n', (size_t)(end - cursor));
            if (!lf) {
                cursor = end;
                conn->rbuf_len = 0;
                break;
            }

            cursor = lf + 1;
            conn->resync = false;
            conn->rbuf_len = 0;
            continue;
        }

        const char *lf = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!lf) {
            if (!tcp_conn_copy_range(conn, &cursor, end)) {
                return false;
            }
            continue;
        }

        if (!tcp_conn_copy_range(conn, &cursor, lf)) {
            return false;
        }

        if (conn->resync) {
            continue;
        }

        cursor = lf + 1;
        if (!tcp_conn_emit_line(conn)) {
            return false;
        }
    }

    return true;
}

/*
 * tcp_conn_copy_range
 * Inputs:
 *   conn   - Connection buffer target.
 *   cursor - Pointer to the current position within the read chunk (updated).
 *   limit  - One-past-the-end pointer delimiting how many bytes to copy.
 * Returns:
 *   true on success, false when the caller should close the connection.
 * Notes:
 *   Stops copying immediately if the per-connection buffer reaches capacity,
 *   triggering the overflow handler so the caller can enter resync mode.
 */
static bool tcp_conn_copy_range(struct tcp_conn *conn,
                                const char **cursor,
                                const char *limit)
{
    if (!conn || !cursor || !*cursor) {
        return false;
    }

    while (*cursor < limit) {
        if (conn->rbuf_len >= conn->rbuf_cap) {
            return tcp_conn_handle_overflow(conn);
        }

        size_t remaining = conn->rbuf_cap - conn->rbuf_len;
        size_t available = (size_t)(limit - *cursor);
        size_t to_copy = EPOLL_ECHO_MIN(remaining, available);

        if (to_copy == 0) {
            break;
        }

        memcpy(conn->rbuf + conn->rbuf_len, *cursor, to_copy);
        conn->rbuf_len += to_copy;
        *cursor += to_copy;
    }

    return true;
}

/*
 * tcp_conn_handle_overflow
 * Input:
 *   conn - Connection whose current line exceeded cfg->max_line bytes.
 * Returns:
 *   true if the connection can stay open (first overflow), false if it must
 *   be closed (second consecutive overflow or send failure).
 * Notes:
 *   Sends "ERR too-long-line" best-effort and flips the resync flag so the
 *   read path discards bytes until the next LF boundary.
 */
static bool tcp_conn_handle_overflow(struct tcp_conn *conn)
{
    static const char err_msg[] = "ERR too-long-line\n";

    if (!conn) {
        return false;
    }

    conn->rbuf_len = 0;
    conn->resync = true;

    if (conn->overflow_streak < UINT8_MAX) {
        conn->overflow_streak++;
    }

    if (!tcp_conn_send(conn, err_msg, sizeof(err_msg) - 1)) {
        return false;
    }

    if (conn->overflow_streak >= 2) {
        LOG_WARN("tcp: closing fd=%d after consecutive line overflows", conn->fd);
        return false;
    }

    return true;
}

/*
 * tcp_conn_emit_line
 * Input:
 *   conn - Connection whose buffer currently holds a full line (no LF).
 * Effect:
 *   Trims a trailing '\r', null-terminates the buffer for logging/command
 *   parsing, resets overflow tracking, and hands the payload to the command
 *   dispatcher (placeholder for now).
 */
static bool tcp_conn_emit_line(struct tcp_conn *conn)
{
    if (!conn || !conn->rbuf) {
        return false;
    }

    size_t len = conn->rbuf_len;
    bool had_cr = false;
    if (len > 0 && conn->rbuf[len - 1] == '\r') {
        len--;
        had_cr = true;
    }

    conn->rbuf[len] = '\0';
    bool ok = tcp_conn_dispatch_line(conn, conn->rbuf, len, had_cr);
    conn->rbuf_len = 0;
    conn->overflow_streak = 0;
    return ok;
}

/*
 * tcp_conn_dispatch_line
 * Inputs:
 *   conn - Connection that produced the line.
 *   line - Pointer to a null-terminated buffer (owned by conn).
 *   len  - Line length excluding the trailing newline (and CR, if removed).
 * Notes:
 *   Stub placeholder until the command module and write queue are wired in.
 */
static bool tcp_conn_dispatch_line(struct tcp_conn *conn,
                                   const char *line,
                                   size_t len,
                                   bool had_cr)
{
    if (!conn || !line) {
        return false;
    }

    cmd_result_t cmd_rc = cmd_handle_tcp(conn, line, len);
    if (cmd_rc == CMD_RESULT_ERROR) {
        return false;
    }
    if (cmd_rc == CMD_RESULT_HANDLED) {
        return true;
    }

    LOG_DEBUG("tcp: fd=%d echoing line (%zu bytes)", conn->fd, len);
    if (len > 0 && !tcp_conn_send(conn, line, len)) {
        return false;
    }
    if (had_cr && !tcp_conn_send(conn, "\r", 1)) {
        return false;
    }
    static const char newline[] = "\n";
    if (!tcp_conn_send(conn, newline, 1)) {
        return false;
    }

    return true;
}

/*
 * tcp_conn_queue_bytes
 * Inputs:
 *   conn - Connection whose write queue should grow.
 *   buf/len - Payload to copy into the queue.
 * Returns:
 *   true when the bytes were enqueued, false on allocation failure.
 * Notes:
 *   The queue owns the copied buffer to keep lifetime independent from the
 *   caller's stack storage. Items preserve FIFO ordering.
 */
static bool tcp_conn_queue_bytes(struct tcp_conn *conn,
                                 const char *buf,
                                 size_t len)
{
    if (!conn || !buf || len == 0) {
        return true;
    }

    const size_t limit = EPOLL_ECHO_TCP_WQ_LIMIT_BYTES;
    if (conn->wq_bytes >= limit || len > limit - conn->wq_bytes) {
        LOG_WARN("tcp: fd=%d write queue limit %zuB exceeded; closing connection",
                 conn->fd,
                 limit);
        errno = ENOBUFS;
        return false;
    }

    if (len > SIZE_MAX - sizeof(struct tcp_wq_item)) {
        LOG_ERROR("tcp: write buffer length %zu exceeds allocation limit", len);
        errno = EOVERFLOW;
        return false;
    }

    struct tcp_wq_item *item = malloc(sizeof(*item) + len);
    if (!item) {
        LOG_ERROR("tcp: failed to allocate %zu-byte write buffer", len);
        return false;
    }

    item->next = NULL;
    item->len = len;
    item->sent = 0;
    memcpy(item->data, buf, len);

    if (!conn->wq_head) {
        conn->wq_head = conn->wq_tail = item;
    } else {
        conn->wq_tail->next = item;
        conn->wq_tail = item;
    }

    conn->wq_bytes += len;
    return true;
}

/*
 * tcp_conn_write_queue_clear
 * Input:
 *   conn - Connection whose pending writes must be freed.
 * Effect:
 *   Releases all queued buffers. Call during teardown to avoid leaks.
 */
static void tcp_conn_write_queue_clear(struct tcp_conn *conn)
{
    if (!conn) {
        return;
    }

    struct tcp_wq_item *item = conn->wq_head;
    while (item) {
        struct tcp_wq_item *next = item->next;
        if (conn->wq_bytes >= item->len) {
            conn->wq_bytes -= item->len;
        } else {
            conn->wq_bytes = 0;
        }
        free(item);
        item = next;
    }

    conn->wq_head = NULL;
    conn->wq_tail = NULL;
    conn->wq_bytes = 0;
}

/*
 * tcp_conn_apply_epollout
 * Inputs:
 *   conn - Connection registered with the loop.
 *   enable - Desired EPOLLOUT state (true => monitor for writable events).
 * Returns:
 *   true on success, false if loop_mod fails (caller should tear down).
 * Notes:
 *   Avoids redundant EPOLL_CTL_MOD calls by tracking epollout_enabled.
 */
static bool tcp_conn_apply_epollout(struct tcp_conn *conn, bool enable)
{
    if (!conn) {
        return false;
    }

    if (!conn->registered || !conn->server || !conn->server->loop) {
        conn->epollout_enabled = enable;
        return true;
    }

    if (conn->epollout_enabled == enable) {
        return true;
    }

    uint32_t events = LOOP_EVENT_DEFAULT | (enable ? EPOLLOUT : 0);
    if (loop_mod(conn->server->loop, conn->fd, events) != 0) {
        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("tcp: failed to %sable EPOLLOUT on fd=%d: %s",
                 enable ? "en" : "dis",
                 conn->fd,
                 tcp_errstr(errno, errbuf));
        return false;
    }

    conn->epollout_enabled = enable;
    return true;
}

/*
 * tcp_conn_flush_write_queue
 * Input:
 *   conn - Connection with pending writes.
 * Returns:
 *   true if the connection remains open after attempting to send queued
 *   bytes; false when a fatal send error occurs.
 * Notes:
 *   Drains the queue until either it is empty or send() would block. Uses
 *   MSG_NOSIGNAL and toggles EPOLLOUT to re-arm write notifications only
 *   when the queue is non-empty.
 */
static bool tcp_conn_flush_write_queue(struct tcp_conn *conn)
{
    if (!conn) {
        return false;
    }

    while (conn->wq_head) {
        struct tcp_wq_item *item = conn->wq_head;
        if (item->sent >= item->len) {
            conn->wq_head = item->next;
            if (!conn->wq_head) {
                conn->wq_tail = NULL;
            }
            if (conn->wq_bytes >= item->len) {
                conn->wq_bytes -= item->len;
            } else {
                conn->wq_bytes = 0;
            }
            free(item);
            continue;
        }

        size_t remaining = item->len - item->sent;
        ssize_t rc = send(conn->fd,
                          item->data + item->sent,
                          remaining,
                          MSG_NOSIGNAL);
        if (rc > 0) {
            item->sent += (size_t)rc;
            continue;
        }
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        if (rc < 0 && epoll_echo_errno_would_block(errno)) {
            return tcp_conn_apply_epollout(conn, true);
        }

        char errbuf[EPOLL_ECHO_ERRBUF_LEN];
        LOG_WARN("tcp: send failed on fd=%d: %s",
                 conn->fd,
                 tcp_errstr(errno, errbuf));
        return false;
    }

    return tcp_conn_apply_epollout(conn, false);
}

/*
 * tcp_conn_send
 * Inputs:
 *   conn - Connection to write to.
 *   buf/len - Message payload.
 * Returns:
 *   true on success (or when send would block but the queue/EPOLLOUT have been
 *   armed); false on allocation or fatal send errors.
 * Notes:
 *   Enqueues the payload and immediately attempts to flush it so callers do
 *   not need to reason about partial writes.
 */
bool tcp_conn_send(struct tcp_conn *conn, const char *buf, size_t len)
{
    if (!conn || !buf || len == 0) {
        return true;
    }

    if (!tcp_conn_queue_bytes(conn, buf, len)) {
        return false;
    }

    return tcp_conn_flush_write_queue(conn);
}
