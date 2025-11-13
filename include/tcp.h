/*
 * tcp.h
 * Purpose: Declares the TCP listener/connection management interfaces used by
 * epoll-echo. This includes the configuration surface, opaque server handle,
 * and the per-connection structure that later steps will extend with parsing
 * and write-queue state.
 */

#ifndef EPOLL_ECHO_TCP_H
#define EPOLL_ECHO_TCP_H

#include "platform.h"
#include "net.h"

struct loop_context;
struct ep_stats;
struct tcp_server;
struct tcp_wq_item;

/*
 * struct tcp_conn
 * Represents a single accepted TCP client. Fields beyond the descriptor,
 * linkage, and peer metadata will be filled in during subsequent plan steps
 * (read buffers, write queues, overflow tracking, etc.).
 */
struct tcp_conn {
    int fd;
    struct tcp_server *server;
    struct tcp_conn *prev;
    struct tcp_conn *next;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    char *rbuf;          /* dynamically sized read buffer (max_line + 1) */
    size_t rbuf_cap;     /* configured max_line limit */
    size_t rbuf_len;     /* bytes currently stored in rbuf */
    uint8_t overflow_streak;
    bool registered; /* true once the fd is added to epoll */
    bool linked;     /* true while present in the server's conn list */
    bool resync;     /* true while discarding until next LF */
    struct tcp_wq_item *wq_head; /* pending write buffers (queue head) */
    struct tcp_wq_item *wq_tail; /* queue tail */
    size_t wq_bytes;             /* total bytes queued (enforce cap) */
    bool epollout_enabled;       /* true when EPOLLOUT is currently armed */
};

/*
 * struct tcp_server_config
 * Captures the listening parameters (port/backlog) and capacity limits that
 * govern TCP behavior. Higher-level code seeds defaults via
 * tcp_server_config_init() and overrides fields after CLI parsing.
 */
struct tcp_server_config {
    struct net_tcp_config net;
    uint32_t max_clients;
    size_t max_line; /* max line length before overflow handling */
};

void tcp_server_config_init(struct tcp_server_config *cfg);

int tcp_server_init(struct tcp_server **server_out,
                    const struct tcp_server_config *cfg,
                    struct ep_stats *stats);
int tcp_server_register(struct tcp_server *server, struct loop_context *loop);
void tcp_server_free(struct tcp_server *server);

/*
 * tcp_conn_send
 * Input:
 *   conn - Connection whose write queue should receive the payload.
 *   buf/len - Bytes to enqueue; len may be zero for no-op.
 * Returns:
 *   true on success, false when queuing or flushing fails (caller should
 *   close the connection).
 */
bool tcp_conn_send(struct tcp_conn *conn, const char *buf, size_t len);

#endif /* EPOLL_ECHO_TCP_H */
