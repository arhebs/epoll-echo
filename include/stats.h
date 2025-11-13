/*
 * stats.h
 * Purpose: Declares the statistics tracking facilities shared across TCP/UDP
 * paths. Counters cover total clients, currently connected TCP clients, and
 * UDP peers active within the rolling 60s window. The UDP peer window logic
 * tracks unique `(ip,port)` pairs, maintains last-seen timestamps, and exposes
 * helpers to age peers out every timer tick.
 */

#ifndef EPOLL_ECHO_STATS_H
#define EPOLL_ECHO_STATS_H

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ep_stats {
    uint64_t total_clients;
    uint32_t tcp_connected_now;
    uint32_t udp_active_60s;
};

void stats_init(struct ep_stats *stats);
void stats_note_tcp_connected(struct ep_stats *stats);
void stats_note_tcp_disconnected(struct ep_stats *stats);

uint64_t stats_get_total_clients(const struct ep_stats *stats) EPOLL_ECHO_ATTR_PURE;
uint32_t stats_get_tcp_connected_now(const struct ep_stats *stats) EPOLL_ECHO_ATTR_PURE;
uint32_t stats_get_udp_active_60s(const struct ep_stats *stats) EPOLL_ECHO_ATTR_PURE;

struct stats_udp_window;

int stats_udp_window_create(struct stats_udp_window **window_out);
void stats_udp_window_destroy(struct stats_udp_window *window);
int stats_udp_window_record_peer(struct stats_udp_window *window,
                                 struct ep_stats *stats,
                                 const struct sockaddr_storage *addr,
                                 socklen_t addr_len,
                                 uint64_t now_epoch_sec);
int stats_udp_window_handle_tick(struct stats_udp_window *window,
                                 struct ep_stats *stats,
                                 uint64_t now_epoch_sec);

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_STATS_H */
