/*
 * udp.h
 * Purpose: Declares the UDP datapath helpers for epoll-echo. The real
 * implementation will handle datagram parsing, truncation detection, and
 * peer tracking once networking helpers are in place.
 */

#ifndef EPOLL_ECHO_UDP_H
#define EPOLL_ECHO_UDP_H

#include "platform.h"
#include "net.h"

struct loop_context;
struct ep_stats;
struct udp_server;

struct udp_server_config {
    struct net_udp_config net; /* UDP port settings (shared with TCP by default). */
    size_t recv_buffer_size;   /* Size of the shared recvmsg buffer (bytes). */
};

void udp_server_config_init(struct udp_server_config *cfg);

int udp_server_init(struct udp_server **server_out,
                    const struct udp_server_config *cfg,
                    struct ep_stats *stats);
int udp_server_register(struct udp_server *server, struct loop_context *loop);
void udp_server_free(struct udp_server *server);

#endif /* EPOLL_ECHO_UDP_H */
