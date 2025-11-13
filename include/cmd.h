/*
 * cmd.h
 * Purpose: Declares the command parsing and dispatch helpers shared by the
 * TCP and UDP datapaths. The handlers interpret `/time`, `/stats`, and the
 * guarded `/shutdown <token>` command, returning transport-agnostic results
 * so callers can decide whether to echo the original payload or reuse the
 * generated response buffer.
 */

#ifndef EPOLL_ECHO_CMD_H
#define EPOLL_ECHO_CMD_H

#include "platform.h"

struct tcp_conn;
struct ep_stats;
struct loop_context;

#ifdef __cplusplus
extern "C" {
#endif

#define CMD_RESPONSE_MAX 128

typedef enum {
    CMD_RESULT_NOT_HANDLED = 0,
    CMD_RESULT_HANDLED,
    CMD_RESULT_ERROR
} cmd_result_t;

void cmd_set_stats(struct ep_stats *stats);
void cmd_set_loop(struct loop_context *loop);
int cmd_set_shutdown_token(const char *token, size_t len);
void cmd_clear_shutdown_token(void);

cmd_result_t cmd_handle_tcp(struct tcp_conn *conn,
                            const char *line,
                            size_t len);

cmd_result_t cmd_handle_udp(const struct sockaddr_storage *peer,
                            socklen_t peer_len,
                            const char *buf,
                            size_t len,
                            char *response_buf,
                            size_t response_buf_len,
                            size_t *response_len);

#ifdef __cplusplus
}
#endif

#endif /* EPOLL_ECHO_CMD_H */
