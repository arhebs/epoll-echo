/*
 * cmd.c
 * Purpose: Implements the shared command parsing and dispatch helpers for
 * the TCP and UDP datapaths. Commands follow a small `/verb [args]` grammar
 * and include `/time`, `/stats`, and the guarded `/shutdown <token>`.
 */

#include "cmd.h"

#include "common.h"
#include "log.h"
#include "loop.h"
#include "stats.h"
#include "tcp.h"
#include "timeutil.h"

#include <ctype.h>

struct cmd_state {
    struct ep_stats *stats;
    struct loop_context *loop;
    char *shutdown_token;
    size_t shutdown_token_len;
};

struct cmd_parts {
    const char *name;
    size_t name_len;
    const char *arg;
    size_t arg_len;
};

static struct cmd_state g_cmd_state;

static const char CMD_ERR_UNKNOWN[] = "ERR unknown-command\n";
static const char CMD_ERR_STATS_UNAVAILABLE[] = "ERR stats-unavailable\n";
static const char CMD_ERR_TIME_UNAVAILABLE[] = "ERR time-unavailable\n";
static const char CMD_ERR_SHUTDOWN_LOOPBACK[] = "ERR shutdown-loopback-required\n";
static const char CMD_ERR_SHUTDOWN_TOKEN_MISSING[] = "ERR shutdown-token-missing\n";
static const char CMD_ERR_SHUTDOWN_TOKEN_REQUIRED[] = "ERR shutdown-token-required\n";
static const char CMD_ERR_SHUTDOWN_TOKEN_INVALID[] = "ERR shutdown-token-invalid\n";
static const char CMD_ERR_SHUTDOWN_UDP[] = "ERR shutdown-not-allowed\n";
static const char CMD_MSG_SHUTDOWN_OK[] = "OK, shutting down\n";

static void cmd_trim_token(char *buf, size_t *len);
static bool cmd_parse_parts(const char *line,
                            size_t len,
                            struct cmd_parts *parts);
static bool cmd_name_equals(const struct cmd_parts *parts, const char *name);
static struct ep_stats *cmd_stats_from_conn(const struct tcp_conn *conn);
static bool cmd_format_time(char *buf, size_t buf_len, size_t *len_out);
static bool cmd_format_stats(struct ep_stats *stats,
                             char *buf,
                             size_t buf_len,
                             size_t *len_out);
static cmd_result_t cmd_tcp_send_buf(struct tcp_conn *conn,
                                     const char *buf,
                                     size_t len);
static cmd_result_t cmd_tcp_send_literal(struct tcp_conn *conn,
                                         const char *msg);
static bool cmd_conn_is_loopback(const struct tcp_conn *conn);
static cmd_result_t cmd_tcp_handle_shutdown(struct tcp_conn *conn,
                                            const struct cmd_parts *parts);
static cmd_result_t cmd_udp_write_literal(char *dst,
                                          size_t dst_cap,
                                          size_t *len_out,
                                          const char *msg);

void cmd_set_stats(struct ep_stats *stats)
{
    g_cmd_state.stats = stats;
}

void cmd_set_loop(struct loop_context *loop)
{
    g_cmd_state.loop = loop;
}

void cmd_clear_shutdown_token(void)
{
    free(g_cmd_state.shutdown_token);
    g_cmd_state.shutdown_token = NULL;
    g_cmd_state.shutdown_token_len = 0;
}

int cmd_set_shutdown_token(const char *token, size_t len)
{
    if (!token || len == 0) {
        cmd_clear_shutdown_token();
        return 0;
    }

    char *copy = malloc(len + 1);
    if (!copy) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(copy, token, len);
    copy[len] = '\0';

    size_t trimmed_len = len;
    cmd_trim_token(copy, &trimmed_len);

    cmd_clear_shutdown_token();
    if (trimmed_len == 0) {
        free(copy);
        return 0;
    }

    g_cmd_state.shutdown_token = copy;
    g_cmd_state.shutdown_token_len = trimmed_len;
    return 0;
}

cmd_result_t cmd_handle_tcp(struct tcp_conn *conn,
                            const char *line,
                            size_t len)
{
    if (!conn || !line || len == 0 || line[0] != '/') {
        return CMD_RESULT_NOT_HANDLED;
    }

    struct cmd_parts parts;
    if (!cmd_parse_parts(line, len, &parts)) {
        return cmd_tcp_send_literal(conn, CMD_ERR_UNKNOWN);
    }

    if (cmd_name_equals(&parts, "time")) {
        char resp[CMD_RESPONSE_MAX];
        size_t resp_len = 0;
        if (!cmd_format_time(resp, sizeof(resp), &resp_len)) {
            return cmd_tcp_send_literal(conn, CMD_ERR_TIME_UNAVAILABLE);
        }
        return cmd_tcp_send_buf(conn, resp, resp_len);
    }

    if (cmd_name_equals(&parts, "stats")) {
        char resp[CMD_RESPONSE_MAX];
        size_t resp_len = 0;
        if (!cmd_format_stats(cmd_stats_from_conn(conn),
                              resp,
                              sizeof(resp),
                              &resp_len)) {
            return cmd_tcp_send_literal(conn, CMD_ERR_STATS_UNAVAILABLE);
        }
        return cmd_tcp_send_buf(conn, resp, resp_len);
    }

    if (cmd_name_equals(&parts, "shutdown")) {
        return cmd_tcp_handle_shutdown(conn, &parts);
    }

    return cmd_tcp_send_literal(conn, CMD_ERR_UNKNOWN);
}

cmd_result_t cmd_handle_udp(const struct sockaddr_storage *peer,
                            socklen_t peer_len,
                            const char *buf,
                            size_t len,
                            char *response_buf,
                            size_t response_buf_len,
                            size_t *response_len)
{
    (void)peer;
    (void)peer_len;

    if (!buf || len == 0 || buf[0] != '/') {
        return CMD_RESULT_NOT_HANDLED;
    }

    if (!response_buf || response_buf_len == 0 || !response_len) {
        return CMD_RESULT_ERROR;
    }

    struct cmd_parts parts;
    if (!cmd_parse_parts(buf, len, &parts)) {
        return cmd_udp_write_literal(response_buf,
                                     response_buf_len,
                                     response_len,
                                     CMD_ERR_UNKNOWN);
    }

    if (cmd_name_equals(&parts, "time")) {
        if (cmd_format_time(response_buf, response_buf_len, response_len)) {
            return CMD_RESULT_HANDLED;
        }
        return cmd_udp_write_literal(response_buf,
                                     response_buf_len,
                                     response_len,
                                     CMD_ERR_TIME_UNAVAILABLE);
    }

    if (cmd_name_equals(&parts, "stats")) {
        if (cmd_format_stats(g_cmd_state.stats,
                             response_buf,
                             response_buf_len,
                             response_len)) {
            return CMD_RESULT_HANDLED;
        }
        return cmd_udp_write_literal(response_buf,
                                     response_buf_len,
                                     response_len,
                                     CMD_ERR_STATS_UNAVAILABLE);
    }

    if (cmd_name_equals(&parts, "shutdown")) {
        return cmd_udp_write_literal(response_buf,
                                     response_buf_len,
                                     response_len,
                                     CMD_ERR_SHUTDOWN_UDP);
    }

    return cmd_udp_write_literal(response_buf,
                                 response_buf_len,
                                 response_len,
                                 CMD_ERR_UNKNOWN);
}

static void cmd_trim_token(char *buf, size_t *len)
{
    if (!buf || !len) {
        return;
    }

    size_t start = 0;
    while (start < *len && isspace((unsigned char)buf[start])) {
        start++;
    }

    size_t end = *len;
    while (end > start && isspace((unsigned char)buf[end - 1])) {
        end--;
    }

    size_t new_len = end > start ? end - start : 0;
    if (start > 0 && new_len > 0) {
        memmove(buf, buf + start, new_len);
    }

    buf[new_len] = '\0';
    *len = new_len;
}

static bool cmd_parse_parts(const char *line,
                            size_t len,
                            struct cmd_parts *parts)
{
    if (!line || len == 0 || !parts) {
        return false;
    }

    if (line[0] != '/') {
        return false;
    }

    size_t pos = 1;
    size_t name_start = pos;
    while (pos < len && !isspace((unsigned char)line[pos])) {
        pos++;
    }

    size_t name_len = pos - name_start;
    if (name_len == 0) {
        return false;
    }

    while (pos < len && isspace((unsigned char)line[pos])) {
        pos++;
    }

    size_t arg_start = pos;
    size_t arg_len = len > arg_start ? len - arg_start : 0;
    while (arg_len > 0 &&
           isspace((unsigned char)line[arg_start + arg_len - 1])) {
        arg_len--;
    }

    parts->name = line + name_start;
    parts->name_len = name_len;
    parts->arg = arg_len ? line + arg_start : NULL;
    parts->arg_len = arg_len;
    return true;
}

static bool cmd_name_equals(const struct cmd_parts *parts, const char *name)
{
    if (!parts || !name) {
        return false;
    }

    size_t name_len = strlen(name);
    if (parts->name_len != name_len) {
        return false;
    }

    return memcmp(parts->name, name, name_len) == 0;
}

static struct ep_stats *cmd_stats_from_conn(const struct tcp_conn *conn)
{
    (void)conn;
    return g_cmd_state.stats;
}

static bool cmd_format_time(char *buf, size_t buf_len, size_t *len_out)
{
    if (!buf || buf_len == 0 || !len_out) {
        return false;
    }

    char timestamp[TIMEUTIL_TIMESTAMP_BUF_LEN];
    if (timeutil_format_utc(timestamp) != 0) {
        return false;
    }

    int written = snprintf(buf, buf_len, "%s\n", timestamp);
    if (written < 0 || (size_t)written >= buf_len) {
        return false;
    }

    *len_out = (size_t)written;
    return true;
}

static bool cmd_format_stats(struct ep_stats *stats,
                             char *buf,
                             size_t buf_len,
                             size_t *len_out)
{
    if (!stats || !buf || buf_len == 0 || !len_out) {
        return false;
    }

    uint64_t total = stats_get_total_clients(stats);
    uint32_t tcp_now = stats_get_tcp_connected_now(stats);
    uint32_t udp_active = stats_get_udp_active_60s(stats);

    int written = snprintf(buf,
                           buf_len,
                           "%" PRIu64 " %" PRIu32 " %" PRIu32 "\n",
                           total,
                           tcp_now,
                           udp_active);
    if (written < 0 || (size_t)written >= buf_len) {
        return false;
    }

    *len_out = (size_t)written;
    return true;
}

static cmd_result_t cmd_tcp_send_buf(struct tcp_conn *conn,
                                     const char *buf,
                                     size_t len)
{
    if (!conn || !buf || len == 0) {
        return CMD_RESULT_NOT_HANDLED;
    }

    if (!tcp_conn_send(conn, buf, len)) {
        return CMD_RESULT_ERROR;
    }

    return CMD_RESULT_HANDLED;
}

static cmd_result_t cmd_tcp_send_literal(struct tcp_conn *conn,
                                         const char *msg)
{
    if (!msg) {
        return CMD_RESULT_ERROR;
    }

    return cmd_tcp_send_buf(conn, msg, strlen(msg));
}

static bool cmd_conn_is_loopback(const struct tcp_conn *conn)
{
    if (!conn) {
        return false;
    }

    const struct sockaddr_storage *ss = &conn->peer_addr;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
        uint32_t addr = ntohl(in->sin_addr.s_addr);
        return (addr & 0xff000000U) == 0x7f000000U;
    }

    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
        if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) {
            return true;
        }

        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            struct in_addr v4_addr;
            memcpy(&v4_addr, &in6->sin6_addr.s6_addr[12], sizeof(v4_addr));
            uint32_t addr = ntohl(v4_addr.s_addr);
            return (addr & 0xff000000U) == 0x7f000000U;
        }
    }

    return false;
}

static cmd_result_t cmd_tcp_handle_shutdown(struct tcp_conn *conn,
                                            const struct cmd_parts *parts)
{
    if (!conn || !parts) {
        return CMD_RESULT_ERROR;
    }

    if (!parts->arg || parts->arg_len == 0) {
        return cmd_tcp_send_literal(conn, CMD_ERR_SHUTDOWN_TOKEN_REQUIRED);
    }

    if (!cmd_conn_is_loopback(conn)) {
        LOG_WARN("cmd: rejecting shutdown from non-loopback fd=%d", conn->fd);
        return cmd_tcp_send_literal(conn, CMD_ERR_SHUTDOWN_LOOPBACK);
    }

    if (!g_cmd_state.shutdown_token || g_cmd_state.shutdown_token_len == 0) {
        LOG_WARN("cmd: shutdown token missing; rejecting request");
        return cmd_tcp_send_literal(conn, CMD_ERR_SHUTDOWN_TOKEN_MISSING);
    }

    if (parts->arg_len != g_cmd_state.shutdown_token_len ||
        memcmp(parts->arg,
               g_cmd_state.shutdown_token,
               g_cmd_state.shutdown_token_len) != 0) {
        LOG_WARN("cmd: shutdown token mismatch on fd=%d", conn->fd);
        return cmd_tcp_send_literal(conn, CMD_ERR_SHUTDOWN_TOKEN_INVALID);
    }

    cmd_result_t rc = cmd_tcp_send_literal(conn, CMD_MSG_SHUTDOWN_OK);
    if (rc != CMD_RESULT_HANDLED) {
        return rc;
    }

    if (g_cmd_state.loop) {
        LOG_INFO("cmd: shutdown requested via loopback client fd=%d", conn->fd);
        loop_request_shutdown(g_cmd_state.loop);
    } else {
        LOG_WARN("cmd: shutdown acknowledged but loop missing");
    }

    return CMD_RESULT_HANDLED;
}

static cmd_result_t cmd_udp_write_literal(char *dst,
                                          size_t dst_cap,
                                          size_t *len_out,
                                          const char *msg)
{
    if (!dst || dst_cap == 0 || !len_out || !msg) {
        return CMD_RESULT_ERROR;
    }

    size_t msg_len = strlen(msg);
    if (msg_len >= dst_cap) {
        return CMD_RESULT_ERROR;
    }

    memcpy(dst, msg, msg_len);
    *len_out = msg_len;
    return CMD_RESULT_HANDLED;
}
