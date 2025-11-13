/*
 * main.c
 * Purpose: Implements the CLI parsing, configuration plumbing, and runtime
 * bootstrap for the epoll-echo daemon. This file owns argument validation,
 * log verbosity handling, and the lifecycle orchestration of the loop, TCP,
 * and UDP modules. Later steps (shutdown token loading, systemd adoption)
 * extend this foundation without rewriting the control flow here.
 */

#include "platform.h"

#include "cmd.h"
#include "common.h"
#include "log.h"
#include "net.h"
#include "loop.h"
#include "stats.h"
#include "tcp.h"
#include "udp.h"

#include <getopt.h>
#include <limits.h>
#include <sys/stat.h>

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define CLI_MAX_LINE_MIN 1U
#define CLI_MAX_LINE_MAX (128U * 1024U)
#define CLI_BACKLOG_MIN 1
#define CLI_BACKLOG_MAX 32768

enum cli_long_option {
    CLI_OPT_PORT = 1000,
    CLI_OPT_TCP_PORT,
    CLI_OPT_UDP_PORT,
    CLI_OPT_MAX_TCP,
    CLI_OPT_BACKLOG,
    CLI_OPT_MAX_LINE,
    CLI_OPT_SHUTDOWN_TOKEN_FILE
};

static void cli_print_usage(FILE *stream, const char *progname);
static bool cli_parse_unsigned(const char *arg,
                               unsigned long long min,
                               unsigned long long max,
                               unsigned long long *value_out);
static bool cli_parse_port(const char *arg, uint16_t *value_out);
static bool cli_parse_backlog(const char *arg, int *value_out);
static bool cli_parse_max_tcp(const char *arg, uint32_t *value_out);
static bool cli_parse_max_line(const char *arg, size_t *value_out);
static bool cli_set_shutdown_token_file(struct epoll_echo_config *cfg,
                                        const char *path);
static int cli_parse(int argc,
                     char **argv,
                     struct epoll_echo_config *cfg,
                     bool *should_exit,
                     int *exit_code);
static void log_startup_summary(const struct epoll_echo_config *cfg);
static int load_shutdown_token(const struct epoll_echo_config *cfg);
static int load_token_from_credentials_dir(const char *dir,
                                           char **token_out,
                                           size_t *token_len_out);
static int load_token_from_path(const char *path,
                                bool require_owner_only,
                                char **token_out,
                                size_t *token_len_out);
static int build_credentials_path(const char *dir, char **path_out);
static int slurp_fd(int fd, char **buf_out, size_t *len_out);
static int adopt_systemd_sockets(struct net_listener **tcp_listener_out,
                                 struct net_listener **udp_listener_out);

/*
 * cli_print_usage
 * stream: Destination FILE* (stdout for normal usage, stderr for errors).
 * progname: Binary name displayed in the synopsis (nullable).
 */
static void cli_print_usage(FILE *stream, const char *progname)
{
    if (!stream) {
        return;
    }

    const char *name = progname ? progname : EPOLL_ECHO_PROGRAM_NAME;
    fprintf(stream,
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "  --port N                 Bind TCP and UDP to port N (default %u; 0 = kernel assigned)\n"
            "  --tcp-port N             Override only the TCP listen port\n"
            "  --udp-port N             Override only the UDP port\n"
            "  --max-tcp N              Limit concurrent TCP clients (default %u)\n"
            "  --backlog N              listen(2) backlog hint (default %d)\n"
            "  --max-line N             Per-line limit in bytes (default %zu)\n"
            "  --shutdown-token-file PATH  Optional file containing the shutdown token\n"
            "  -v / -vv                  Increase log verbosity (INFO -> DEBUG)\n"
            "  -q                        Reduce verbosity (INFO -> WARN)\n"
            "  -h, --help                Show this help and exit\n",
            name,
            EPOLL_ECHO_DEFAULT_PORT,
            EPOLL_ECHO_DEFAULT_MAX_TCP,
            EPOLL_ECHO_DEFAULT_BACKLOG,
            (size_t)EPOLL_ECHO_DEFAULT_MAX_LINE);
}

/*
 * cli_parse_unsigned
 * arg: String representation of the numeric value.
 * min/max: Allowed range (inclusive).
 * value_out: Receives the parsed number on success.
 */
static bool cli_parse_unsigned(const char *arg,
                               unsigned long long min,
                               unsigned long long max,
                               unsigned long long *value_out)
{
    if (!arg || !value_out || min > max) {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0') {
        return false;
    }

    if (value < min || value > max) {
        return false;
    }

    *value_out = value;
    return true;
}

/*
 * cli_parse_port
 * Accepts decimal ports in [0, 65535].
 */
static bool cli_parse_port(const char *arg, uint16_t *value_out)
{
    unsigned long long value = 0;
    if (!cli_parse_unsigned(arg, 0ULL, 65535ULL, &value)) {
        return false;
    }

    *value_out = (uint16_t)value;
    return true;
}

/*
 * cli_parse_backlog
 * Ensures backlog resides within a conservative, documented window.
 */
static bool cli_parse_backlog(const char *arg, int *value_out)
{
    unsigned long long value = 0;
    if (!cli_parse_unsigned(arg,
                            (unsigned long long)CLI_BACKLOG_MIN,
                            (unsigned long long)CLI_BACKLOG_MAX,
                            &value)) {
        return false;
    }

    if (value > INT_MAX) {
        return false;
    }

    *value_out = (int)value;
    return true;
}

/*
 * cli_parse_max_tcp
 * Converts the argument into a uint32_t client cap.
 */
static bool cli_parse_max_tcp(const char *arg, uint32_t *value_out)
{
    unsigned long long value = 0;
    if (!cli_parse_unsigned(arg, 1ULL, (unsigned long long)UINT32_MAX, &value)) {
        return false;
    }

    *value_out = (uint32_t)value;
    return true;
}

/*
 * cli_parse_max_line
 * Applies the guard rails for the TCP per-line cap.
 */
static bool cli_parse_max_line(const char *arg, size_t *value_out)
{
    unsigned long long value = 0;
    if (!cli_parse_unsigned(arg,
                            (unsigned long long)CLI_MAX_LINE_MIN,
                            (unsigned long long)CLI_MAX_LINE_MAX,
                            &value)) {
        return false;
    }

    if (value > (unsigned long long)SIZE_MAX) {
        return false;
    }

    *value_out = (size_t)value;
    return true;
}

/*
 * cli_set_shutdown_token_file
 * Copies the provided path so later token-loading logic can consume it.
 */
static bool cli_set_shutdown_token_file(struct epoll_echo_config *cfg,
                                        const char *path)
{
    if (!cfg || !path || path[0] == '\0') {
        errno = EINVAL;
        return false;
    }

    char *copy = strdup(path);
    if (!copy) {
        return false;
    }

    free(cfg->shutdown_token_file);
    cfg->shutdown_token_file = copy;
    return true;
}

/*
 * cli_parse
 * Parses argv, fills cfg, and reports whether execution should stop
 * immediately (e.g., --help). On errors the function prints a message to
 * stderr and returns -1.
 */
static int cli_parse(int argc,
                     char **argv,
                     struct epoll_echo_config *cfg,
                     bool *should_exit,
                     int *exit_code)
{
    if (!cfg) {
        errno = EINVAL;
        return -1;
    }

    bool exit_after_parse = false;
    int local_exit_code = EXIT_SUCCESS;
    const char *progname = (argv && argv[0]) ? argv[0] : EPOLL_ECHO_PROGRAM_NAME;

    static const struct option long_opts[] = {
        {"port", required_argument, NULL, CLI_OPT_PORT},
        {"tcp-port", required_argument, NULL, CLI_OPT_TCP_PORT},
        {"udp-port", required_argument, NULL, CLI_OPT_UDP_PORT},
        {"max-tcp", required_argument, NULL, CLI_OPT_MAX_TCP},
        {"backlog", required_argument, NULL, CLI_OPT_BACKLOG},
        {"max-line", required_argument, NULL, CLI_OPT_MAX_LINE},
        {"shutdown-token-file", required_argument, NULL, CLI_OPT_SHUTDOWN_TOKEN_FILE},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    opterr = 0;
    optind = 1;

    for (;;) {
        int opt = getopt_long(argc, argv, "hvq", long_opts, NULL);
        if (opt == -1) {
            break;
        }

        switch (opt) {
        case 'h':
            cli_print_usage(stdout, progname);
            exit_after_parse = true;
            break;
        case 'v':
            if (cfg->verbosity_delta < 2) {
                cfg->verbosity_delta++;
            }
            break;
        case 'q':
            if (cfg->verbosity_delta > -2) {
                cfg->verbosity_delta--;
            }
            break;
        case CLI_OPT_PORT: {
            uint16_t port = 0;
            if (!cli_parse_port(optarg, &port)) {
                fprintf(stderr, "%s: invalid value for --port: '%s'\n", progname, optarg);
                return -1;
            }
            cfg->tcp_port = port;
            cfg->udp_port = port;
            break;
        }
        case CLI_OPT_TCP_PORT: {
            uint16_t port = 0;
            if (!cli_parse_port(optarg, &port)) {
                fprintf(stderr,
                        "%s: invalid value for --tcp-port: '%s'\n",
                        progname,
                        optarg);
                return -1;
            }
            cfg->tcp_port = port;
            break;
        }
        case CLI_OPT_UDP_PORT: {
            uint16_t port = 0;
            if (!cli_parse_port(optarg, &port)) {
                fprintf(stderr,
                        "%s: invalid value for --udp-port: '%s'\n",
                        progname,
                        optarg);
                return -1;
            }
            cfg->udp_port = port;
            break;
        }
        case CLI_OPT_MAX_TCP: {
            uint32_t max_tcp = 0;
            if (!cli_parse_max_tcp(optarg, &max_tcp)) {
                fprintf(stderr,
                        "%s: invalid value for --max-tcp: '%s'\n",
                        progname,
                        optarg);
                return -1;
            }
            cfg->max_tcp = max_tcp;
            break;
        }
        case CLI_OPT_BACKLOG: {
            int backlog = 0;
            if (!cli_parse_backlog(optarg, &backlog)) {
                fprintf(stderr,
                        "%s: invalid value for --backlog: '%s'\n",
                        progname,
                        optarg);
                return -1;
            }
            cfg->backlog = backlog;
            break;
        }
        case CLI_OPT_MAX_LINE: {
            size_t max_line = 0;
            if (!cli_parse_max_line(optarg, &max_line)) {
                fprintf(stderr,
                        "%s: invalid value for --max-line: '%s'\n",
                        progname,
                        optarg);
                return -1;
            }
            cfg->max_line = max_line;
            break;
        }
        case CLI_OPT_SHUTDOWN_TOKEN_FILE:
            if (!cli_set_shutdown_token_file(cfg, optarg)) {
                int err = errno;
                fprintf(stderr,
                        "%s: failed to apply --shutdown-token-file '%s' (%s)\n",
                        progname,
                        optarg,
                        strerror(err));
                return -1;
            }
            break;
        case '?':
            if (optopt) {
                fprintf(stderr, "%s: unknown option '-%c'\n", progname, optopt);
            } else if (optind > 0 && optind <= argc) {
                fprintf(stderr, "%s: unknown option '%s'\n", progname, argv[optind - 1]);
            } else {
                fprintf(stderr, "%s: unknown option\n", progname);
            }
            return -1;
        default:
            fprintf(stderr, "%s: unexpected option code %d\n", progname, opt);
            return -1;
        }
    }

    if (!exit_after_parse && optind < argc) {
        fprintf(stderr,
                "%s: unexpected argument '%s'\n",
                progname,
                argv[optind]);
        return -1;
    }

    if (should_exit) {
        *should_exit = exit_after_parse;
    }
    if (exit_code) {
        *exit_code = local_exit_code;
    }

    return 0;
}

/*
 * log_startup_summary
 * Provides a concise overview of effective configuration knobs.
 */
static void log_startup_summary(const struct epoll_echo_config *cfg)
{
    if (!cfg) {
        return;
    }

    LOG_INFO("config: tcp_port=%u udp_port=%u backlog=%d max_tcp=%u max_line=%zu",
             (unsigned)cfg->tcp_port,
             (unsigned)cfg->udp_port,
             cfg->backlog,
             cfg->max_tcp,
             cfg->max_line);

    if (cfg->shutdown_token_file) {
        LOG_INFO("shutdown token file: %s", cfg->shutdown_token_file);
    }
}

/*
 * slurp_fd
 * fd: Open descriptor positioned at the start of the token file.
 * buf_out/len_out: Receives a NUL-terminated heap buffer and its raw length.
 * Returns: 0 on success, -1 on error with errno preserved.
 * Notes: Used for both credential-provided files and user-specified files to
 * avoid bespoke stdio handling and to guarantee the token is treated as text.
 */
static int slurp_fd(int fd, char **buf_out, size_t *len_out)
{
    if (fd < 0 || !buf_out || !len_out) {
        errno = EINVAL;
        return -1;
    }

    size_t cap = 256;
    char *buf = malloc(cap + 1);
    if (!buf) {
        return -1;
    }

    size_t len = 0;
    for (;;) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) {
                free(buf);
                errno = EOVERFLOW;
                return -1;
            }
            size_t new_cap = cap * 2;
            char *tmp = realloc(buf, new_cap + 1);
            if (!tmp) {
                int err = errno;
                free(buf);
                errno = err;
                return -1;
            }
            buf = tmp;
            cap = new_cap;
        }

        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            int err = errno;
            free(buf);
            errno = err;
            return -1;
        }
        if (n == 0) {
            break;
        }

        len += (size_t)n;
    }

    buf[len] = '\0';
    *buf_out = buf;
    *len_out = len;
    return 0;
}

static int adopt_systemd_sockets(struct net_listener **tcp_listener_out,
                                 struct net_listener **udp_listener_out)
{
    if (!tcp_listener_out || !udp_listener_out) {
        errno = EINVAL;
        return -1;
    }

    *tcp_listener_out = NULL;
    *udp_listener_out = NULL;

#ifndef ENABLE_SYSTEMD
    return 0;
#else
    int fd_count = sd_listen_fds(0);
    if (fd_count < 0) {
        int err = -fd_count;
        errno = err;
        LOG_ERROR("systemd: sd_listen_fds failed: %s", strerror(err));
        return -1;
    }

    if (fd_count == 0) {
        return 0;
    }

    size_t capacity = (size_t)fd_count;
    int *tcp_fds = calloc(capacity, sizeof(int));
    int *udp_fds = calloc(capacity, sizeof(int));
    if (!tcp_fds || !udp_fds) {
        int err = errno ? errno : ENOMEM;
        free(tcp_fds);
        free(udp_fds);
        errno = err;
        LOG_ERROR("systemd: failed to allocate activation fd scratch space: %s",
                  strerror(err));
        return -1;
    }

    size_t tcp_count = 0;
    size_t udp_count = 0;

    for (int i = 0; i < fd_count; ++i) {
        int fd = SD_LISTEN_FDS_START + i;
        int rc = sd_is_socket_inet(fd, AF_UNSPEC, SOCK_STREAM, 1, 0);
        if (rc < 0) {
            int err = -rc;
            errno = err;
            LOG_ERROR("systemd: sd_is_socket_inet(stream) failed for fd=%d: %s",
                      fd,
                      strerror(err));
            goto fail;
        }
        if (rc > 0) {
            tcp_fds[tcp_count++] = fd;
            continue;
        }

        rc = sd_is_socket_inet(fd, AF_UNSPEC, SOCK_DGRAM, 0, 0);
        if (rc < 0) {
            int err = -rc;
            errno = err;
            LOG_ERROR("systemd: sd_is_socket_inet(datagram) failed for fd=%d: %s",
                      fd,
                      strerror(err));
            goto fail;
        }
        if (rc > 0) {
            udp_fds[udp_count++] = fd;
            continue;
        }

        LOG_WARN("systemd: closing unexpected fd=%d (not inet stream/dgram)", fd);
        epoll_echo_close_fd(&fd);
    }

    if (tcp_count > 0) {
        if (net_listener_adopt_inet(NET_LISTENER_TCP,
                                    tcp_fds,
                                    tcp_count,
                                    tcp_listener_out) != 0) {
            LOG_ERROR("systemd: failed to adopt TCP listeners: %s",
                      strerror(errno));
            goto fail;
        }
    }

    if (udp_count > 0) {
        if (net_listener_adopt_inet(NET_LISTENER_UDP,
                                    udp_fds,
                                    udp_count,
                                    udp_listener_out) != 0) {
            if (*tcp_listener_out) {
                net_listener_destroy(*tcp_listener_out);
                *tcp_listener_out = NULL;
            }
            LOG_ERROR("systemd: failed to adopt UDP listeners: %s",
                      strerror(errno));
            goto fail;
        }
    }

    free(tcp_fds);
    free(udp_fds);
    return 0;

fail:
    {
        int saved = errno;
        free(tcp_fds);
        free(udp_fds);
        errno = saved;
    }
    return -1;
#endif
}

/*
 * build_credentials_path
 * dir: Base directory pointed to by $CREDENTIALS_DIRECTORY.
 * path_out: Receives the heap-allocated path "<dir>/shutdown.token".
 */
static int build_credentials_path(const char *dir, char **path_out)
{
    if (!dir || !path_out) {
        errno = EINVAL;
        return -1;
    }

    size_t dir_len = strlen(dir);
    const char *basename = EPOLL_ECHO_CREDENTIAL_TOKEN_BASENAME;
    size_t base_len = strlen(basename);
    bool need_sep = dir_len == 0 || dir[dir_len - 1] != '/';
    size_t total = dir_len + (need_sep ? 1 : 0) + base_len + 1;

    char *path = malloc(total);
    if (!path) {
        return -1;
    }

    int written = snprintf(path,
                           total,
                           need_sep ? "%s/%s" : "%s%s",
                           dir,
                           basename);
    if (written < 0 || (size_t)written >= total) {
        free(path);
        errno = EINVAL;
        return -1;
    }

    *path_out = path;
    return 0;
}

/*
 * load_token_from_path
 * path: Absolute or relative path to a token file.
 * require_owner_only: When true, enforce mode 0600 semantics (no group/other).
 * token_out/token_len_out: Receives heap buffer and length.
 */
static int load_token_from_path(const char *path,
                                bool require_owner_only,
                                char **token_out,
                                size_t *token_len_out)
{
    if (!path || !token_out || !token_len_out) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if (require_owner_only) {
        mode_t perms = st.st_mode & 0777;
        mode_t expected = S_IRUSR | S_IWUSR;
        if (perms != expected) {
            close(fd);
            errno = EPERM;
            return -1;
        }
    }

    char *buf = NULL;
    size_t len = 0;
    int rc = slurp_fd(fd, &buf, &len);
    int err = errno;
    close(fd);
    if (rc != 0) {
        errno = err;
        return -1;
    }

    *token_out = buf;
    *token_len_out = len;
    return 0;
}

/*
 * load_token_from_credentials_dir
 * dir: Path from $CREDENTIALS_DIRECTORY.
 * token_out/token_len_out: Receives file contents.
 */
static int load_token_from_credentials_dir(const char *dir,
                                           char **token_out,
                                           size_t *token_len_out)
{
    if (!dir) {
        errno = EINVAL;
        return -1;
    }

    char *path = NULL;
    if (build_credentials_path(dir, &path) != 0) {
        return -1;
    }

    int rc = load_token_from_path(path, false, token_out, token_len_out);
    int err = errno;
    free(path);
    errno = err;
    return rc;
}

/*
 * load_shutdown_token
 * cfg: CLI-derived configuration used for fallback token files.
 * Effect: Installs the shutdown token (if any) into the cmd module so that
 * `/shutdown` requests can be authenticated. Preferred source is the
 * systemd-provided credential directory; the CLI file path is a fallback.
 */
static int load_shutdown_token(const struct epoll_echo_config *cfg)
{
    const char *cred_dir = getenv(EPOLL_ECHO_CREDENTIALS_DIR_ENV);
    char *token = NULL;
    size_t token_len = 0;

    if (cred_dir && cred_dir[0] != '\0') {
        if (load_token_from_credentials_dir(cred_dir, &token, &token_len) == 0) {
            int rc = cmd_set_shutdown_token(token, token_len);
            int err = errno;
            free(token);
            if (rc != 0) {
                LOG_ERROR("shutdown: failed to install token from credentials directory: %s",
                          strerror(err));
                errno = err;
                return -1;
            }

            LOG_INFO("shutdown: using credential '%s' from %s",
                     EPOLL_ECHO_CREDENTIAL_TOKEN_BASENAME,
                     cred_dir);
            return 0;
        }

        int err = errno;
        LOG_WARN("shutdown: could not read credential '%s' under '%s': %s",
                 EPOLL_ECHO_CREDENTIAL_TOKEN_BASENAME,
                 cred_dir,
                 strerror(err));
    }

    if (cfg && cfg->shutdown_token_file) {
        if (load_token_from_path(cfg->shutdown_token_file,
                                 true,
                                 &token,
                                 &token_len) != 0) {
            int err = errno;
            LOG_ERROR("shutdown: failed to read token file '%s': %s",
                      cfg->shutdown_token_file,
                      strerror(err));
            errno = err;
            return -1;
        }

        int rc = cmd_set_shutdown_token(token, token_len);
        int err = errno;
        free(token);
        if (rc != 0) {
            LOG_ERROR("shutdown: failed to install token from '%s': %s",
                      cfg->shutdown_token_file,
                      strerror(err));
            errno = err;
            return -1;
        }

        LOG_INFO("shutdown: using token from file '%s'", cfg->shutdown_token_file);
        return 0;
    }

    if (cmd_set_shutdown_token(NULL, 0) != 0) {
        LOG_ERROR("shutdown: failed to clear shutdown token");
        return -1;
    }

    LOG_INFO("shutdown: no token configured; /shutdown remains disabled");
    return 0;
}

int main(int argc, char **argv)
{
    struct loop_context *loop = NULL;
    struct tcp_server *tcp = NULL;
    struct udp_server *udp = NULL;

    struct epoll_echo_config cfg;
    epoll_echo_config_init(&cfg);

    bool cli_should_exit = false;
   int cli_exit_code = EXIT_SUCCESS;
   int exit_code = EXIT_FAILURE;
    struct net_listener *activation_tcp = NULL;
    struct net_listener *activation_udp = NULL;

    if (cli_parse(argc, argv, &cfg, &cli_should_exit, &cli_exit_code) != 0) {
        goto cleanup;
    }

    if (cli_should_exit) {
        exit_code = cli_exit_code;
        goto cleanup;
    }

    log_set_verbosity(cfg.verbosity_delta);

    if (load_shutdown_token(&cfg) != 0) {
        goto cleanup;
    }

    if (adopt_systemd_sockets(&activation_tcp, &activation_udp) != 0) {
        goto cleanup;
    }

    if (activation_tcp) {
        cfg.tcp_port = net_listener_port(activation_tcp);
        LOG_INFO("systemd: adopting %zu TCP listener fd(s)",
                 net_listener_fd_count(activation_tcp));
        if (net_listener_register_prebound(activation_tcp) != 0) {
            LOG_ERROR("systemd: failed to register TCP listener: %s",
                      strerror(errno));
            goto cleanup;
        }
        activation_tcp = NULL;
    }

    if (activation_udp) {
        cfg.udp_port = net_listener_port(activation_udp);
        LOG_INFO("systemd: adopting %zu UDP listener fd(s)",
                 net_listener_fd_count(activation_udp));
        if (net_listener_register_prebound(activation_udp) != 0) {
            LOG_ERROR("systemd: failed to register UDP listener: %s",
                      strerror(errno));
            goto cleanup;
        }
        activation_udp = NULL;
    }

    log_startup_summary(&cfg);

    struct ep_stats stats;
    stats_init(&stats);

    if (loop_init(&loop) != 0) {
        int err = errno;
        LOG_ERROR("failed to initialize event loop: %s", strerror(err));
        goto cleanup;
    }

    struct tcp_server_config tcp_cfg;
    tcp_server_config_init(&tcp_cfg);
    tcp_cfg.net.port = cfg.tcp_port;
    tcp_cfg.net.backlog = cfg.backlog;
    tcp_cfg.max_clients = cfg.max_tcp;
    tcp_cfg.max_line = cfg.max_line;

    if (tcp_server_init(&tcp, &tcp_cfg, &stats) != 0) {
        int err = errno;
        LOG_ERROR("failed to initialize TCP server: %s", strerror(err));
        goto cleanup;
    }

    struct udp_server_config udp_cfg;
    udp_server_config_init(&udp_cfg);
    udp_cfg.net.port = cfg.udp_port;

    if (udp_server_init(&udp, &udp_cfg, &stats) != 0) {
        int err = errno;
        LOG_ERROR("failed to initialize UDP server: %s", strerror(err));
        goto cleanup;
    }

    if (tcp_server_register(tcp, loop) != 0) {
        LOG_ERROR("failed to register TCP listeners");
        goto cleanup;
    }

    if (udp_server_register(udp, loop) != 0) {
        LOG_ERROR("failed to register UDP listeners");
        goto cleanup;
    }

    LOG_INFO("listening (TCP port=%u, UDP port=%u)",
             (unsigned)cfg.tcp_port,
             (unsigned)cfg.udp_port);

    loop_run(loop);

    if (loop_shutdown_requested(loop)) {
        LOG_INFO("shutdown requested; exiting cleanly");
        exit_code = EXIT_SUCCESS;
    } else {
        LOG_ERROR("event loop exited unexpectedly");
    }

cleanup:
    net_listener_destroy(activation_udp);
    net_listener_destroy(activation_tcp);
    udp_server_free(udp);
    tcp_server_free(tcp);
    loop_free(loop);
    cmd_clear_shutdown_token();
    epoll_echo_config_reset(&cfg);
    return exit_code;
}
