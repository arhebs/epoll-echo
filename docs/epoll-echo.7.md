# epoll-echo(7) — epoll-based TCP/UDP echo daemon

## NAME

`epoll-echo` — single-process echo server for TCP and UDP using epoll on
GNU/Linux.

## SYNOPSIS

```sh
epoll-echo [OPTIONS]
```

Common examples:

```sh
epoll-echo --port=12345
epoll-echo --tcp-port=12345 --udp-port=12346
epoll-echo --port=12345 --max-tcp=2048 --backlog=256
```

When compiled with systemd support:

```sh
systemd-socket-activate --listen=[::]:12345 ./epoll-echo
systemd-socket-activate --datagram --listen=[::]:12345 ./epoll-echo
```

## DESCRIPTION

`epoll-echo` is a small, single-process daemon that demonstrates robust
non-blocking I/O on GNU/Linux using a level-triggered epoll loop. It accepts
both TCP and UDP clients:

- TCP uses a **line-oriented** protocol with a 4 KiB per-line cap.
- UDP treats each datagram as a message and detects truncated datagrams via
  `recvmsg()` + `MSG_TRUNC`.

Lines beginning with `/` are interpreted as **commands**; all others are echoed
back verbatim (subject to the configured maximum line length).

The server is intended for interview exercises, demonstrations of epoll and
socket APIs, and light operational scenarios where systemd integration and
observability via journald are desirable.

By default the daemon prefers an IPv6 listener with `IPV6_V6ONLY=0` so a
single socket can service both IPv6 and IPv4 (v4-mapped) clients. On systems
that enforce `bindv6only=1`, it automatically falls back to separate IPv4 and
IPv6 sockets to preserve dual-stack behavior.

## OPTIONS

- `--port N`  
  Bind TCP and UDP listeners to port `N` (default `12345`).

- `--tcp-port N`  
  Bind the TCP listener to port `N` only.

- `--udp-port N`  
  Bind the UDP listener to port `N` only.

- `--max-tcp N`  
  Maximum number of concurrent TCP clients (default `1024`). When the limit is
  reached the server still accepts, replies with `server busy`, and closes the
  connection.

- `--backlog N`  
  Requested TCP listen backlog (default `128`). The effective backlog is
  limited by `net.core.somaxconn`.

- `--max-line N`  
  Maximum permitted TCP line length in bytes (default `4096`).

- `--shutdown-token-file PATH`  
  Fallback path to a shutdown token. Prefer systemd credentials (see
  “Systemd credentials”).

- `-v`, `-vv`  
  Increase logging verbosity.

- `-q`  
  Reduce logging verbosity.

- `-h`, `--help`  
  Print usage and exit.

## PROTOCOL

### TCP

- Messages are delimited by `\n` or `\r\n`; a trailing `\r` is stripped.
- Lines longer than the configured maximum result in an `ERR too-long-line`
  response and resynchronization at the next newline; two consecutive
  overflows cause the connection to be closed.

Commands:

- `/time` — UTC timestamp (`YYYY-MM-DD HH:MM:SS`).
- `/stats` — `total_clients tcp_connected_now udp_active_60s`.
- `/shutdown <token>` — TCP + loopback + valid token only; requests a clean
  shutdown.

### UDP

- Each datagram is a message; no application-level fragmentation.
- `/time` and `/stats` are supported.
- `/shutdown` is rejected with `ERR shutdown-not-allowed`.
- Truncated datagrams generate `ERR datagram-truncated`.

The statistics counters used by `/stats` have the following semantics:

- `total_clients` counts TCP accepts plus unique UDP `(ip,port)` tuples ever
  seen during the process lifetime.
- `udp_active_60s` counts distinct UDP peers seen in the last 60 seconds,
  aged out by the timerfd tick.

## EPOLL & EVENT LOOP

- All sockets are non-blocking and registered with a level-triggered epoll
  instance.
- TCP connections use `EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP`; `EPOLLOUT`
  is enabled only when a write queue is non-empty and disabled after it drains.
- Accept, read, and write loops continue until `EAGAIN`/`EWOULDBLOCK` to avoid
  starvation under load.
- `signalfd` is used to handle `SIGINT`/`SIGTERM` inside the event loop.
- A `timerfd` ticks roughly once per second to expire inactive UDP peers from
  the 60s window used by `/stats`.

## SYSTEMD INTEGRATION

### Simple service

`epoll-echo` can be run as a simple systemd service using the example unit in
`systemd/epoll-echo.service`. Logs are captured by journald:

```sh
journalctl -u epoll-echo
```

### Systemd credentials

To supply the `/shutdown` token securely, use systemd credentials:

```ini
[Service]
ExecStart=/usr/bin/epoll-echo --port=12345
LoadCredential=shutdown.token:/etc/epoll-echo/shutdown.token
```

The daemon reads the token from `$CREDENTIALS_DIRECTORY/shutdown.token`.

### Socket activation

When compiled with `ENABLE_SYSTEMD=1`, `epoll-echo` can adopt sockets passed by
systemd via `sd_listen_fds()`. Example `.socket` and `.service` units are
provided in the `systemd/` directory.

## PACKAGING

The source tree includes Debian packaging metadata under the `debian/`
directory. A native package can be built using `dpkg-buildpackage -us -uc`,
which produces an `epoll-echo` binary installed into `/usr/bin/` along with
the usual `.deb` artefacts.

## SEE ALSO

`epoll(7)`, `socket(7)`, `listen(2)`, `recvmsg(2)`, `send(2)`,
`systemd.service(5)`, `systemd.socket(5)`, `systemd.special(7)`,
`journalctl(1)`.
