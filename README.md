# epoll-echo

A single-process GNU/Linux echo server that demonstrates robust epoll-based
handling of TCP and UDP clients. The project is organized around discrete
implementation steps defined in `IMPLEMENTATION_PLAN.md` and ships with
systemd units, Debian packaging metadata, and a minimal GitHub Actions CI
workflow.

At a high level:

- The server is **single-process**, written in **C11**.
- TCP uses a **line-oriented** text protocol with a 4 KiB per-line cap.
- UDP treats each datagram as a standalone message with truncation detection.
- All sockets are **non-blocking** and driven by a **level-triggered epoll**
  loop that drains accepts/reads/writes until `EAGAIN`.

## Building

```sh
sudo apt-get install -y build-essential pkg-config
make
```

Optional systemd socket activation helpers can be linked by enabling the flag:

```sh
make ENABLE_SYSTEMD=1
```

The resulting binary is called `epoll-echo`.

## CLI Reference

The daemon is configured via a small set of flags that match the project
specification in `PROJECT_REQUEST.md` and `TECHNICAL_SPECIFICATION.md`.

Common options:

- `--port N`  
  Bind both TCP and UDP listeners to port `N` (default: `12345`). This is a
  convenience that sets both `--tcp-port` and `--udp-port` when they are not
  specified explicitly.

- `--tcp-port N`  
  Override the TCP listener port only.

- `--udp-port N`  
  Override the UDP listener port only.

- `--max-tcp N`  
  Maximum number of concurrent TCP clients that will be serviced (default
  `1024`). Once the cap is reached the server continues to accept but replies
  with `server busy` and immediately closes the connection.

- `--backlog N`  
  Requested TCP listen backlog (default `128`). The kernel applies `min(N,
  net.core.somaxconn)` internally; see the backlog and sysctl notes below.

- `--max-line N`  
  Maximum permitted line length for TCP clients in bytes (default `4096`,
  minimum and maximum are clamped to conservative bounds). Lines that exceed
  this limit trigger the overflow policy described in the technical
  specification.

- `--shutdown-token-file /path/to/file`  
  Optional path to a token file used to guard the `/shutdown` command. This is
  a **fallback** to systemd credentials: the preferred mechanism is to supply
  the token via `$CREDENTIALS_DIRECTORY` (see “Systemd credentials” below).

- `-v`, `-vv`  
  Increase logging verbosity (DEBUG-level tracing at `-vv`).

- `-q`  
  Reduce logging verbosity (quiet mode).

- `--help`, `-h`  
  Print usage and exit.

If both systemd socket activation and CLI ports are in play, the adopted
systemd sockets win: after adoption, the effective TCP/UDP ports are derived
from the passed file descriptors and reflected in startup logs.

## Protocol Overview

### TCP

- Each **line** is treated as one message.
- Both `\n` and `\r\n` terminators are accepted; a trailing `\r` is trimmed.
- Lines longer than the configured `--max-line` (default 4 KiB) trigger:
  - `ERR too-long-line\n` sent to the client.
  - bytes discarded until the next `\n` to resynchronize.
  - after **two consecutive** overflows, the connection is closed.

Commands (lines starting with `/`):

- `/time`  
  Returns UTC time in `YYYY-MM-DD HH:MM:SS` using `clock_gettime` +
  `strftime("%F %T")`.

- `/stats`  
  Returns three integers separated by spaces:  
  `total_clients tcp_connected_now udp_active_60s`

- `/shutdown <token>`  
  Only valid on **TCP** connections from loopback addresses (`127.0.0.0/8` or
  `::1`) with a correct token configured via systemd credentials or
  `--shutdown-token-file`. On success the server replies
  `OK, shutting down` and exits cleanly.

Any non-command line (not starting with `/`) is echoed back verbatim (subject
to the max-line policy).

### UDP

- Each datagram is treated as one message; the server never reassembles or
  fragments at the application level.
- `/time` and `/stats` work similarly to TCP.
- `/shutdown` is **never** honored over UDP and always yields
  `ERR shutdown-not-allowed\n` (UDP is trivially spoofable).
- `recvmsg()` is used with truncation detection; when `MSG_TRUNC` is observed
  the server replies `ERR datagram-truncated\n` and does not attempt to use
  the partial payload.

UDP peers contribute to the statistics:

- `total_clients` counts TCP accepts plus unique UDP `(ip,port)` pairs ever
  seen during the process lifetime.
- `udp_active_60s` counts UDP peers seen in the last 60 seconds, aged out via
  an internal timer.

## Epoll Design & Event Loop

The server uses a single-threaded, **level-triggered** epoll loop:

- All sockets are created with `SOCK_NONBLOCK | SOCK_CLOEXEC`.
- TCP connection file descriptors are registered with
  `EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP` by default.
- `EPOLLOUT` is enabled only when a connection’s write queue becomes non-empty
  and is removed again once all pending bytes have been flushed.
- On readiness, accepts, reads, and writes all **drain in a loop** until
  `EAGAIN` or `EWOULDBLOCK` is reached, ensuring no head-of-line blocking in a
  level-triggered environment.

The loop also integrates:

- `signalfd` for `SIGINT`/`SIGTERM`, registered in epoll so shutdown is
  handled asynchronously inside the main loop.
- `timerfd` ticking approximately once per second to drive UDP peer aging and
  any other periodic housekeeping.
- A wakeup fd to break out of `epoll_wait` when a shutdown is requested so the
  process can exit promptly.

These behaviors are validated by the shell scripts in `tests/` (framing,
overflow, SIGPIPE resilience, UDP truncation, stats window, and shutdown).

## Testing

The `tests/` directory contains focused shell scripts that exercise each
acceptance scenario (dual-stack TCP, CRLF/LF framing, overflow policy, UDP
truncation, stats aging, `/shutdown`, SIGPIPE resilience, and systemd socket
activation). Run them individually after building the server, for example:

```sh
tests/dualstack.sh
tests/socket_activation.sh   # requires ENABLE_SYSTEMD=1 binaries
```

These scripts rely on standard userland tools: `python3`, `timeout`, `nc`
(`netcat-openbsd`), `hexdump`, `cc` (to compile a small LD_PRELOAD shim), and
`systemd-socket-activate`. Installing `socat` is also recommended for manual UDP
spot-checks alongside the scripted coverage. Ensure the binary exists (`make`
or `make ENABLE_SYSTEMD=1`) before invoking the tests.

## Directory Overview

- `src/` – C sources grouped by subsystem (main, loop, tcp, udp, etc.).
- `include/` – Project headers shared across modules.
- `tests/` – Integration and acceptance tests implemented as shell scripts.
- `systemd/` – Example `.service`/`.socket` units for simple and activated modes.
- `debian/` – Debhelper packaging metadata for building `.deb` artifacts.
- `docs/` – Manpage stub and additional documentation.
- `.github/` – GitHub Actions workflow used for CI on this repository.

Refer to `PROJECT_REQUEST.md` and `TECHNICAL_SPECIFICATION.md` for the full
feature set and acceptance criteria.

## Dual-stack Networking, Backlog & Kernel Caps

- TCP and UDP listeners prefer an `AF_INET6` socket with `IPV6_V6ONLY=0` so a
  single socket can handle both IPv6 and IPv4 (v4-mapped) traffic.
- On systems where the kernel or distro forces `IPV6_V6ONLY=1` (for example
  via `/proc/sys/net/ipv6/bindv6only`), the server automatically falls back to
  **separate IPv4 and IPv6 sockets** to preserve dual-stack behavior.
- The TCP backlog passed to `listen(2)` is taken from `--backlog N` but is
  ultimately capped by the kernel `net.core.somaxconn` sysctl. The effective
  backlog is roughly:

  ```text
  effective_backlog = min(--backlog, net.core.somaxconn)
  ```

To raise the backlog cap temporarily:

```sh
sudo sysctl -w net.core.somaxconn=1024
```

To make the change persistent across reboots, add a drop-in file such as:

```sh
echo 'net.core.somaxconn = 1024' | sudo tee /etc/sysctl.d/99-epoll-echo.conf
sudo sysctl --system
```

This does **not** remove the need to size `--backlog` appropriately; both the
CLI flag and the sysctl interact.

## Capacity & Resource Limits

- The `--max-tcp N` flag caps concurrent TCP clients (default `1024`). When
  the limit is reached the server still accepts the socket, writes
  `server busy` best-effort, and closes immediately so clients see a clear
  rejection.
- Each TCP connection and the core event-loop descriptors (listeners,
  `signalfd`, `timerfd`) consume file descriptors. If the process hits the
  kernel-imposed `RLIMIT_NOFILE` (`ulimit -n`), new accepts will fail even if
  `--max-tcp` has headroom. Raise the limit before launching or via systemd.
- Interactive example:

  ```sh
  ulimit -n 4096
  ./epoll-echo --max-tcp 2048
  ```

- systemd service override (see `man 7 resource_limits`):

  ```ini
  [Service]
  LimitNOFILE=8192
  ```

  Restart the unit after adjusting the limit to ensure the daemon inherits the
  updated cap.

## Logging & Journald

- All logs are written to **stdout/stderr** using a small leveled logger.
- The default level is INFO; verbosity can be adjusted with `-v`, `-vv`, or
  `-q`.
- When running under systemd, logs are captured automatically by journald.

Common journald queries:

```sh
sudo journalctl -u epoll-echo             # simple service
sudo journalctl -u epoll-echo-activated   # socket-activated variant
```

You can add `-f` to tail the logs in real time.

## Systemd Integration

The repository ships with example unit files under `systemd/`.

### Simple service

`systemd/epoll-echo.service` runs the daemon directly, binding its own sockets
and logging to journald:

```ini
[Service]
ExecStart=/usr/bin/epoll-echo --port=12345
Restart=on-failure
LimitNOFILE=8192
```

Install and manage the service:

```sh
sudo cp systemd/epoll-echo.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now epoll-echo
```

### Systemd credentials for /shutdown

The preferred way to provide the `/shutdown` token is via systemd’s credential
mechanism:

```ini
[Service]
ExecStart=/usr/bin/epoll-echo --port=12345
LoadCredential=shutdown.token:/etc/epoll-echo/shutdown.token
```

With this configuration systemd mounts the credential into a private directory
and sets `$CREDENTIALS_DIRECTORY`, which the server uses to locate
`shutdown.token`. The CLI flag `--shutdown-token-file` remains available as a
fallback when systemd credentials are not used.

### Socket activation

Socket activation allows systemd to own the listening sockets and start the
daemon on first connection:

```sh
systemd-socket-activate --listen=[::]:12345 ./epoll-echo
systemd-socket-activate --datagram --listen=[::]:12345 ./epoll-echo
```

In a full systemd deployment, the `.socket` units in `systemd/` define the
TCP/UDP listeners and pass the resulting file descriptors to
`epoll-echo-activated.service`, which adopts them via `sd_listen_fds()`. When
compiled with `ENABLE_SYSTEMD=1`, the binary automatically checks for and
adopts such pre-bound sockets instead of binding its own.
