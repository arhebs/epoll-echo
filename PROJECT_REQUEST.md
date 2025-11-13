# PROJECT_REQUEST.md — epoll-echo (v3)

A single-process server in C/C++ for GNU/Linux that asynchronously handles **TCP and UDP** clients via **epoll**. TCP uses a **line-delimited** text protocol; UDP treats each datagram as a message. Lines starting with `/` are **commands**; all others are echoed back.

## Target Audience
- Interviewers validating Linux networking/epoll proficiency.
- Operators who expect clean systemd/journal integration and sane limits.
- Security reviewers (guarded `/shutdown`, UDP caveats).

## Desired Features

### Networking & Sockets
- **Dual-stack IPv4/IPv6.** Prefer an `AF_INET6` socket with `IPV6_V6ONLY=0` for true dual-stack; allow an optional dedicated IPv4 socket to cover distros that default to `V6ONLY=1`. :contentReference[oaicite:0]{index=0}
- **Ports.** By default bind **TCP and UDP** to the same numeric port on all interfaces. CLI: `--port N` (applies to both), optional `--tcp-port N`, `--udp-port N`.
- **Creation & accept flags (must-have).** Create sockets atomically with `SOCK_NONBLOCK|SOCK_CLOEXEC`; use `accept4(..., SOCK_NONBLOCK|SOCK_CLOEXEC)` so non-blocking and close-on-exec are set without racy `fcntl`. :contentReference[oaicite:1]{index=1}
- **Reuse & backlog.** Set `SO_REUSEADDR`. Make the **listen backlog** configurable and document kernel cap via `net.core.somaxconn`. :contentReference[oaicite:2]{index=2}

### Event Loop & Robustness (epoll)
- **Level-triggered** epoll with **non-blocking** I/O; always drain **accept/read/write** loops until `EAGAIN`. Register **`EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP`** for TCP sockets. Enable **`EPOLLOUT` only when the per-connection write-queue is non-empty**, then drop it after flushing. :contentReference[oaicite:3]{index=3}
- **Signals & timers.** Handle `SIGINT`/`SIGTERM` via **`signalfd`** inside the epoll loop for graceful shutdown; add a **`timerfd`** (tick ≈ 1s) to expire inactive UDP peers from the 60s window. :contentReference[oaicite:4]{index=4}
- **SIGPIPE safety (must-have).** Prevent process termination on closed peers by using `send(..., MSG_NOSIGNAL)` or ignoring `SIGPIPE` process-wide. :contentReference[oaicite:5]{index=5}

### Protocol — TCP
- **Line-delimited text.** Each line is one message. Accept both `\r\n` and `\n`; trim a trailing `\r`. (HTTP/1.1 allows recipients to treat LF as a line terminator.) :contentReference[oaicite:6]{index=6}
- **Max line length (must-have policy).** **4 KiB per line.** If the limit is exceeded **before** EOL: send `ERR too-long-line\n`, **discard bytes until the next LF to resynchronize**, and if **two consecutive** overflows occur, **close** the connection. (Prevents desync and churn.)  
- **Commands.**
  - `/time` → **UTC** time `YYYY-MM-DD HH:MM:SS` using `strftime("%F %T")`.  
  - `/stats` → three integers: `total_clients tcp_connected_now udp_active_60s`.
  - `/shutdown <token>` → **TCP-only**, **loopback-only** (`127.0.0.0/8` or `::1`), with valid token; reply `OK, shutting down` then exit.

### Protocol — UDP
- **Message = datagram.** Echo non-command payloads; implement `/time` and `/stats`. **Always reject `/shutdown`** on UDP (spoofable). :contentReference[oaicite:7]{index=7}
- **Stats semantics.**  
  - `total_clients` = TCP accepts **+** unique UDP `(ip,port)` **ever** seen (process lifetime).  
  - `udp_active_60s` = unique UDP peers seen in the last **60s** (timer-aged).
- **Truncation handling (must-have).** Use `recvmsg` and check `msg_flags & MSG_TRUNC`; if truncated, reply `ERR datagram-truncated\n` to the sender. Optionally size-probe with `MSG_TRUNC|MSG_PEEK`. :contentReference[oaicite:8]{index=8}

### Security & Secrets
- **Guard `/shutdown`.** Enforce **TCP + loopback + token**; reject all UDP attempts. (UDP is connectionless and easily **spoofed**.) :contentReference[oaicite:9]{index=9}
- **Token provisioning (must-have).**  
  - **Preferred (systemd credentials):** read token from `$CREDENTIALS_DIRECTORY/<name>` supplied via `LoadCredential=`. Fail closed if missing. :contentReference[oaicite:10]{index=10}  
  - **Fallback:** `--shutdown-token-file=/secure/path` (0600). Avoid argv/env secrets.

### Limits & Resource Management
- **Max concurrent TCP clients.** Default **1024**, configurable. If at capacity: `accept` then immediately send `server busy\n` and close. Document interaction with **`RLIMIT_NOFILE`** and how to raise it (and/or unit `LimitNOFILE=`). :contentReference[oaicite:11]{index=11}
- **Buffers.** TCP per-connection read buffer sufficient for 4 KiB lines; per-connection write-queue drained on `EPOLLOUT`.

### Observability & Ops
- **Binary:** `epoll-echo`.
- **Logging:** INFO by default; `-v/-vv/-q` control verbosity. Log to **stdout/stderr**; captured by journald (`journalctl -u epoll-echo`).  
- **Systemd units.**  
  - Simple `.service` binding sockets itself.  
  - **Bonus: socket activation** — provide `.socket` units for **TCP (Stream)** and **UDP (Datagram)** and a `.service` that adopts FDs via `sd_listen_fds()` (FDs start at 3). Include local test with `systemd-socket-activate` (`--datagram` for UDP). :contentReference[oaicite:12]{index=12}
- **Packaging (Debian/Ubuntu).** Ship a minimal `.deb` using **debhelper**, with `Build-Depends: debhelper-compat (= 13)` (no `debian/compat`). Include `debian/{control,rules,install,changelog}`. :contentReference[oaicite:13]{index=13}

## Design Requests

- **CLI**  
  `epoll-echo --port 12345 [--tcp-port N] [--udp-port N] [--max-tcp 1024] [--backlog 128] [--max-line 4096] [-v|-vv|-q] [--shutdown-token-file /path]`
- **Modules**  
  `main.c`, `loop.c`, `tcp.c`, `udp.c`, `cmd.c`, `stats.c`, `timeutil.c`
- **I/O details (must-have)**  
  - Register `EPOLLIN|EPOLLRDHUP|EPOLLERR|EPOLLHUP`; add/remove `EPOLLOUT` around non-empty write-queues. Drain accept/read/write until `EAGAIN`. :contentReference[oaicite:14]{index=14}  
  - Use `send(..., MSG_NOSIGNAL)` (or ignore `SIGPIPE`). :contentReference[oaicite:15]{index=15}  
  - TCP overflow policy: `ERR too-long-line`, resync (discard to LF), close on repeated overflow.  
  - UDP truncation: detect with `recvmsg` `MSG_TRUNC`; send `ERR datagram-truncated\n`. :contentReference[oaicite:16]{index=16}
- **Time**  
  `/time` uses UTC via `strftime("%F %T")`.

## Acceptance & Test Plan

- **Dual-stack:** Connect via `nc -4 127.0.0.1 12345` and `nc -6 ::1 12345`. Confirm `IPV6_V6ONLY=0` or separate IPv4 socket as needed. :contentReference[oaicite:17]{index=17}  
- **Epoll masks & drains:** Burst sends verify no spins and correct `EPOLLOUT` toggling. :contentReference[oaicite:18]{index=18}  
- **TCP framing:** `printf 'a\r\nb\n' | nc ::1 12345` → echoes `a`, `b`. (CRLF/LF tolerance per RFC 9112 §2.2.) :contentReference[oaicite:19]{index=19}  
- **Overflow policy:** Send >4096 bytes without LF → receive `ERR too-long-line`; next LF resyncs; second consecutive overflow closes.  
- **SIGPIPE safety:** Close client mid-write → server continues (no crash). :contentReference[oaicite:20]{index=20}  
- **UDP truncation:** Send an oversize datagram → server responds `ERR datagram-truncated`. :contentReference[oaicite:21]{index=21}  
- **/stats window:** UDP peer appears in `udp_active_60s`, ages out after 60s tick.  
- **/shutdown hardening:** Works only via TCP from loopback with correct token; all UDP attempts rejected. (UDP spoofing risk rationale.) :contentReference[oaicite:22]{index=22}  
- **Socket activation:** Test with `systemd-socket-activate --listen=[::]:12345` (TCP) and `--datagram` (UDP); server adopts FDs 3+. :contentReference[oaicite:23]{index=23}  
- **Packaging:** Build with `debhelper-compat (= 13)` workflow. :contentReference[oaicite:24]{index=24}
