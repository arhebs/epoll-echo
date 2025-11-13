# TECHNICAL_SPECIFICATION.md — epoll-echo (v3)

---

## 1. Planning & Discovery

### 1.1 Core Purpose & Success

* **Mission Statement**: A tiny, production‑friendly echo daemon that demonstrates expert Linux networking (epoll, TCP/UDP) with solid ops ergonomics.

* **Core Purpose & Goals**

  * Exercise and validate epoll/socket mastery via a minimal but complete server handling TCP lines and UDP datagrams. 
  * Be safe-by-default (no SIGPIPE crashes; guarded shutdown) and easy to operate under systemd. 
  * Provide a clean baseline for interviews and future extensions.

* **Success Indicators**

  * All acceptance tests in the request pass (dual-stack, epoll drains, CRLF/LF, overflow policy, UDP truncation, `/stats`, cred-guarded `/shutdown`, socket activation, Debian packaging). 
  * Zero busy loops under backpressure; no crashes on client abort; clean shutdown.

* **Experience Qualities**: **Predictable**, **observable**, **secure-by-default**.

### 1.2 Project Classification & Approach

* **Complexity Level**: *Light App / System daemon*.
* **Primary User Activity**: Interacting (clients send/receive lines/datagrams; operators manage service).
* **Primary Use Cases**

  * TCP line echo + commands `/time`, `/stats`, `/shutdown` (last one guarded). 
  * UDP datagram echo + `/time`, `/stats` (no `/shutdown`). 
  * Ops: run under systemd, view logs via journal, test socket activation. 

### 1.3 Feature-Selection Rationale

* **Core Problem**: Show robust asynchronous I/O with backpressure handling and protocol framing that tolerates real-world newline variations (CRLF or LF). RFC 9112 explicitly allows recipients to accept a lone LF as a line terminator. ([RFC Editor][1])
* **User Context**: Local development and VM/container targets; systemd-managed in production-like environments. 
* **Critical Path**: Start daemon → connect via TCP/UDP → send data → receive echo/command response → observe via journal → `/shutdown` (guarded). 
* **Key Moments**

  1. Dual-stack binding and acceptance of both IPv4 and IPv6 connections using an AF_INET6 socket with `IPV6_V6ONLY=0` where supported.  ([man7.org][2])
  2. Correct epoll loop behavior under bursty I/O (toggle `EPOLLOUT` only when needed). 
  3. Clean `/shutdown` using systemd credentials and loopback enforcement. 

### 1.4 High-Level Architecture Overview

**Textual Map**

* **Client(s)**: TCP line clients, UDP datagram senders (nc/socat/scripts).
* **Server (this project)**:

  * `main` boots, parses CLI, builds listening sockets (or adopts via systemd), builds epoll set.
  * `loop` runs the epoll wait/dispatch; registers timerfd and signalfd. ([man7.org][3])
  * `tcp` manages accepts, per-conn buffers, write queues.
  * `udp` processes datagrams; manages 60s active peer window.
  * `cmd` parses `/time` `/stats` `/shutdown`.
  * `stats` tracks counters.
  * `timeutil` provides UTC formatting.
* **OS / Libraries**: Linux kernel epoll; optional `libsystemd` for socket activation. ([man7.org][4])
* **Ops**: systemd `.service` + optional `.socket` units; journald logging on stdout/stderr. 

### 1.5 Essential Features (examples)

* **Dual-stack binding**

  * **Purpose**: One listener for IPv6 and IPv4 (via v4-mapped IPv6) or fall back to separate IPv4 socket. 
  * **Validation**: `nc -4 127.0.0.1 12345` and `nc -6 ::1 12345` both work. 

* **Epoll loop (LT) with drains**

  * **Purpose**: Avoid head-of-line stalls/spin; robust backpressure. 
  * **Validation**: Burst tests do not spin, `EPOLLOUT` toggles only when write queue non-empty. 

* **TCP framing & overflow policy**

  * **Purpose**: Accept CRLF or LF; enforce 4KiB line cap; resync on overflow. 
  * **Validation**: `printf 'a\r\nb\n' | nc ::1 12345` echoes both lines; overflow behavior matches spec. 

* **UDP truncation handling**

  * **Purpose**: Detect truncated datagrams and respond with a clear error. 
  * **Validation**: Oversized datagram yields `ERR datagram-truncated\n`. 

* **Secure `/shutdown`**

  * **Purpose**: Safe admin control via TCP+loopback+token only; credentials via systemd. 
  * **Validation**: TCP+loopback+correct token → `OK, shutting down`; UDP attempts are rejected. 

---

## 2. System Architecture & Technology

### 2.1 Tech Stack

* **Languages & Frameworks**: C11 (portable libc, POSIX).
* **Libraries & Dependencies**

  * Linux syscalls: `epoll`, `accept4`, `recvmsg`, `send`, `timerfd`, `signalfd`. ([man7.org][4])
  * Optional: `libsystemd` (`sd_listen_fds()` for socket activation). ([man7.org][5])
* **Database & ORM**: None.
* **DevOps & Hosting**: systemd service; optional socket activation; journald logs. 
* **CI/CD Pipeline**: GitHub Actions (build, unit tests, packaging job). (Design choice.)

### 2.2 Project Structure

```
/epoll-echo
  /src
    main.c        # CLI, config, systemd adoption, bootstrap
    loop.c        # epoll init, signalfd/timerfd, dispatch
    tcp.c         # listeners, accept, per-conn I/O state machine
    udp.c         # datagram I/O, /stats window mgmt
    cmd.c         # /time, /stats, /shutdown parsing/format
    stats.c       # counters and UDP peer window
    timeutil.c    # UTC time formatting
    log.h/.c      # leveled logging macros to stdout/stderr
    net.h/.c      # socket helpers (v6-only, reuseaddr, backlog, nonblocking)
    platform.h    # feature macros, compiler attributes
  /include        # public headers per module
  /debian         # debhelper packaging (control, rules, install, changelog)
  /systemd        # epoll-echo.service, epoll-echo.socket (+tcp,+udp variants)
  /tests          # integration scripts
```

* **Naming Conventions**: snake_case for C files; `epoll_echo_*` symbols; `struct EpConn`, `struct EpStats`.
* **Key Modules**: As requested. 

### 2.3 Component Architecture

#### Server / Backend

* **Framework**: Custom event loop on `epoll` (level-triggered). ([man7.org][4])
* **Data Models & Domain Objects**

  * `struct Conn` (TCP): fd, read buffer (≥ 4096+1), write queue list, overflow state, peer addr.
  * `struct WQItem`: iovec-like segment for queued writes.
  * `struct Stats`: `total_clients`, `tcp_connected_now`, `udp_active_60s`, plus LRU-ish map for UDP peer activity.
  * `struct UdpPeerKey`: (addr, port) tuple.
* **Error Boundaries**: A single fatal logger for unrecoverable setup errors; per-connection errors close only that FD; all syscalls checked.

#### Client / Frontend

* N/A (headless daemon). CLI parsing covers user interaction.

### 2.4 Data Flow & Real-Time

* **Request/Response Lifecycle**

  * TCP: `EPOLLIN` → read and frame lines; echo payload or run `/...` command; enqueue output → enable `EPOLLOUT`; on drain to empty → disable `EPOLLOUT`. Handle `EPOLLRDHUP`/`EPOLLHUP`/`EPOLLERR`. ([man7.org][4])
  * UDP: `recvmsg` → handle single datagram; detect `MSG_TRUNC`; respond. ([man7.org][6])
* **State Sync**: Counters updated on accept/disconnect; UDP peer activity updated at receive and via 60s tick of timerfd. ([man7.org][7])
* **Real-Time Updates**: Epoll wait with timeout tied to 1s timerfd cadence; signalfd wakes for SIGINT/SIGTERM. ([man7.org][3])

---

## 3. Database & Server Logic

### 3.1 Database Schema

* None (in-memory structures only). `udp_active_60s` maintained as a time-bucketed set keyed by `(ip,port)`.

### 3.2 Server Actions

#### Database Actions

* N/A.

#### Endpoints / Commands (over TCP & UDP)

* `/time` → UTC `YYYY-MM-DD HH:MM:SS` (`strftime("%F %T")`). 
* `/stats` → `total_clients tcp_connected_now udp_active_60s`. 
* `/shutdown <token>` → **TCP-only**, loopback-only, token matches → acknowledge then exit. All UDP attempts rejected. 

#### Representative call flow snippets (conceptual)

* **Accept path**

  * Listen sockets created with `SOCK_NONBLOCK|SOCK_CLOEXEC`; `accept4(..., SOCK_NONBLOCK|SOCK_CLOEXEC)` avoids racy `fcntl`.  ([man7.org][8])
  * Backlog configurable; kernel may cap to `net.core.somaxconn`. 

* **Read path (TCP)**

  * Read loop until `EAGAIN` or buffer full. If LF found: extract a line, strip trailing `\r`. If line begins with `/` → dispatch command; else echo.

* **Write path (TCP)**

  * Queue response segments; register `EPOLLOUT`; loop `send(..., MSG_NOSIGNAL)` until `EAGAIN` or queue empty; then clear `EPOLLOUT`.  ([man7.org][9])

* **UDP path**

  * `recvmsg` into fixed buffer; test `msg_flags & MSG_TRUNC`. If set: reply `ERR datagram-truncated\n`. Optionally use size probe via `MSG_TRUNC|MSG_PEEK`.  ([man7.org][6])

#### Other Backend Logic

* **Signals**: Subscribe to `SIGINT`/`SIGTERM` via `signalfd` and drain on graceful shutdown. ([man7.org][3])

* **Timers**: 1s `timerfd` tick to age out UDP peers (60s window). ([man7.org][7])

* **Socket options**:

  * Dual-stack preference: AF_INET6, `IPV6_V6ONLY=0` (noting default is controlled by `/proc/sys/net/ipv6/bindv6only` and defaults to `0`). Fallback to separate IPv4 socket if needed.  ([man7.org][2])
  * `SO_REUSEADDR` for restart ergonomics. 

* **systemd socket activation**: Adopt pre-opened FDs via `sd_listen_fds()` (FDs start at 3); verify stream vs datagram with helpers if linked. Provide a test with `systemd-socket-activate --datagram` for UDP.  ([man7.org][5])

* **File/Media handling**: N/A.

* **Background Jobs**: N/A (timerfd only).

---

## 4. Feature Specifications

### 4.1 TCP Echo (line‑delimited)

* **User Story & Requirements**

  * As a client, I send line(s); I receive the same lines back, framing tolerant to CRLF or LF. Enforce max 4 KiB per line with resync policy. 
* **Implementation Details**

  1. Per-conn read buffer `rbuf[4097]`. Accumulate until LF or overflow.
  2. On line end: if last byte is `\r`, drop it; enqueue echo.
  3. If buffer exceeds 4096 without LF: enqueue `ERR too-long-line\n`; set `overflowed=true` and enter resync mode (discard until LF), counting consecutive overflows; if two back-to-back overflows, close.
  4. Always use `send` with `MSG_NOSIGNAL` (or ignore `SIGPIPE` once at start). ([man7.org][9])
* **Edge Cases & Error Handling**

  * Handle `EPOLLRDHUP` (peer half-closed) and `EPOLLHUP`/`EPOLLERR` by draining readable bytes, then closing. ([man7.org][4])
* **UI/UX Considerations**

  * Responses end with `\n`. Error text is stable and greppable.

### 4.2 UDP Echo (datagram)

* **User Story & Requirements**

  * As a client, each datagram is echoed or handled as a command. `/shutdown` is always rejected on UDP. Maintain `udp_active_60s`. 
* **Implementation Details**

  * `recvmsg` into `buf[65535]`; if `MSG_TRUNC`, send `ERR datagram-truncated\n`. Record `(ip,port)` into activity window with current tick. ([man7.org][6])
* **Edge Cases**

  * Zero-length datagrams are valid; echo blank line. (Per `recvmsg` semantics.) ([man7.org][6])

### 4.3 `/time`

* **Requirements**: UTC timestamp `YYYY-MM-DD HH:MM:SS` via `strftime("%F %T")`. Available on TCP & UDP. 
* **Implementation**: `timeutil_format_utc()` uses `clock_gettime(CLOCK_REALTIME)`/`gmtime_r`/`strftime`.

### 4.4 `/stats`

* **Requirements**: Output `total_clients tcp_connected_now udp_active_60s`. TCP: `total_clients` increments on accept; UDP: `total_clients` also increments on first time seeing a new `(ip,port)`. 60s window ages via timerfd tick. 
* **Implementation**: Fixed-size open addressing hash table or `uthash`-like table (in-tree) for UDP peers with last-seen tick; a circular array of minute buckets is acceptable.

### 4.5 `/shutdown <token>`

* **Requirements**: TCP-only, loopback-only (`127.0.0.0/8` or `::1`) and token must match; reply and exit gracefully. All UDP attempts rejected due to spoofing risk. 

* **Implementation Details**

  * Load expected token from `$CREDENTIALS_DIRECTORY/<name>` when available (systemd `LoadCredential=`) or fallback `--shutdown-token-file` (0600). Fail fast if token required but missing. 
  * Check peer address is loopback before verifying token.
  * On success, set a shutdown flag and break loop after draining logs.

* **Reference**: Systemd credentials design & `LoadCredential=` in `systemd.exec`; `$CREDENTIALS_DIRECTORY` is provided by manager when credentials are delivered. ([systemd][10])

---

## 5. Design System

*(CLI + logs style)*

### 5.1 Visual Tone & Identity

* **Branding & Theme**: Minimal, terminal-friendly.
* **Emotional Response**: Confidence via concise logs.
* **Personality**: Precise and quiet by default; `-v/-vv` unlocks detail. 

### 5.2 Color Strategy

* Avoid color by default; keep logs machine-parseable. (Journal provides level filtering.)

### 5.3 Typography System

* N/A; monospace terminal.

### 5.4 Visual Hierarchy & Layout

* Log format: `ts=... lvl=INFO msg="..." conn=fd:123 raddr=...`. Include event keys consistently.

### 5.5 Animations

* N/A.

### 5.6 UI Elements & Components

* CLI flags exactly as requested:
  `epoll-echo --port 12345 [--tcp-port N] [--udp-port N] [--max-tcp 1024] [--backlog 128] [--max-line 4096] [-v|-vv|-q] [--shutdown-token-file /path]` 

### 5.7 Visual Consistency Framework

* Document log levels and message keys used across modules (`accept`, `close`, `read`, `write`, `overflow`, `udp_trunc`, `cmd`, `shutdown`, `cred`).

### 5.8 Accessibility & Readability

* Ensure journal-friendly severity mapping (INFO/DEBUG/WARN/ERROR). By default, systemd captures stdout/stderr into journald without extra configuration (`StandardOutput=journal` is default). ([Server Fault][11])

---

## 6. Security & Compliance

* **Encryption**: Out of scope (plain TCP/UDP). For production, terminate TLS at a proxy if needed.
* **Compliance**: No PII stored; no special regulatory scope.
* **Threat Modeling**

  * **UDP spoofing** → reject `/shutdown` over UDP; do not treat UDP address as identity. 
  * **SIGPIPE termination** → use `MSG_NOSIGNAL` or ignore SIGPIPE. ([man7.org][9])
  * **FD exhaustion** → enforce `--max-tcp`; document relation to `RLIMIT_NOFILE`.  ([man7.org][12])
  * **Credential leakage** → read token from systemd credentials or 0600 file; do not accept token via argv/env.
* **Secrets Management**

  * Prefer systemd `LoadCredential=`; read via `$CREDENTIALS_DIRECTORY`. ([systemd][10])

---

## 7. Optional Integrations

### 7.1 Payment Integration

* N/A.

### 7.2 Analytics Integration

* Optional: Prometheus exporter mode (future) or stats via log scraping.

---

## 8. Environment Configuration & Deployment

* **Local Setup**

  * Build: `gcc -std=c11 -Wall -Wextra -O2 -D_GNU_SOURCE ...` (+ `-lsystemd` if using socket activation).
  * Hardening (recommended): `-fno-common -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -Wl,-z,relro,-z,now`. (Industry best practice; defer to distro toolchain defaults.)

* **Staging / Production**

  * Run under systemd. Logs reachable via `journalctl -u epoll-echo`.
  * Socket activation (optional): Provide `.socket` units for TCP & UDP and a `.service` that adopts FDs via `sd_listen_fds()`. Test with `systemd-socket-activate`, including `--datagram` for UDP.  ([man7.org][5])

* **CI/CD**

  * Lint & build matrix, run unit tests, produce `.deb` artifact.

* **Monitoring & Logging**

  * Journald captures stdout/stderr by default; operators may also configure `StandardOutput=journal+console` if desired. ([Server Fault][11])

* **Debian/Ubuntu Packaging**

  * Minimal `.deb` via debhelper with `Build-Depends: debhelper-compat (= 13)` (no `debian/compat`). Provide `debian/{control,rules,install,changelog}`. 

---

## 9. Testing & Quality Assurance

* **Unit Testing**

  * Line parser (CRLF/LF normalization, overflow/resync).
  * Token verification logic (loopback checks, credential loading).
  * UDP peer window aging.

* **Integration Testing**

  * **Dual-stack**: `nc -4 127.0.0.1 12345` and `nc -6 ::1 12345`. Ensure `IPV6_V6ONLY=0` on v6 socket or provide separate v4 socket.  ([man7.org][2])
  * **Epoll drains**: Burst writes from client; verify no CPU spin and `EPOLLOUT` toggling. 
  * **TCP framing**: `printf 'a\r\nb\n' | nc ::1 12345` echoes `a` then `b` (LF tolerant per RFC 9112).  ([RFC Editor][1])
  * **Overflow policy**: Send >4096 bytes w/o LF → receive `ERR too-long-line`, resync at next LF; second consecutive overflow closes. 
  * **SIGPIPE safety**: Close client mid-write; server must not crash. Use `MSG_NOSIGNAL`.  ([man7.org][9])
  * **UDP truncation**: Oversized datagram → server responds `ERR datagram-truncated`.  ([man7.org][6])
  * **/stats window**: UDP peer appears in `udp_active_60s`, ages out after ~60s tick. 
  * **/shutdown hardening**: Works only via TCP loopback with correct token; UDP attempts rejected. 
  * **Socket activation**: `systemd-socket-activate --listen=[::]:12345` (TCP) and `--datagram` (UDP); daemon adopts FDs 3+.  ([man7.org][13])
  * **Packaging**: Build with debhelper-compat 13 workflow. 

* **Performance & Security Testing**

  * Simple `wrk`/`ab`-style loops for TCP; `pktgen`/`nping` for UDP.
  * Negative tests: invalid commands; malformed tokens; non-loopback attempts.

* **Accessibility Tests**

  * N/A.

---

## 10. Edge Cases, Implementation Considerations & Reflection

* **Potential Obstacles**

  * Distro variations for dual-stack: some environments may default to `bindv6only=1`, requiring a separate IPv4 socket. ([man7.org][2])
  * Kernel backlog capping (`net.core.somaxconn`) may reduce effective listen backlog. Document this. 
  * MSG_TRUNC usage nuances: Linux reports real datagram size with flags; ensure correct behavior and testing across kernels. ([man7.org][6])

* **Edge-Case Handling**

  * Handle `EPOLLERR`/`EPOLLHUP` robustly by reading error (via `getsockopt(SO_ERROR)`) then closing.
  * Ensure no starvation: always drain until `EAGAIN` on read/write/accept. 
  * Respect `RLIMIT_NOFILE`: If at capacity, accept+immediately write `server busy\n`, then close.  ([man7.org][12])

* **Technical Constraints**

  * Single-threaded by design (interview-friendly). High-core scalability is out of scope.

* **Scalability Needs**

  * Future: sharded loops or io_uring variant; metrics exporter.

* **Testing Focus**

  * Correct CRLF/LF handling (per RFC 9112). ([RFC Editor][1])
  * UDP truncation and error messaging. ([man7.org][6])

* **Critical Questions (open)**

  * Token file path default name? (Current: provided by CLI; otherwise systemd credentials path.)
  * Whether to support `SO_REUSEPORT` for parallel instances (out of scope initially).

* **Approach Suitability**

  * Epoll LT with nonblocking ops is the canonical, portable approach for multi-FD servers; `accept4` with `SOCK_NONBLOCK|SOCK_CLOEXEC` prevents races. ([man7.org][8])

* **Assumptions to Challenge**

  * UDP peers identified solely by `(ip,port)` tuple (sufficient for window count).
  * Journal-only logging meets operator needs (file logging can be added via systemd settings).

* **Exceptional Solution Definition**

  * No busy loops under stress, minimal CPU under idle, deterministic shutdown, perfect observability via journal.

---

## 11. Summary & Next Steps

* **Recap**

  * This spec implements *epoll-echo (v3)* exactly as requested: dual‑stack sockets, level‑triggered epoll with nonblocking I/O and drains, safe TCP framing (CRLF/LF), explicit overflow rules, UDP truncation detection via `recvmsg` flags, secure `/shutdown` using loopback+token from systemd credentials, and strong systemd ergonomics (logging, socket activation).  
  * Key Linux references underpinning choices: epoll API, `accept4` flags, `IPV6_V6ONLY` behavior, `MSG_NOSIGNAL`, `MSG_TRUNC`, signalfd, timerfd, systemd socket activation & credentials, RLIMIT_NOFILE semantics. ([man7.org][4])

* **Open Questions**

  1. Credential filename under `$CREDENTIALS_DIRECTORY`: use a default like `shutdown.token` or make it required via unit? (Currently unspecified in request.)
  2. Should we emit JSON logs optionally for structured ingestion?
  3. Do we want a hard connection limit lower than `RLIMIT_NOFILE` by default (e.g., `--max-tcp=1024`)—request says yes; confirm interaction with `LimitNOFILE=` in unit docs.

* **Future Enhancements**

  * Prometheus metrics endpoint or text file collector.
  * `SO_REUSEPORT` multi-process scale-out.
  * Optional TLS termination (via stunnel or reverse proxy).

---

### Appendix A — Key Standards & Man Pages (select)

* `epoll(7)` overview and events (level vs edge). ([man7.org][4])
* `accept(2)`/`accept4(2)` for atomic `NONBLOCK`/`CLOEXEC`. ([man7.org][8])
* `ipv6(7)` `IPV6_V6ONLY` and `bindv6only` default. ([man7.org][2])
* `listen(2)` backlog semantics and `somaxconn` cap.
* `send(2)` `MSG_NOSIGNAL`; SIGPIPE behavior. ([man7.org][9])
* `recvmsg(2)` `MSG_TRUNC` / `MSG_PEEK`. ([man7.org][6])
* `signalfd(2)` and `timerfd_create(2)` for in-loop signals/timers. ([man7.org][3])
* RFC 9112 (HTTP/1.1) tolerance for bare LF line terminators (recipient MAY accept). ([RFC Editor][1])
* `sd_listen_fds(3)` and `systemd-socket-activate(1)` for socket activation. ([man7.org][5])
* `RLIMIT_NOFILE` semantics (process FD ceiling). ([man7.org][12])
