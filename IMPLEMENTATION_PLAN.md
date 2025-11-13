# Implementation Plan

> **Legend**: Each step lists tasks, files (≤ ~20), dependencies, and any manual instructions. Follow steps sequentially.

## 0) Validate Scope & Inputs

* [x] Step 0.1: Confirm baseline requirements & acceptance tests

  * **Task**: Treat **PROJECT_REQUEST.md** and **TECHNICAL_SPECIFICATION.md** as the source of truth; pin CLI, features, and tests.

    * Note epoll masks (`EPOLLIN|EPOLLRDHUP|EPOLLERR|EPOLLHUP`), level‑triggered behavior, drain‑until‑EAGAIN, and EPOLLOUT toggling.
    * Confirm UDP truncation policy and `/shutdown` guard.
    * Record Debian packaging and systemd requirements.
  * **Files**: none (planning only)
  * **Step Dependencies**: None
  * **User Instructions**: N/A
  * *Refs*: ; epoll semantics ([Man7][1])

---

## 1) Repository & Toolchain Scaffolding

* [x] Step 1.1: Create repository structure & base build

  * **Task**: Create directories and a conservative `Makefile` with debug‑friendly defaults.
  * **Files**:

    * `Makefile`: targets `all`, `clean`, `test`, optional `ENABLE_SYSTEMD=1` to link `-lsystemd`; `CFLAGS=-std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2` (PIE/RELRO in LDFLAGS).
    * `src/` (empty placeholders): `main.c`, `loop.c`, `tcp.c`, `udp.c`, `cmd.c`, `stats.c`, `timeutil.c`, `log.c`, `net.c`
    * `include/`: `platform.h`, `log.h`, `net.h`, `loop.h`, `tcp.h`, `udp.h`, `cmd.h`, `stats.h`, `timeutil.h`, `common.h`
    * `tests/` (dir), `systemd/` (dir), `debian/` (dir)
    * `LICENSE`, `README.md`
  * **Step Dependencies**: Step 0
  * **User Instructions**: Install toolchain (Ubuntu/Debian): `sudo apt-get install -y build-essential pkg-config` (and later `libsystemd-dev` for socket activation).
  * *Refs*: hardening flags (best practice); systemd linking will be optional. 

---

## 2) Cross‑cutting Headers & Logging

* [x] Step 2.1: Implement platform & common includes

  * **Task**: Centralize POSIX/Linux headers, attributes, and small helpers (e.g., `likely/unlikely`, safe `close_fd`).
  * **Files**:

    * `include/platform.h`: feature macros, `_GNU_SOURCE`, `_POSIX_C_SOURCE`, attributes.
    * `include/common.h`: errno helpers, string utils, constants (defaults).
* [x] Step 2.2: Logging API

  * **Task**: Minimal leveled logger to stdout/stderr with `-v/-vv/-q`. Journald captures stdout/stderr by default.

    * Map levels to simple prefixes `DEBUG/INFO/WARN/ERROR`. Avoid color to keep logs machine‑parseable.
  * **Files**:

    * `include/log.h`: macros `LOG_DEBUG/INFO/WARN/ERROR`.
    * `src/log.c`: `log_set_verbosity(int)`, `log_printf(level, ...)`.
  * **Step Dependencies**: Step 1
  * **User Instructions**: None
  * *Refs*: journald default capture of stdout/stderr. ([GitHub][9])

---

## 3) Stats & Time Utilities

* [x] Step 3.1: UTC time formatter

  * **Task**: `timeutil_format_utc(char out[20])` using `clock_gettime(CLOCK_REALTIME)`, `gmtime_r`, `strftime("%F %T")`.
  * **Files**:

    * `include/timeutil.h`, `src/timeutil.c`
* [x] Step 3.2: Stats structure

  * **Task**: `struct EpStats { uint64_t total_clients; uint32_t tcp_connected_now; uint32_t udp_active_60s; }` with getters/incrementers; stub UDP peer window interface.
  * **Files**:

    * `include/stats.h`, `src/stats.c`
  * **Step Dependencies**: Step 2
  * **User Instructions**: None
  * *Refs*: `/stats` format per spec. 

---

## 4) Networking Helpers

* [x] Step 4.1: Socket helpers & dual‑stack

  * **Task**:

    * Create listening TCP socket(s): prefer IPv6 with `IPV6_V6ONLY=0`; fall back to separate IPv4 if needed.
    * Always use `SOCK_NONBLOCK | SOCK_CLOEXEC` at creation; set `SO_REUSEADDR`; configurable backlog.
    * Open UDP socket(s) similarly.
  * **Files**:

    * `include/net.h`, `src/net.c`
  * **Step Dependencies**: Step 2
  * **User Instructions**: On distros where `/proc/sys/net/ipv6/bindv6only` is `1`, expect an extra IPv4 socket.
  * *Refs*: `IPV6_V6ONLY`/dual‑stack; backlog semantics and somaxconn cap; `accept4` flags rationale applies to accepted FDs too. ([Man7][3])

---

## 5) Event Loop Foundation (epoll)

* [x] Step 5.1: epoll instance & registration API

  * **Task**: Implement `loop_init()`, `loop_add(fd, events)`, `loop_mod(fd, events)`, `loop_del(fd)`, and the `epoll_wait` dispatch skeleton. Default mask: `EPOLLIN|EPOLLRDHUP|EPOLLERR|EPOLLHUP`; defer `EPOLLOUT`.
  * **Files**:

    * `include/loop.h`, `src/loop.c`
  * **Step Dependencies**: Step 4
  * **User Instructions**: None
  * *Refs*: Level‑triggered behavior and event masks. ([Man7][1])

---

## 6) Signals & Timers inside the Loop

* [x] Step 6.1: signalfd for SIGINT/SIGTERM

  * **Task**: Block SIGINT/SIGTERM; create `signalfd`; register with epoll; set a `shutdown_requested` flag when read.
  * **Files**: modify `src/loop.c` and add helpers in `include/loop.h`
* [x] Step 6.2: timerfd for 1s ticks

  * **Task**: Create `timerfd` with 1s interval; on tick, age UDP peers (60s window).
  * **Files**: modify `src/loop.c`; expose `loop_on_tick()` hook
  * **Step Dependencies**: Step 5
  * **User Instructions**: None
  * *Refs*: `signalfd(2)`, `timerfd_create(2)` can be monitored by epoll. ([Man7][6])

---

## 7) TCP Listener & Accept Path

* [x] Step 7.1: Listener registration

  * **Task**: Create TCP listener(s) via `net.c`; register in epoll with `EPOLLIN`.
* [x] Step 7.2: Accept loop

  * **Task**: On events from the listener, loop `accept4(..., SOCK_NONBLOCK|SOCK_CLOEXEC)` until `EAGAIN`. For each accept:

    * If at capacity (`--max-tcp`), send `"server busy\n"` and close.
    * Else, allocate `struct Conn`, register conn fd with epoll default mask.
  * **Files**:

    * `include/tcp.h`, `src/tcp.c` (listener, accept, conn list mgmt)
    * minor change in `src/loop.c` (dispatch to `tcp_on_accept()`)
  * **Step Dependencies**: Steps 4–6
  * **User Instructions**: None
  * *Refs*: `accept4` flags avoid racy `fcntl`. ([Man7][2])

---

## 8) TCP Read Path: Framing & Overflow Policy

* [x] Step 8.1: Per‑connection read buffer & state

  * **Task**: For each `Conn`, maintain `rbuf[4097]`, `rlen`, `overflow_streak`, `resync` flag.
* [x] Step 8.2: Read loop & line extraction

  * **Task**: On `EPOLLIN` for a conn fd, read until `EAGAIN`.

    * If LF found, cut line; trim trailing `\r` if present; hand to command/echo layer.
    * If length exceeds `max_line` before LF: enqueue `ERR too-long-line\n`, set `resync=true`, increment `overflow_streak`; if `overflow_streak==2`, close. While `resync`, discard until LF then clear.
* [x] Step 8.3: EPOLLRDHUP/HUP/ERR handling

  * **Task**: Drain readable bytes; then close connection cleanly and update stats.
  * **Files**:

    * `src/tcp.c` (read handler, line splitter, overflow state)
    * `include/tcp.h` (struct Conn)
  * **Step Dependencies**: Step 7
  * **User Instructions**: None
  * *Refs*: Line tolerance rationale from RFC 9112 (recipient may accept bare LF). ([RFC Editor][11]); behavior per project spec. 

---

## 9) TCP Write Path: Backpressure & EPOLLOUT Toggling

* [x] Step 9.1: Write queue

  * **Task**: Implement a small intrusive queue of `WQItem` buffers per `Conn`.
* [x] Step 9.2: send loop with MSG_NOSIGNAL

  * **Task**: On `EPOLLOUT` (or after enqueue), loop `send(fd, buf, len, MSG_NOSIGNAL)` until `EAGAIN` or empty, then drop `EPOLLOUT` if queue drained.
  * **Files**:

    * `src/tcp.c` (enqueue, write handler)
  * **Step Dependencies**: Step 8
  * **User Instructions**: None
  * *Refs*: `MSG_NOSIGNAL` prevents SIGPIPE on closed peers. ([Man7][5])

---

## 10) UDP Socket Handling

* [x] Step 10.1: UDP registration

  * **Task**: Create UDP socket(s) via `net.c`; register with epoll for `EPOLLIN`.
* [x] Step 10.2: Datagram I/O & truncation detection

  * **Task**: Use `recvmsg()` into a large buffer; check `msg_flags & MSG_TRUNC`.

    * If truncated → send `ERR datagram-truncated\n` to sender.
    * Else handle command or echo. Update UDP peer activity window.
  * **Files**:

    * `include/udp.h`, `src/udp.c`
  * **Step Dependencies**: Steps 4–6
  * **User Instructions**: None
  * *Refs*: `recvmsg()` + `MSG_TRUNC` to detect truncation. ([Man7][4])

---

## 11) Command Parsing & Dispatch

* [x] Step 11.1: Command module

  * **Task**: Implement `cmd_handle_tcp(conn, line)` and `cmd_handle_udp(addr,buf,len)` with:

    * `/time` → UTC timestamp from `timeutil`.
    * `/stats` → `total_clients tcp_connected_now udp_active_60s`.
    * `/shutdown <token>`:

      * **TCP only**: verify peer is loopback (`127.0.0.0/8` or `::1`), token matches; enqueue `OK, shutting down\n` and signal main loop to exit gracefully.
      * **UDP**: always reply `ERR shutdown-not-allowed\n`.
  * **Files**:

    * `include/cmd.h`, `src/cmd.c`
    * small hooks in `src/tcp.c` and `src/udp.c`
  * **Step Dependencies**: Steps 3, 8–10
  * **User Instructions**: None
  * *Refs*: Command semantics per request. 

---

## 12) UDP Peer Activity Window (60s)

* [x] Step 12.1: Data structures

  * **Task**: Maintain hash table/set keyed by `(ip,port)` with last-seen tick. Increment `total_clients` on first-time sighting per process lifetime; compute `udp_active_60s` from entries with `now - seen <= 60`.
* [x] Step 12.2: Aging on timerfd tick

  * **Task**: On each `loop_on_tick()`, drop entries older than 60s; expose a `stats_get_udp_active_60s()`.
  * **Files**:

    * `src/stats.c` (peer table + aging), `include/stats.h`
  * **Step Dependencies**: Step 6, Step 10
  * **User Instructions**: None
  * *Refs*: Specified window semantics. 

---

## 13) CLI & Configuration

* [x] Step 13.1: Parse arguments & defaults

  * **Task**: Implement CLI flags:
    `--port`, `--tcp-port`, `--udp-port`, `--max-tcp`, `--backlog`, `--max-line`, `-v/-vv/-q`, `--shutdown-token-file`.

    * Default: dual‑stack bind to same port for TCP & UDP.
    * Validate ranges; store in a `struct Config`.
  * **Files**:

    * `src/main.c`, `include/common.h` (Config)
  * **Step Dependencies**: Steps 2–12
  * **User Instructions**: None
  * *Refs*: CLI as requested. 

---

## 14) Main Bootstrap & Graceful Shutdown

* [x] Step 14.1: Wire up everything

  * **Task**: In `main.c`: parse CLI → open sockets via `net` → create epoll → register TCP/UDP/signalfd/timerfd → run loop → on shutdown signal, drain and exit with `0`.
  * **Files**:

    * `src/main.c` (full program entry), minor updates in `src/loop.c`
  * **Step Dependencies**: Steps 3–13
  * **User Instructions**: None

---

## 15) Security: Shutdown Token from systemd Credentials or File

* [x] Step 15.1: Token loading

  * **Task**: Implement `load_shutdown_token()`:

    * Preferred: read from `$CREDENTIALS_DIRECTORY/<name>` if set (provided by systemd `LoadCredential=`).
    * Fallback: `--shutdown-token-file` path; enforce mode `0600`.
    * Fail **closed** if a token is required but not found when `/shutdown` is attempted.
  * **Files**:

    * `src/main.c` (token load), `include/common.h`
  * **Step Dependencies**: Step 14
  * **User Instructions**: To provision via systemd, add `LoadCredential=shutdown.token:/secure/path` in the unit and ensure the service has the credential; `$CREDENTIALS_DIRECTORY` is exported to the process. ([GitHub][8])

---

## 16) Resource Limits & Capacity Handling

* [x] Step 16.1: Max TCP clients & RLIMIT docs

  * **Task**: Enforce `--max-tcp` (default 1024). If full: accept then immediately write `"server busy\n"` and close.

    * Document `RLIMIT_NOFILE` interaction (raise via shell or unit `LimitNOFILE=`).
  * **Files**:

    * `README.md` (operations notes), `src/tcp.c` (capacity branch)
  * **Step Dependencies**: Step 7
  * **User Instructions**: To raise limits under systemd, set `LimitNOFILE=` in the service file. *Reference RLIMIT docs.* ([Man7][12])

---

## 17) Systemd Units (simple service)

* [x] Step 17.1: Basic unit files

  * **Task**: Provide `epoll-echo.service` (simple service) that runs the binary and logs to journal (default). Provide examples of `LoadCredential=` usage and `LimitNOFILE=`.
  * **Files**:

    * `systemd/epoll-echo.service`
  * **Step Dependencies**: Steps 13–15
  * **User Instructions**: `sudo cp systemd/epoll-echo.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now epoll-echo`
  * *Refs*: journald default; credentials directive usage. ([GitHub][9])

---

## 18) Systemd Socket Activation (bonus, but in spec)

* [x] Step 18.1: Service + sockets

  * **Task**: Add `.socket` units for TCP (Stream) and UDP (Datagram); `.service` adopts passed FDs via `sd_listen_fds()`; use `sd_is_socket_inet()` to validate types when linked.
  * **Files**:

    * `systemd/epoll-echo.socket` (TCP Stream)
    * `systemd/epoll-echo-udp.socket` (UDP Datagram)
    * `systemd/epoll-echo@.service` or `epoll-echo-activated.service` (adopt FDs)
    * `src/main.c` (adoption path guarded by `#ifdef ENABLE_SYSTEMD`)
  * **Step Dependencies**: Step 14
  * **User Instructions**:

    * Install `libsystemd-dev` and build with `make ENABLE_SYSTEMD=1`.
    * Local test:
      `systemd-socket-activate --listen=[::]:12345 ./epoll-echo` (TCP) and `systemd-socket-activate --datagram --listen=[::]:12345 ./epoll-echo` (UDP). ([Freedesktop][7])

---

## 19) Tests: Acceptance & Integration

* [x] Step 19.1: Add test scripts

  * **Task**: Provide `tests/*.sh` to cover:

    * **Dual‑stack** nc tests: `nc -4 127.0.0.1 $PORT` and `nc -6 ::1 $PORT`.
    * **CRLF/LF framing**: `printf 'a\r\nb\n' | nc ::1 $PORT`.
    * **Overflow policy**: send >4KiB w/o LF → expect `ERR too-long-line`.
    * **SIGPIPE safety**: close client mid‑write; server continues.
    * **UDP truncation**: send oversize datagram → `ERR datagram-truncated`.
    * **/stats window**: UDP peer appears, then ages after ~60s.
    * **/shutdown**: works only via TCP loopback with valid token; UDP attempt rejected.
    * **Socket activation**: using `systemd-socket-activate` for TCP and UDP.
  * **Files**:

    * `tests/dualstack.sh`, `tests/framing.sh`, `tests/overflow.sh`, `tests/sigpipe.sh`, `tests/udp_trunc.sh`, `tests/stats_window.sh`, `tests/shutdown.sh`, `tests/socket_activation.sh`
  * **Step Dependencies**: Steps 7–18
  * **User Instructions**: Ensure `nc`, `socat`, and `systemd-socket-activate` are installed.
  * *Refs*: Acceptance tests in request. ; RFC 9112 LF tolerance reference. ([RFC Editor][11])

---

## 20) Debian Packaging (debhelper‑compat = 13)

* [x] Step 20.1: Minimal package files

  * **Task**: Create a **minimal** Debian package using **debhelper‑compat (= 13)** (no `debian/compat` file).
  * **Files**:

    * `debian/control` — `Source: epoll-echo`, `Build-Depends: debhelper-compat (= 13), pkg-config, libsystemd-dev (optional)`; `Package: epoll-echo` with `Architecture: any`.
    * `debian/rules` — tiny dh‑based rules invoking `make`.
    * `debian/install` — install `epoll-echo` into `/usr/bin/`.
    * `debian/changelog` — initial entry.
    * `debian/copyright`
  * **Step Dependencies**: Steps 1–18
  * **User Instructions**: Build with `dpkg-buildpackage -us -uc` (or `debuild -us -uc`).
  * *Refs*: Use `debhelper-compat (= 13)` in `debian/control`; remove `debian/compat`. ([Debian][13])

---

## 21) Documentation & Ops Notes

* [x] Step 21.1: README & manpage stub

  * **Task**: Document CLI, epoll design (level‑triggered, drains), dual‑stack caveats (`bindv6only`), somaxconn cap, RLIMIT guidance, journald usage (`journalctl -u epoll-echo`), systemd credentials & socket activation examples.
  * **Files**:

    * `README.md`, optional `docs/epoll-echo.7.md`
  * **Step Dependencies**: Steps 4–20
  * **User Instructions**: Provide sysctl examples to raise `net.core.somaxconn` if needed; explain that kernel caps backlog. ([Man7][10])

---

## 22) Final Polish & Lint

* [x] Step 22.1: Static checks & warnings‑as‑errors

  * **Task**: Add `-Werror=implicit-function-declaration -Wpointer-arith -Wformat -Wshadow`; ensure clean build with and without `ENABLE_SYSTEMD`.
  * **Files**:

    * `Makefile` (flags), minor code tweaks
  * **Step Dependencies**: All previous
  * **User Instructions**: None

---

## 23) (Optional) CI Skeleton

* [ ] Step 23.1: GitHub Actions

  * **Task**: Add workflow to build, run tests (where feasible), and create `.deb` artifact.
  * **Files**:

    * `.github/workflows/build.yml`
  * **Step Dependencies**: Steps 1–21
  * **User Instructions**: Add repo secrets only if needed.

---

# File‑by‑File Responsibilities (overview)

* `src/main.c`: CLI, config, token loading, systemd FD adoption (optional), bootstrap & shutdown. 
* `src/loop.c` / `include/loop.h`: epoll init, registration helpers, dispatch, signalfd, timerfd. ([Man7][1])
* `src/net.c` / `include/net.h`: dual‑stack listeners, `SO_REUSEADDR`, backlog, non‑blocking creation. ([Man7][3])
* `src/tcp.c` / `include/tcp.h`: accept loop (accept4), per‑conn state, read framing & overflow, write queue (MSG_NOSIGNAL). ([Man7][2])
* `src/udp.c` / `include/udp.h`: `recvmsg`, MSG_TRUNC, replies; update UDP peer window. ([Man7][4])
* `src/cmd.c` / `include/cmd.h`: command parsing & dispatch; loopback check; token verify. 
* `src/stats.c` / `include/stats.h`: counters; UDP 60s window & aging. 
* `src/timeutil.c` / `include/timeutil.h`: UTC timestamp `YYYY‑MM‑DD HH:MM:SS`. 
* `src/log.c` / `include/log.h`: leveled logging to stdout/stderr (journald picks it up). ([GitHub][9])
