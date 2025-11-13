#!/usr/bin/env python3
"""
socket_activation_helper.py
Purpose: Pre-bind UDP sockets for epoll-echo's socket activation test so
systemd-socket-activate can supply TCP listeners while both descriptor sets
are delivered to the daemon. This script opens IPv6 (dual-stack when
possible) and IPv4 UDP sockets on the requested port, exposes them via
LISTEN_FDS/LISTEN_PID, and then execs systemd-socket-activate with the
original arguments.
"""

import os
import socket
import sys
from typing import List


def open_udp_sockets(port: int) -> List[socket.socket]:
    """
    Creates UDP sockets bound to the requested port.

    Inputs:
        port: Numeric UDP port to bind.
    Returns:
        List of socket objects (at least one IPv6 or IPv4).
    Raises:
        SystemExit when neither IPv6 nor IPv4 sockets can be created/bound.
    Notes:
        Attempts to disable IPV6_V6ONLY so a single IPv6 socket can handle
        IPv4-mapped traffic. Falls back to a dedicated IPv4 socket when the
        kernel refuses to clear the flag.
    """
    sockets: List[socket.socket] = []
    ipv6_sock = None
    dual_stack = False

    try:
        ipv6_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        ipv6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ipv6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            dual_stack = True
        except OSError:
            dual_stack = False
        ipv6_sock.bind(("::", port))
        sockets.append(ipv6_sock)
    except OSError as exc:
        if ipv6_sock is not None:
            ipv6_sock.close()
        ipv6_sock = None
        dual_stack = False
        sys.stderr.write(
            f"socket_activation_helper: IPv6 UDP bind failed on port {port}: {exc}\n"
        )

    if not dual_stack:
        try:
            ipv4_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ipv4_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ipv4_sock.bind(("0.0.0.0", port))
            sockets.append(ipv4_sock)
        except OSError as exc:
            if ipv6_sock is None:
                raise SystemExit(
                    f"socket_activation_helper: IPv4 UDP bind failed on port {port}: {exc}"
                ) from exc

    if not sockets:
        raise SystemExit(
            f"socket_activation_helper: unable to bind any UDP sockets on port {port}"
        )

    return sockets


def duplicate_into_listen_range(sock: socket.socket, target_fd: int) -> None:
    """
    Moves the provided socket to a deterministic descriptor number so the
    sd_listen_fds contract (FDs start at 3) is satisfied.

    Inputs:
        sock: Socket instance to duplicate.
        target_fd: Desired descriptor number.
    Raises:
        SystemExit if dup2 fails.
    Side effects:
        Marks the duplicated fd inheritable and closes the original socket.
    """
    fd = sock.fileno()
    try:
        if fd != target_fd:
            os.dup2(fd, target_fd, inheritable=True)
            sock.close()
        else:
            os.set_inheritable(target_fd, True)
            sock.detach()
    except OSError as exc:
        raise SystemExit(
            f"socket_activation_helper: failed to duplicate socket fd to {target_fd}: {exc}"
        ) from exc


def main() -> None:
    """
    Entry point. Validates arguments, prepares UDP sockets, exports the
    sd_listen_fds environment variables, and execs systemd-socket-activate.
    """
    if len(sys.argv) < 3:
        sys.stderr.write(
            "usage: socket_activation_helper.py <port> <systemd-socket-activate args...>\n"
        )
        raise SystemExit(2)

    try:
        port = int(sys.argv[1])
    except ValueError as exc:
        raise SystemExit(f"invalid port '{sys.argv[1]}': {exc}") from exc

    sockets = open_udp_sockets(port)
    for idx, sock in enumerate(sockets):
        duplicate_into_listen_range(sock, 3 + idx)

    os.environ["LISTEN_PID"] = str(os.getpid())
    os.environ["LISTEN_FDS"] = str(len(sockets))
    os.environ.pop("LISTEN_FDNAMES", None)

    cmd = ["systemd-socket-activate"] + sys.argv[2:]
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
