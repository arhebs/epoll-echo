#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd systemd-socket-activate
require_cmd nc
require_cmd timeout
require_cmd python3
require_cmd stdbuf

ensure_systemd_support() {
    if ! ldd "$BIN" 2>/dev/null | grep -q 'libsystemd'; then
        echo "socket_activation test requires epoll-echo built with ENABLE_SYSTEMD=1" >&2
        exit 1
    fi
}

wait_for_socket_activation() {
    local log="$1"
    local port="$2"
    local attempts=0

    while (( attempts < 100 )); do
        if [[ -n "${SERVER_PID:-}" ]] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "socket activation helper: systemd-socket-activate exited early" >&2
            cat "$log" >&2 || true
            exit 1
        fi

        if grep -q 'listening (TCP port=' "$log" 2>/dev/null; then
            return
        fi

        printf 'prime\n' | timeout 1s nc -N -6 ::1 "$port" >/dev/null 2>&1 || true
        sleep 0.1
        attempts=$((attempts + 1))
    done

    echo "socket activation: server did not report ready" >&2
    cat "$log" >&2 || true
    exit 1
}

main() {
    ensure_systemd_support

    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/socket-activation.log"

    local token="socket-activation-token"
    local token_file="$TEST_TMP/socket-activation.token"
    printf '%s\n' "$token" >"$token_file"
    chmod 600 "$token_file"

    local helper="$SCRIPT_DIR/socket_activation_helper.py"
    local cmd=(
        python3
        "$helper"
        "$port"
        "--listen=[::1]:$port"
        "--"
        stdbuf
        -o0
        -e0
        "$BIN"
        --shutdown-token-file
        "$token_file"
    )

    "${cmd[@]}" >"$log" 2>&1 &
    SERVER_PID=$!
    SERVER_LOG="$log"

    wait_for_socket_activation "$log" "$port"

    local tcp_resp
    tcp_resp=$(printf 'sa-tcp\n' | timeout 5s nc -N -6 ::1 "$port")
    if [[ "$tcp_resp" != "sa-tcp" ]]; then
        echo "socket activation TCP echo mismatch (got '$tcp_resp')" >&2
        stop_server
        exit 1
    fi

    python3 - <<'PY' "$port"
import socket
import sys

port = int(sys.argv[1])
expected = b'sa-udp'

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(expected, ("::1", port))
    data, _ = sock.recvfrom(1024)

if data != expected:
    print(f"socket activation UDP echo mismatch (expected {expected!r}, got {data!r})",
          file=sys.stderr)
    raise SystemExit(1)
PY

    python3 - <<'PY' "$port" "$token"
import socket
import sys

port = int(sys.argv[1])
token = sys.argv[2]
expected = b'OK, shutting down\n'

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
    sock.settimeout(5)
    sock.connect(("::1", port))
    sock.sendall(f"/shutdown {token}\n".encode())
    sock.shutdown(socket.SHUT_WR)
    data = sock.recv(512)

if data != expected:
    print(f"socket activation shutdown mismatch (expected {expected!r}, got {data!r})",
          file=sys.stderr)
    raise SystemExit(1)
PY

    echo "socket_activation.sh: systemd-socket-activate handed TCP/UDP sockets and shutdown succeeded"
    sleep 0.2
    stop_server
}

main "$@"
