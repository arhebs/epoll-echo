#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd python3

wait_for_clean_exit() {
    local attempts=0
    while (( attempts < 50 )); do
        if [[ -z "${SERVER_PID:-}" ]] || ! kill -0 "$SERVER_PID" 2>/dev/null; then
            wait "$SERVER_PID" 2>/dev/null || true
            SERVER_PID=""
            return
        fi
        sleep 0.1
        attempts=$((attempts + 1))
    done
    echo "shutdown test: server failed to exit after /shutdown" >&2
    exit 1
}

main() {
    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/shutdown-server.log"
    local token_file="$TEST_TMP/shutdown.token"
    local token="letmein-secret"
    printf '%s\n' "$token" > "$token_file"
    chmod 600 "$token_file"

    start_server "$port" "$log" -- --shutdown-token-file "$token_file"

    python3 - <<'PY' "$port" "$token"
import socket
import sys

port = int(sys.argv[1])
token = sys.argv[2]
expected = b'ERR shutdown-not-allowed\n'

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(f"/shutdown {token}".encode(), ("::1", port))
    data, _ = sock.recvfrom(512)

if data != expected:
    print(f"shutdown test failed: UDP attempt mismatch (expected {expected!r}, got {data!r})",
          file=sys.stderr)
    raise SystemExit(1)
PY

    python3 - <<'PY' "$port" "$token"
import socket
import sys

port = int(sys.argv[1])
token = sys.argv[2]
expected = b'OK, shutting down\n'

with socket.create_connection(("127.0.0.1", port)) as sock:
    sock.sendall(f"/shutdown {token}\n".encode())
    sock.shutdown(socket.SHUT_WR)
    data = sock.recv(512)

if data != expected:
    print(f"shutdown test failed: TCP attempt mismatch (expected {expected!r}, got {data!r})",
          file=sys.stderr)
    raise SystemExit(1)
PY

    wait_for_clean_exit
    echo "shutdown.sh: UDP blocked, TCP loopback with token shut server down"
}

main "$@"
