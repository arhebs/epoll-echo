#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd python3

main() {
    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/overflow-server.log"

    start_server "$port" "$log" -- --max-line 4096

    python3 - <<'PY' "$port"
import socket
import sys

port = int(sys.argv[1])
payload = b'x' * 5000
expected = b'ERR too-long-line\n'

with socket.create_connection(("::1", port)) as sock:
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    data = sock.recv(1024)

if data != expected:
    print(f"overflow test failed: expected {expected!r}, got {data!r}", file=sys.stderr)
    raise SystemExit(1)
PY

    echo "overflow.sh: server rejected >4KiB line with ERR too-long-line"
    stop_server
}

main "$@"
