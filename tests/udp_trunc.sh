#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd python3
require_cmd cc

main() {
    local shim
    shim=$(ensure_test_shim)
    SERVER_ENV=("LD_PRELOAD=$shim" "EPOLL_ECHO_TEST_FORCE_TRUNC=1")

    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/udp-trunc-server.log"

    start_server "$port" "$log"

    python3 - <<'PY' "$port"
import socket
import sys

port = int(sys.argv[1])
payload = b'U' * 8192
expected = b'ERR datagram-truncated\n'

with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(payload, ("::1", port))
    data, _ = sock.recvfrom(4096)

if data != expected:
    print(f"udp_trunc test failed: expected {expected!r}, got {data!r}", file=sys.stderr)
    raise SystemExit(1)
PY

    SERVER_ENV=()

    echo "udp_trunc.sh: server detected truncated datagram via MSG_TRUNC"
    stop_server
}

main "$@"
