#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd python3
require_cmd cc

fetch_udp_active() {
    local port="$1"
    python3 - <<'PY' "$port"
import socket
import sys
port = int(sys.argv[1])
with socket.create_connection(("::1", port)) as sock:
    sock.sendall(b"/stats\n")
    sock.shutdown(socket.SHUT_WR)
    data = sock.recv(1024)
line = data.decode().strip()
parts = line.split()
if len(parts) >= 3:
    print(parts[2])
else:
    print(0)
PY
}

send_udp_probe() {
    local port="$1"
    python3 - <<'PY' "$port"
import socket
import sys
port = int(sys.argv[1])
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
    sock.sendto(b'stats-peer', ("::1", port))
PY
}

main() {
    local shim
    shim=$(ensure_test_shim)
    SERVER_ENV=("LD_PRELOAD=$shim" "EPOLL_ECHO_TEST_TIME_SCALE=120")

    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/stats-window-server.log"

    start_server "$port" "$log"

    local before
    before=$(fetch_udp_active "$port")
    before=${before:-0}
    local before_val=$((10#$before))

    send_udp_probe "$port"
    sleep 0.2

    local after
    after=$(fetch_udp_active "$port")
    after=${after:-0}
    local after_val=$((10#$after))

    if (( after_val < before_val + 1 )); then
        echo "stats_window test failed: UDP peer not counted (before=$before_val, after=$after_val)" >&2
        exit 1
    fi

    sleep 1.5

    local final
    final=$(fetch_udp_active "$port")
    final=${final:-0}
    local final_val=$((10#$final))

    if (( final_val > before_val )); then
        echo "stats_window test failed: UDP peer did not age out (final=$final_val, baseline=$before_val)" >&2
        exit 1
    fi

    echo "stats_window.sh: UDP active window increments and ages out via accelerated clock"
    SERVER_ENV=()
    stop_server
}

main "$@"
