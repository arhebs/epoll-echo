#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd python3
require_cmd nc
require_cmd timeout

main() {
    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/sigpipe-server.log"

    start_server "$port" "$log"

    python3 - <<'PY' "$port"
import socket
import sys
port = int(sys.argv[1])
with socket.create_connection(("::1", port)) as sock:
    sock.sendall(b"/time\n")
    # Close immediately without reading so the server hits EPIPE
PY

    # Give the server a brief moment to process the failed write
    sleep 0.2

    local check
    check=$(printf 'still-here\n' | timeout 5s nc -N ::1 "$port")
    if [[ "$check" != "still-here" ]]; then
        echo "sigpipe test failed: expected echo, got '$check'" >&2
        exit 1
    fi

    echo "sigpipe.sh: server survived client abort during write"
    stop_server
}

main "$@"
