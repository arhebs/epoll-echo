#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd nc
require_cmd timeout

main() {
    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/dualstack-server.log"

    start_server "$port" "$log"

    local v4_payload="dualstack-v4"
    local v4_out
    v4_out=$(printf '%s\n' "$v4_payload" | timeout 5s nc -N -4 127.0.0.1 "$port")
    if [[ "$v4_out" != "$v4_payload" ]]; then
        echo "TCP IPv4 echo mismatch (expected '$v4_payload', got '$v4_out')" >&2
        exit 1
    fi

    local v6_payload="dualstack-v6"
    local v6_out
    v6_out=$(printf '%s\n' "$v6_payload" | timeout 5s nc -N -6 ::1 "$port")
    if [[ "$v6_out" != "$v6_payload" ]]; then
        echo "TCP IPv6 echo mismatch (expected '$v6_payload', got '$v6_out')" >&2
        exit 1
    fi

    echo "dualstack.sh: IPv4 and IPv6 echo succeeded on port $port"
    stop_server
}

main "$@"
