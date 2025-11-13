#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=tests/common.sh
. "$SCRIPT_DIR/common.sh"

require_cmd nc
require_cmd hexdump
require_cmd timeout

main() {
    local port
    port=$(pick_free_port)
    local log="$TEST_TMP/framing-server.log"

    start_server "$port" "$log"

    local payload=$'a\r\nb\n'
    local expected_hex="610d0a620a"
    local output_hex
    output_hex=$(printf '%s' "$payload" | timeout 5s nc -N ::1 "$port" | hexdump -v -e '/1 "%02x"')
    output_hex=${output_hex//$'\n'/}
    if [[ "$output_hex" != "$expected_hex" ]]; then
        echo "framing mismatch: expected hex $expected_hex, got $output_hex" >&2
        exit 1
    fi

    echo "framing.sh: CRLF and LF inputs echoed with correct framing"
    stop_server
}

main "$@"
