#!/usr/bin/env bash
# shellcheck disable=SC1090
# Common helpers for epoll-echo integration tests.

set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "common.sh is a helper meant to be sourced" >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BIN="$ROOT_DIR/epoll-echo"
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/epoll-echo-test.XXXXXX")
SERVER_PID=""
SERVER_LOG="$TEST_TMP/server.log"
SERVER_ENV=()
TEST_SHIM_SO=""

cleanup() {
    set +e
    if [[ -n "${SERVER_PID:-}" ]]; then
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            kill "$SERVER_PID" 2>/dev/null || true
        fi
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    rm -rf "$TEST_TMP"
}

trap cleanup EXIT INT TERM

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing required command: $cmd" >&2
        exit 1
    fi
}

ensure_binary() {
    if [[ ! -x "$BIN" ]]; then
        echo "missing epoll-echo binary at $BIN; run 'make' first" >&2
        exit 1
    fi
}

pick_free_port() {
    require_cmd python3
    python3 - <<'PY'
import socket
import random
for _ in range(32):
    port = random.randint(20000, 60000)
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock6:
        sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        try:
            sock6.bind(('::1', port))
        except OSError:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock4:
            try:
                sock4.bind(('127.0.0.1', port))
            except OSError:
                continue
        print(port)
        break
else:
    raise SystemExit('failed to locate free port')
PY
}

wait_for_server() {
    local log="$1"
    local attempts=0
    while (( attempts < 100 )); do
        if [[ -n "${SERVER_PID:-}" ]] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "server exited prematurely" >&2
            cat "$log" >&2 || true
            exit 1
        fi
        if grep -q 'listening (TCP port=' "$log" 2>/dev/null; then
            return
        fi
        sleep 0.1
        attempts=$((attempts + 1))
    done
    echo "server did not report ready" >&2
    cat "$log" >&2 || true
    exit 1
}

start_server() {
    local port="$1"
    shift || true
    local log
    if [[ "$#" -gt 0 ]]; then
        log="$1"
        shift || true
    else
        log="$SERVER_LOG"
    fi
    if [[ "$log" == -- ]]; then
        log="$SERVER_LOG"
    fi
    if [[ "${1:-}" == "--" ]]; then
        shift || true
    fi
    ensure_binary
    require_cmd stdbuf
    local cmd=("$BIN" --port "$port")
    if [[ "$#" -gt 0 ]]; then
        cmd+=("$@")
    fi
    local run_cmd=(stdbuf -o0 -e0 "${cmd[@]}")
    local env_cmd=()
    if [[ "${#SERVER_ENV[@]}" -gt 0 ]]; then
        env_cmd=(env "${SERVER_ENV[@]}" "${run_cmd[@]}")
    else
        env_cmd=("${run_cmd[@]}")
    fi
    "${env_cmd[@]}" >"$log" 2>&1 &
    SERVER_PID=$!
    SERVER_LOG="$log"
    wait_for_server "$log"
}

stop_server() {
    if [[ -z "${SERVER_PID:-}" ]]; then
        return
    fi
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

ensure_test_shim() {
    if [[ -n "$TEST_SHIM_SO" && -f "$TEST_SHIM_SO" ]]; then
        printf '%s\n' "$TEST_SHIM_SO"
        return
    fi
    local out="$TEST_TMP/test_shim.so"
    cc -shared -fPIC -O2 -Wall -Wextra -o "$out" "$SCRIPT_DIR/test_shim.c" -ldl
    TEST_SHIM_SO="$out"
    printf '%s\n' "$TEST_SHIM_SO"
}
