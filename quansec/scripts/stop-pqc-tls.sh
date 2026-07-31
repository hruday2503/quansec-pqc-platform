#!/usr/bin/env bash
# scripts/stop-pqc-tls.sh — stop the PQC TLS data plane.
#
# Graceful `nginx -s quit`, then waits until the listening socket is actually
# released. Returning only once the port is free is what makes restart and
# port-reuse deterministic rather than racy.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pqc-tls-common.sh"

WAIT_SECONDS="${WAIT_SECONDS:-15}"

if ! nginx_running && ! port_listening; then
    ok "Not running"
    exit 0
fi

say "Stopping PQC TLS data plane (pid $(nginx_pid))"
if [[ -x "$NGINX_BIN" && -f "$NGINX_CONF" ]]; then
    "$NGINX_BIN" -s quit -c "$NGINX_CONF" 2>/dev/null || true
fi

deadline=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < deadline )); do
    if ! nginx_running && ! port_listening; then
        rm -f "$PID_FILE"
        ok "Stopped; port $TLS_PORT released"
        exit 0
    fi
    sleep 0.2
done

pid="$(nginx_pid)"
if [[ -n "$pid" ]]; then
    warn "Graceful quit timed out after ${WAIT_SECONDS}s - sending SIGTERM to $pid"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 1
fi

if nginx_running || port_listening; then
    die "NGINX is still holding $TLS_HOST:$TLS_PORT"
fi
rm -f "$PID_FILE"
ok "Stopped; port $TLS_PORT released"
