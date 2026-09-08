#!/usr/bin/env bash
# scripts/_pqc-tls-common.sh — shared paths for the PQC TLS lifecycle scripts.
#
# Sourced by start/stop/status/test. Resolves the runtime through the same
# environment variables the backend uses, so the scripts and the API can never
# disagree about which NGINX or which OpenSSL is in play.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"

RUNTIME="${QUANSEQ_TLS_RUNTIME_DIR:-$HOME/.quanseq/pqc-tls}"
NGINX_BIN="${QUANSEQ_TLS_NGINX_BIN:-$RUNTIME/nginx/sbin/nginx}"
OPENSSL_BIN="${QUANSEQ_TLS_OPENSSL_BIN:-$RUNTIME/openssl/bin/openssl}"
NGINX_CONF="${QUANSEQ_TLS_NGINX_CONF:-$RUNTIME/conf/nginx.conf}"
ACCESS_LOG="${QUANSEQ_TLS_ACCESS_LOG:-$RUNTIME/logs/access.json.log}"
ERROR_LOG="${QUANSEQ_TLS_ERROR_LOG:-$RUNTIME/logs/error.log}"
PID_FILE="${QUANSEQ_TLS_PID_FILE:-$RUNTIME/run/nginx.pid}"
EVIDENCE_DIR="${QUANSEQ_TLS_EVIDENCE_DIR:-$RUNTIME/evidence}"

TLS_HOST="${QUANSEQ_TLS_HOST:-127.0.0.1}"
TLS_PORT="${QUANSEQ_TLS_PORT:-8443}"
CERT_DIR="${QUANSEQ_TLS_CERT_DIR:-$HOME/quanseq-certs}"
CA_CERT="${QUANSEQ_TLS_CA_CERT:-$CERT_DIR/ca.crt}"
CLIENT_CERT="${QUANSEQ_TLS_CLIENT_CERT:-$CERT_DIR/client.crt}"
CLIENT_KEY="${QUANSEQ_TLS_CLIENT_KEY:-$CERT_DIR/client.key}"
SERVER_NAME="${QUANSEQ_TLS_SERVER_HOSTNAME:-localhost}"
HYBRID_GROUP="${QUANSEQ_TLS_HYBRID_GROUP:-X25519MLKEM768}"

if [[ -x "$BACKEND_DIR/.venv/bin/python" ]]; then
    PYTHON="$BACKEND_DIR/.venv/bin/python"
else
    PYTHON="${PYTHON:-python3}"
fi

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m%s\033[0m\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

require_runtime() {
    [[ -x "$NGINX_BIN" ]] || die "NGINX not built at $NGINX_BIN
       Run: bash scripts/build-pqc-tls-runtime.sh"
    [[ -x "$OPENSSL_BIN" ]] || die "OpenSSL not built at $OPENSSL_BIN
       Run: bash scripts/build-pqc-tls-runtime.sh"

    # The data plane is only meaningful if NGINX is linked against an OpenSSL
    # that has the hybrid group. Check every time, cheaply, rather than assuming.
    local linked
    linked="$("$NGINX_BIN" -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*' | awk '{print $4}')"
    case "$linked" in
        3.5.*|3.6.*|4.*) : ;;
        *) die "NGINX is built with OpenSSL ${linked:-unknown}, which cannot enforce
       $HYBRID_GROUP. Rebuild: bash scripts/build-pqc-tls-runtime.sh --force" ;;
    esac
}

nginx_pid() { [[ -f "$PID_FILE" ]] && cat "$PID_FILE" 2>/dev/null || true; }

nginx_running() {
    local pid; pid="$(nginx_pid)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

port_listening() {
    "$PYTHON" - "$TLS_HOST" "$TLS_PORT" <<'PY' 2>/dev/null
import socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1):
        sys.exit(0)
except OSError:
    sys.exit(1)
PY
}
