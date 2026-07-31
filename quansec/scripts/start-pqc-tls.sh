#!/usr/bin/env bash
# scripts/start-pqc-tls.sh — start the QUANSEC post-quantum TLS data plane.
#
# Renders nginx.conf from the backend's own settings, validates it with
# `nginx -t`, and only then starts NGINX. Rendering through the backend rather
# than a shell heredoc means the running config and the config QUANSEC reports
# are the same artifact, hashed and recorded in tls_policy_state.
#
# Uses ONLY the isolated runtime. The system NGINX and system OpenSSL are never
# invoked and never modified.
#
#   bash scripts/start-pqc-tls.sh
#   bash scripts/start-pqc-tls.sh --mtls        # require client certificates

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pqc-tls-common.sh"

MTLS_FLAG="false"
for arg in "$@"; do
    case "$arg" in
        --mtls) MTLS_FLAG="true" ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

require_runtime

if nginx_running; then
    ok "Already running (pid $(nginx_pid)) on $TLS_HOST:$TLS_PORT"
    exit 0
fi

say "Starting PQC TLS data plane"
echo "    NGINX    : $("$NGINX_BIN" -v 2>&1 | sed 's|nginx version: ||')"
echo "    OpenSSL  : $("$NGINX_BIN" -V 2>&1 | grep -o 'built with OpenSSL.*' | head -1)"
echo "    Endpoint : $TLS_HOST:$TLS_PORT"
echo "    Policy   : TLSv1.3 only, Groups=${QUANSEC_TLS_GROUPS:-$HYBRID_GROUP}, mTLS=$MTLS_FLAG"

cd "$BACKEND_DIR"
QUANSEC_TLS_MTLS="$MTLS_FLAG" "$PYTHON" - <<'PY' || die "start failed"
import logging, sys
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO, format="    %(message)s")
from protocols.tls.service import NginxTlsService
from protocols.tls.settings import TlsConfigurationError, get_tls_settings

settings = get_tls_settings()
try:
    for warning in settings.validate():
        print(f"    warning: {warning}")
except TlsConfigurationError as exc:
    print(exc, file=sys.stderr)
    sys.exit(1)

state = NginxTlsService(settings).start()
if not state.running or state.error:
    print(f"    {state.error or 'nginx did not start'}", file=sys.stderr)
    sys.exit(1)
PY

if port_listening; then
    ok "Listening on $TLS_HOST:$TLS_PORT (pid $(nginx_pid))"
    echo
    echo "    Verify:  bash scripts/test-pqc-tls.sh"
    echo "    Logs:    tail -f $ACCESS_LOG"
else
    die "NGINX started but nothing is listening on $TLS_HOST:$TLS_PORT"
fi
