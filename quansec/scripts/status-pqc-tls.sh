#!/usr/bin/env bash
# scripts/status-pqc-tls.sh — what the PQC TLS data plane is actually doing.
#
# Reports build provenance, process state, the enforced policy as parsed back
# out of the running config, and the most recent observed sessions. Read-only.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pqc-tls-common.sh"

say "Build provenance"
if [[ -x "$NGINX_BIN" ]]; then
    echo "    NGINX binary   : $NGINX_BIN"
    "$NGINX_BIN" -V 2>&1 | grep -E "^nginx version|^built with" | sed 's/^/    /'
    ldd "$NGINX_BIN" | grep -E "libssl|libcrypto" | sed 's/^\s*/    /'
else
    warn "NGINX not built - run scripts/build-pqc-tls-runtime.sh"
fi
if [[ -x "$OPENSSL_BIN" ]]; then
    echo "    OpenSSL client : $OPENSSL_BIN"
    echo "                     $("$OPENSSL_BIN" version)"
fi
echo "    System OpenSSL : $(openssl version 2>/dev/null || echo n/a)  (untouched)"
echo "    System NGINX   : $(nginx -v 2>&1 | sed 's|nginx version: ||' || echo n/a)  (untouched)"

say "Process"
if nginx_running; then
    ok "running, pid $(nginx_pid)"
else
    warn "not running"
fi
if port_listening; then
    ok "listening on $TLS_HOST:$TLS_PORT"
else
    warn "nothing listening on $TLS_HOST:$TLS_PORT"
fi

say "Enforced policy (parsed from the running config)"
if [[ -f "$NGINX_CONF" ]]; then
    grep -E "ssl_protocols|ssl_conf_command|ssl_early_data|ssl_verify_client|listen " "$NGINX_CONF" \
        | sed 's/^\s*/    /'
    echo "    config sha256  : $(sha256sum "$NGINX_CONF" | cut -c1-16)"
else
    warn "no config at $NGINX_CONF"
fi

say "Recent observed sessions"
if [[ -s "$ACCESS_LOG" ]]; then
    tail -5 "$ACCESS_LOG" | "$PYTHON" -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    # A missing group means NGINX did not report one (resumed session), which is
    # not the same as a classical group. Say so rather than printing a blank.
    print("    %s  %-8s %-18s %s" % (
        r.get("timestamp", "?"), r.get("tls_protocol", "?"),
        r.get("negotiated_group") or "(not reported)", r.get("cipher", "?")))
'
    echo "    total lines    : $(wc -l < "$ACCESS_LOG")"
else
    warn "no sessions logged yet at $ACCESS_LOG"
fi

say "Errors"
if [[ -s "$ERROR_LOG" ]]; then
    tail -3 "$ERROR_LOG" | sed 's/^/    /'
else
    ok "error log empty"
fi
