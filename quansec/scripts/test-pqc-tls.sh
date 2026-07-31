#!/usr/bin/env bash
# scripts/test-pqc-tls.sh — prove the PQC TLS data plane enforces what it claims.
#
# Runs one positive and six negative handshake tests with the RUNTIME OpenSSL
# 3.5.7 client, then collects the supporting evidence.
#
# The negative X25519-only test is the one that matters. A successful hybrid
# handshake shows the server CAN do hybrid; only a refused classical client
# shows it MUST. A run where the positive test passes and the negatives do not
# is a FAILING run, not a partial success.
#
#   bash scripts/test-pqc-tls.sh
#   bash scripts/test-pqc-tls.sh --capture     # + tcpdump proof of group 0x11ec

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pqc-tls-common.sh"

CAPTURE=0
for arg in "$@"; do
    case "$arg" in
        --capture) CAPTURE=1 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

require_runtime
nginx_running || die "data plane is not running - start it with scripts/start-pqc-tls.sh"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE_DIR"

say "Runtime under test"
echo "    NGINX     : $("$NGINX_BIN" -v 2>&1 | sed 's|nginx version: ||')"
echo "    Linked    : $("$NGINX_BIN" -V 2>&1 | grep -o 'built with OpenSSL.*' | head -1)"
echo "    Client    : $OPENSSL_BIN"
echo "                $("$OPENSSL_BIN" version)"
echo "    Endpoint  : $TLS_HOST:$TLS_PORT"
# Named explicitly so nobody later wonders whether the system client was used.
echo "    NOT used  : /usr/bin/openssl ($(openssl version | awk '{print $1, $2}'))"

# ── Packet capture (optional) ────────────────────────────────────────────────
CAPTURE_FILE="$EVIDENCE_DIR/handshake-$STAMP.pcap"
CAPTURE_PID=""
if [[ "$CAPTURE" == 1 ]]; then
    say "Starting packet capture on loopback"
    if getcap /usr/bin/tcpdump 2>/dev/null | grep -q cap_net_raw; then
        tcpdump -i lo -s 0 -w "$CAPTURE_FILE" "tcp port $TLS_PORT" >/dev/null 2>&1 &
        CAPTURE_PID=$!
        sleep 1
        ok "capturing to $(basename "$CAPTURE_FILE")"
    else
        warn "tcpdump lacks cap_net_raw - run:"
        warn "  bash scripts/build-pqc-tls-runtime.sh --with-capture"
        warn "continuing without a capture; the other four evidence sources still apply"
        CAPTURE=0
    fi
fi

# ── The enforcement matrix ───────────────────────────────────────────────────
say "Enforcement matrix"
cd "$BACKEND_DIR"
set +e
"$PYTHON" - <<'PY'
import json, logging, sys
sys.path.insert(0, ".")
logging.basicConfig(level=logging.ERROR)
from protocols.tls.probe import ENFORCEMENT_PROBES, TlsProber

prober = TlsProber()
results = prober.run_standard_suite()
results.append(prober.run_mtls_probe())

print()
for r in results:
    mark = "\033[32mPASS\033[0m" if r.passed else "\033[31mFAIL\033[0m"
    detail = r.negotiated_group or (f"HTTP {r.http_status}" if r.http_status else "") \
        or (r.verify_result or "")
    print(f"    [{mark}] {r.probe_type:30s} expect={r.expected_outcome:7s} "
          f"got={r.actual_outcome:7s} {detail}")
    print(f"           {r.description}")

by_type = {r.probe_type: r for r in results}
enforced = all(by_type[t].passed for t in ENFORCEMENT_PROBES if t in by_type)
positive = by_type.get("positive_hybrid")

print()
print(f"    Hybrid handshake succeeds        : {bool(positive and positive.passed)}")
print(f"    Classical clients refused        : {enforced}   <-- the proof that matters")
print(f"    All probes passed                : {all(r.passed for r in results)}")

with open("/tmp/quansec-probe-summary.json", "w") as fh:
    json.dump({"all_passed": all(r.passed for r in results),
               "enforced": enforced,
               "results": [r.to_dict() for r in results]}, fh, indent=2, default=str)

sys.exit(0 if all(r.passed for r in results) else 1)
PY
PROBE_RC=$?
set -e

# ── Evidence ─────────────────────────────────────────────────────────────────
if [[ -n "$CAPTURE_PID" ]]; then
    sleep 1
    kill "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    say "Packet capture: looking for key_share group 0x11ec (4588 = X25519MLKEM768)"
    if command -v tshark >/dev/null 2>&1; then
        tshark -r "$CAPTURE_FILE" -Y "tls.handshake.extensions_key_share_group" \
               -T fields -e tls.handshake.type \
               -e tls.handshake.extensions_key_share_group 2>/dev/null | head -6 | sed 's/^/    /'
    else
        warn "tshark not installed - capture saved but not decoded"
        echo "    Decode with: tshark -r $CAPTURE_FILE -Y tls.handshake.extensions_key_share_group"
    fi
    echo "    capture: $CAPTURE_FILE"
fi

say "NGINX log evidence (\$ssl_curve, recorded by the server itself)"
if [[ -s "$ACCESS_LOG" ]]; then
    grep -c "X25519MLKEM768" "$ACCESS_LOG" | sed 's/^/    lines recording X25519MLKEM768: /'
    tail -1 "$ACCESS_LOG" | sed 's/^/    /'
    cp "$ACCESS_LOG" "$EVIDENCE_DIR/access-$STAMP.json.log"
else
    warn "no access log lines yet - probes use -brief and may not send a request"
    echo "    Generate one:  printf 'GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n' | \\"
    echo "      $OPENSSL_BIN s_client -connect $TLS_HOST:$TLS_PORT -CAfile $CA_CERT -quiet"
fi

say "Stored evidence"
ls -1t "$EVIDENCE_DIR" | head -8 | sed 's|^|    |'
echo "    directory: $EVIDENCE_DIR"

if [[ $PROBE_RC -eq 0 ]]; then
    say "RESULT: fail-closed hybrid TLS enforcement verified"
    echo "    Key establishment : hybrid post-quantum (X25519MLKEM768), enforced"
    echo "    Authentication    : classical X.509 - see /api/tls/certificate"
else
    die "one or more enforcement tests FAILED - see the matrix above"
fi
