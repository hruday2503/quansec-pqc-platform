# TLS module

> ## ⚠️ Specification, not shipped code
>
> **The TLS module is not implemented.** `quansec/protocols/tls/` contains only an
> empty `__init__.py`, and the TLS router is commented out in `main.py`:
>
> ```python
> # app.include_router(tls_router)    # Phase 2
> ```
>
> Everything below is a **design specification** derived from the existing
> protocol module contract. It exists so the module can be built without
> redesign — not as a description of working functionality.
>
> **What *does* exist today:** TLS placeholder rows seeded by migrations
> (`fail_mode_policies` and `pqc_scores` both carry a `tls` row), and two unused
> config keys (`NGINX_ACCESS_LOG`, `TLS_POLL_INTERVAL`). That is why `tls` appears
> in the database with a grade of F and a risk level of critical — it is a seeded
> placeholder, not a measurement.

**Status:** planned · **Target KEX:** `X25519MLKEM768` (hybrid) · **NIST level:** 3 · **CNSA 2.0 deadline:** 2030

- [1. Why TLS matters most](#1-why-tls-matters-most)
- [2. Cryptographic design](#2-cryptographic-design)
- [3. Where the telemetry comes from](#3-where-the-telemetry-comes-from)
- [4. Proposed module structure](#4-proposed-module-structure)
- [5. Proposed schema](#5-proposed-schema)
- [6. Proposed API](#6-proposed-api)
- [7. Proposed policy engine](#7-proposed-policy-engine)
- [8. Integration with cross-cutting modules](#8-integration-with-cross-cutting-modules)
- [9. Implementation plan](#9-implementation-plan)
- [10. Open questions](#10-open-questions)

---

## 1. Why TLS matters most

TLS is the highest-volume, highest-exposure protocol of the three, and it has the
**earliest** CNSA 2.0 deadline alongside SSH — **2030**.

| | IPsec | SSH | TLS |
|---|---|---|---|
| Typical endpoints | tens | hundreds | **millions** |
| Network exposure | usually private | usually private | **public internet** |
| Sessions per day | tens | thousands | **billions** |
| Harvest-now-decrypt-later exposure | high (long-lived tunnels) | medium | **highest** |
| CNSA 2.0 deadline | 2033 | 2030 | **2030** |

It is also the protocol where post-quantum deployment is furthest along in the
real world: Chrome and Firefox enable `X25519MLKEM768` by default, Cloudflare
reports a large and growing share of connections negotiating it, and OpenSSL 3.5
supports it natively. A TLS module therefore measures something that is *already
happening* rather than something that has to be enabled first — which makes it
the strongest candidate for demonstrating real-world PQC coverage.

---

## 2. Cryptographic design

### 2.1 Target key exchange

```
X25519MLKEM768        IANA named group 0x11EC (4588)
```

Hybrid, exactly like SSH: an X25519 share and an ML-KEM-768 share, both fed into
the TLS 1.3 key schedule. Compromise requires breaking both.

Hybrid is the correct choice for TLS for the same reasons as SSH, only more so:
the client population is the entire internet, and a pure ML-KEM group would fail
to negotiate with the overwhelming majority of it.

Related groups worth recognising in the classifier:

| Group | ID | Notes |
|---|---|---|
| `X25519MLKEM768` | 0x11EC | The consensus deployment target |
| `SecP256r1MLKEM768` | 0x11EB | For FIPS-constrained stacks needing a NIST curve |
| `X25519Kyber768Draft00` | 0x6399 | Pre-standard; still seen from older clients |
| `x25519` | 0x001D | Classical baseline |
| `secp256r1` / `secp384r1` | 0x0017 / 0x0018 | Classical |

### 2.2 TLS 1.3 only

TLS 1.2's key exchange is bound into the cipher suite and its extension model
cannot carry a hybrid group cleanly. TLS 1.3 separates the named group from the
cipher suite, which is exactly what makes swapping in a KEM possible. A PQC TLS
module should treat TLS 1.2 as **classical by definition** and report it as such.

### 2.3 What changes and what does not

| Component | Classical | PQC | Changed? |
|---|---|---|---|
| Key exchange | X25519 / P-256 | **X25519MLKEM768** | ✅ the only broken part |
| Certificates | ECDSA P-256 / RSA-2048 | unchanged (ML-DSA later) | ❌ |
| Cipher | AES-256-GCM / ChaCha20 | unchanged | ❌ |
| Transcript hash | SHA-384 | unchanged | ❌ |

Same reasoning as the other two modules: Shor breaks key establishment
retroactively; Grover only halves symmetric strength, which 256-bit keys absorb.
Certificate signatures are a real-time forgery risk, not a retroactive one, so
ML-DSA (FIPS 204) migration follows rather than leads.

### 2.4 The size problem — unique to TLS

An `X25519MLKEM768` ClientHello key share is ~1.2 KB, versus 32 bytes for pure
X25519. Consequences that do not arise for IPsec or SSH:

- The ClientHello may exceed one TCP segment, adding a round trip on some paths.
- Some middleboxes drop or mangle unexpectedly large ClientHellos.
- QUIC has its own amplification limits to respect.

A production TLS module should therefore record **handshake latency** alongside
the negotiated group, so the cost of PQC is measured rather than asserted. This
is a metric the IPsec and SSH modules do not need and is the main reason the TLS
collector is not a straight copy of the SSH one.

---

## 3. Where the telemetry comes from

There is no VICI equivalent, and unlike SSH there is no single verbose log line.
Four viable sources, in descending order of fidelity:

### Option A — nginx access log with `$ssl_curve` (recommended)

nginx 1.21.8+ exposes the negotiated group directly:

```nginx
log_format quansec_tls '$remote_addr $ssl_protocol $ssl_cipher $ssl_curve '
                       '$ssl_session_reused $request_time';
access_log /var/log/nginx/quansec-tls.log quansec_tls;
```

- **Pros:** authoritative (it is what was negotiated), no privileged code, tails
  like the SSH collector, `$request_time` gives the latency signal for free.
- **Cons:** nginx-specific; requires a log-format change; high-volume servers
  produce a lot of lines.
- **Config key already reserved:** `NGINX_ACCESS_LOG`.

This is the recommended first implementation: it reuses the SSH collector's
log-tailing shape almost verbatim.

### Option B — active probing with OpenSSL

```bash
openssl s_client -connect host:443 -groups X25519MLKEM768 -tls1_3 </dev/null
```

- **Pros:** works against **any** server including third parties; directly tests
  whether PQC is *offered*; ideal for an external inventory of "which of my
  domains support PQC".
- **Cons:** measures capability, not actual traffic; needs OpenSSL 3.5+;
  synthetic load.

Best used as a *complement* to A — one collector for observed traffic, one for
capability inventory.

### Option C — OpenSSL callback in the application

Register a TLS info callback and report the negotiated group over an internal
endpoint.

- **Pros:** the most authoritative possible, per-connection, no log parsing.
- **Cons:** requires instrumenting every application. Not viable for a monitoring
  platform that must observe systems it does not own.

### Option D — passive capture

Parse ClientHello/ServerHello `supported_groups` and `key_share` from the wire
with `tshark` or eBPF.

- **Pros:** protocol-accurate, server-agnostic, sees clients as well as servers.
- **Cons:** needs `CAP_NET_RAW`, does not scale to high traffic, significant
  implementation cost.

**Recommendation:** implement **A** first, add **B** as a second collector for
external inventory, and treat **D** as a future enhancement.

---

## 4. Proposed module structure

Following the [module contract](../ARCHITECTURE.md#3-the-protocol-module-contract):

```
protocols/tls/
├── __init__.py
├── collector.py     collect_once(pool) + no-arg collect_loop()
├── router.py        APIRouter(prefix="/api/tls")
├── policy.py        APIRouter(prefix="/api/tls/policies")
└── models.py        TlsSessionOut, TlsStats, TlsCertificate
```

### Classification table

Mirrors `PQC_KEX` / `CLASSICAL_KEX` in the SSH collector:

```python
PQC_GROUPS = {
    "X25519MLKEM768":         ("X25519 + ML-KEM-768",  "ML-KEM-768", True),
    "SecP256r1MLKEM768":      ("P-256 + ML-KEM-768",   "ML-KEM-768", True),
    "X25519Kyber768Draft00":  ("X25519 + Kyber768",    "Kyber768",   True),
}
CLASSICAL_GROUPS = {
    "x25519":    ("X25519 (classical)", "X25519",    False),
    "prime256v1":("ECDH P-256",         "ECDH-P256", False),
    "secp384r1": ("ECDH P-384",         "ECDH-P384", False),
}
```

With the same fallback the SSH classifier uses: an unrecognised group name
containing `mlkem` or `kyber` is treated as PQC.

### Collector sketch

```python
POLL_INTERVAL = 3     # TLS_POLL_INTERVAL — TLS turns over faster than IPsec/SSH

async def collect_once(pool):
    lines = _tail_since_last_offset(settings.NGINX_ACCESS_LOG)
    for line in lines:
        remote, proto, cipher, curve, reused, rtt = _parse(line)
        label, kem, pqc = _classify(curve)
        if proto != "TLSv1.3":
            pqc = False                     # TLS 1.2 is classical by definition
        # upsert into tls_sessions, aggregated per (remote, curve) per minute
```

**Aggregation is mandatory here.** A busy server produces thousands of handshakes
per second; one row per handshake is not viable. Aggregate into per-minute
buckets keyed by `(server_name, tls_version, cipher, named_group)` with a count
and a latency percentile. This is the main structural difference from the IPsec
and SSH collectors, both of which track a bounded number of long-lived sessions.

Track the log offset between cycles so lines are read once, and handle rotation
by detecting a shrinking file size.

---

## 5. Proposed schema

`migrations/007_tls.sql` — idempotent, per the
[migration requirement](../DATA-MODEL.md#migrations).

```sql
-- Aggregated handshake observations
CREATE TABLE IF NOT EXISTS tls_sessions (
    id              BIGSERIAL PRIMARY KEY,
    server_name     TEXT NOT NULL,
    remote_host     TEXT,
    tls_version     TEXT NOT NULL,
    cipher_suite    TEXT,
    named_group     TEXT,
    kem_label       TEXT,
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    session_reused  BOOLEAN NOT NULL DEFAULT FALSE,
    handshake_count BIGINT  NOT NULL DEFAULT 1,
    handshake_ms_p50 FLOAT,
    handshake_ms_p95 FLOAT,
    bucket_start    TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_name, tls_version, cipher_suite, named_group, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_tls_sessions_pqc    ON tls_sessions(pqc_enabled);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_bucket ON tls_sessions(bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_server ON tls_sessions(server_name);

-- Certificate inventory — signature algorithms matter for the ML-DSA migration
CREATE TABLE IF NOT EXISTS tls_certificates (
    id              SERIAL PRIMARY KEY,
    server_name     TEXT NOT NULL,
    subject         TEXT,
    issuer          TEXT,
    serial_number   TEXT,
    signature_algorithm TEXT,
    public_key_algorithm TEXT,
    key_size        INTEGER,
    pqc_signature   BOOLEAN NOT NULL DEFAULT FALSE,
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    last_checked    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_name, serial_number)
);

CREATE INDEX IF NOT EXISTS idx_tls_certs_expiry ON tls_certificates(not_after);
```

The `UNIQUE` constraint on the bucket tuple is what makes the collector's upsert
idempotent, exactly as `name` does for `ipsec_tunnels` and `session_key` for
`ssh_connections`.

---

## 6. Proposed API

Mirrors the IPsec and SSH surfaces so the frontend can reuse its components.

| Method | Path | Auth | Returns |
|---|---|---|---|
| `GET` | `/api/tls/stats` | user | Coverage, handshake totals, version breakdown |
| `GET` | `/api/tls/sessions` | user | `?pqc=&server=&limit=` — aggregated buckets |
| `GET` | `/api/tls/handshakes` | user | Recent negotiations with latency |
| `GET` | `/api/tls/certificates` | user | Certificate inventory with expiry |
| `GET` | `/api/tls/policies` | user | Available group policies |
| `POST` | `/api/tls/policies/apply` | **admin** | Rewrite `ssl_ecdh_curve`, reload nginx |
| `GET` | `/api/tls/policies/compare` | user | Classical vs hybrid + CNSA 2030 countdown |
| `POST` | `/api/tls/attacks/{name}` | user | `downgrade`, `shors`, `harvest` |

```jsonc
// GET /api/tls/stats  (proposed shape)
{
  "total_handshakes": 148203,
  "pqc_handshakes": 96331,
  "pqc_coverage": 65.0,
  "tls13_handshakes": 147890,
  "tls12_handshakes": 313,
  "top_groups": [
    {"named_group": "X25519MLKEM768", "count": 96331, "pqc": true},
    {"named_group": "x25519",         "count": 51559, "pqc": false}
  ],
  "handshake_ms_p50_pqc": 12.4,
  "handshake_ms_p50_classical": 9.1,
  "last_updated": "2026-07-29T14:23:11Z"
}
```

Reporting both latency figures is what turns "PQC costs more" from an assertion
into a number the operator can weigh.

---

## 7. Proposed policy engine

Same three-endpoint contract, targeting nginx.

| Policy | `ssl_ecdh_curve` | Quantum-safe |
|---|---|---|
| `classical` | `X25519:prime256v1` | ❌ |
| `pqc-hybrid` | `X25519MLKEM768:X25519` | ✅ preferred, classical fallback |
| `pqc-only` | `X25519MLKEM768` | ✅ fail-closed — non-PQC clients refused |

`pqc-only` maps directly onto the fail-mode module: it is `fail-closed` for TLS,
and it will break every client that does not support hybrid groups. That is
exactly what the fail-mode control exists to make explicit.

Apply sequence, following the SSH engine's validate-before-restart discipline:

1. Rewrite `ssl_ecdh_curve` in the nginx server block.
2. **`sudo nginx -t`** — validate. Abort on failure *before* touching the daemon.
3. `sudo nginx -s reload` — a graceful reload, not a restart. Existing
   connections drain; no listener downtime. This is strictly better than the SSH
   engine's `pkill` + relaunch, and the SSH module should adopt the same pattern.
4. Audit row + policy history row.

Requires OpenSSL 3.5+ or an OQS-provider-enabled build for the hybrid group to be
available at all — verify with `openssl list -group-algorithms` before offering
the policy.

---

## 8. Integration with cross-cutting modules

Each of these is roughly ten lines, because the shape is fixed.

**Scoring** (`protocols/scoring/router.py`) — add `score_tls()` following
`score_ssh()`, extend `ALGO_STRENGTH` with the group names, and include TLS in
`score_overall()`'s average. The existing weights apply unchanged: coverage 40 %,
algorithm strength 35 %, downgrade resistance 15 %, hybrid construction 10 %.

**Alerts** (`protocols/alerts/evaluate_once`) — add a TLS block mirroring the SSH
one. TLS needs a *threshold* rather than a per-session rule: on the public
internet some classical clients will always exist, so alerting on every classical
handshake would be pure noise. Alert when PQC coverage drops below a configured
percentage, and separately when a TLS 1.2 handshake is observed at all.

**Metrics** (`protocols/metrics/router.py`) — add
`quansec_tls_handshakes_total`, `quansec_tls_handshakes_pqc`,
`quansec_tls_pqc_coverage_percent`, `quansec_tls_handshake_duration_ms`.

**Fail-mode** — `MODES["tls"]` with `fail-closed` → `X25519MLKEM768` and
`fail-open` → `X25519MLKEM768:X25519`. The `fail_mode_policies` table already
seeds a `tls` row.

**Frontend** — copy `app/ssh-portal/` to `app/tls-portal/`, change the nav array
and endpoint paths. The landing page already renders a TLS card, currently marked
`SOON`; flipping it to `LIVE` and pointing it at `/tls/login` is a two-line change.

---

## 9. Implementation plan

| Phase | Work | Delivers |
|---|---|---|
| **1** | `migrations/007_tls.sql`; `collector.py` parsing the nginx log; `router.py` with `/stats`, `/sessions`, `/handshakes`; wire into `main.py` | Observability — real coverage numbers from real traffic |
| **2** | `policy.py` with three policies and validate-before-reload | Enforcement |
| **3** | Certificate inventory collector (`openssl s_client -showcerts` per configured server) | ML-DSA migration planning |
| **4** | Scoring, alerts, metrics, fail-mode integration | Parity with IPsec and SSH |
| **5** | `app/tls-portal/`; flip the landing card to `LIVE` | Operator UI |
| **6** | Active-probe collector (Option B) for external inventory | Third-party PQC posture |

Phase 1 alone is worth shipping: it turns the seeded `tls` grade-F placeholder
into a measurement.

---

## 10. Open questions

Decisions that should be made before implementation rather than during it.

**Aggregation granularity.** Per-minute buckets are proposed. Per-second is too
much data; per-hour loses the ability to see a coverage drop quickly. One minute
matches the alert engine's 10-second evaluation cadence well enough.

**Retention.** `tls_sessions` grows continuously even when aggregated. IPsec and
SSH track bounded numbers of long-lived connections and have no retention policy;
TLS cannot get away with that. Decide on a rollup (per-minute → per-hour after
7 days) or a hard retention window before phase 1 ships.

**Server-side only, or clients too?** The nginx-log approach only sees inbound
connections to servers we run. Outbound TLS from our own applications — arguably
the bigger harvest-now-decrypt-later exposure — needs Option C or D.

**Which nginx?** The design assumes nginx because `NGINX_ACCESS_LOG` is already
reserved. Apache (`%{SSL_PROTOCOL}x`) and HAProxy (`%sslv %sslc`) expose
equivalent fields; Envoy and Caddy do not expose the named group as readily.
Supporting more than one means a pluggable parser rather than a single regex.

**Session resumption.** A resumed TLS session performs no key exchange, so
`$ssl_curve` is empty. Counting resumptions as classical understates coverage;
ignoring them overstates handshake volume. The proposed schema records
`session_reused` so both figures can be reported and the choice made in the API
rather than the collector.

---

*See also:* [IPSEC.md](IPSEC.md) · [SSH.md](SSH.md) · [ARCHITECTURE.md](../ARCHITECTURE.md#9-extending-the-platform) · [DATA-MODEL.md](../DATA-MODEL.md)
