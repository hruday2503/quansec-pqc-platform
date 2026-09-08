# TLS Portal — operations, evidence and limits

What the TLS module does, how to run it, and — importantly — what its numbers
do and do not prove.

Companion documents: [`../SETUP.md`](../SETUP.md) for first-time provisioning,
[`../AUTHENTICATION.md`](../AUTHENTICATION.md) for the token model,
[`TLS.md`](TLS.md) for protocol background.

---

## 1. Architecture

```
browser ──TLS 1.3──> NGINX :8444 (portal)   ──> Next.js  :3000
                                             └─> FastAPI :8000 ──> PostgreSQL
                                                                └─> Redis
OpenSSL client ──TLS 1.3──> NGINX :8443 (strict) ──> /dataplane/ only
                                   │
                                   └─ JSON access log ──> TLS collector ──> PostgreSQL
```

**Two listeners, and the difference is the whole point.**

| | `:8443` strict | `:8444` portal |
|---|---|---|
| Groups | `X25519MLKEM768` only | hybrid first, classical fallback |
| Ciphersuites | `TLS_AES_256_GCM_SHA384` only | the three TLS 1.3 suites |
| Serves | `/dataplane/` only | Next.js + FastAPI |
| Browser can connect | **No, by design** | Yes |
| Probed | Yes | **No** |
| Access log | `logs/access.json.log` | `logs/access-portal.json.log` |
| Counts as enforcement evidence | **Yes** | **No** |

No mainstream browser negotiates `X25519MLKEM768` against a single-ciphersuite
policy with a private CA. Weakening `:8443` to make the dashboard reachable
would destroy the property the probes exist to verify, so the portal got its
own listener instead. Sessions observed on `:8444` describe what a client
*chose*; only `:8443` shows what the server *required*.

---

## 2. Running it

Ubuntu's system OpenSSL (3.0.x) cannot do ML-KEM. The runtime is built from
source into `~/.quanseq/pqc-tls` and **the system OpenSSL is never replaced.**

```bash
# One time — builds OpenSSL 3.5.7 + NGINX 1.27.5. Takes a while.
bash quanseq/scripts/build-pqc-tls-runtime.sh

# One time — development PKI into ~/quanseq-certs (ca, server, client)
python3 quanseq/scripts/generate_tls_certs.py

# Database
cd quanseq && source .venv/bin/activate
python3 seed_admin.py            # admin@quanseq.io, password from ADMIN_PASSWORD

# Data plane
bash quanseq/scripts/start-pqc-tls.sh
bash quanseq/scripts/status-pqc-tls.sh
bash quanseq/scripts/stop-pqc-tls.sh

# Backend (migrations run automatically at startup)
cd quanseq && uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd quanseq-ui && npm run dev
```

Then open **`https://localhost:8444/tls-portal`**. The certificate is signed by
the development CA at `~/quanseq-certs/ca.crt`; trust it or accept the warning.

### Enforcement check

```bash
bash quanseq/scripts/test-pqc-tls.sh          # scripted
cd quanseq && python3 -m pytest tests/test_tls_enforcement.py -q
```

The pytest suite skips itself if the listener is down — a missing data plane is
an environment fact, not a code defect.

---

## 3. What the evidence means

The module's central rule: **configuration is never evidence.** A file saying
`Groups X25519MLKEM768` proves only what was asked for.

Four states, in strict order of strength:

| State | Requires |
|---|---|
| `HYBRID UNAVAILABLE` | runtime does not list the group, or service unreachable |
| `HYBRID SUPPORTED` | runtime lists it; no successful handshake evidence |
| `HYBRID VERIFIED` | a real handshake negotiated it (an NGINX log line) |
| `HYBRID ENFORCED` | **and** X25519-only, P-256-only and TLS 1.2 were all refused |

Only the fourth is a guarantee. `hybrid_group_configured` is an intention.
`hybrid_group_negotiated` proves the server *can*, not that it *must*.

### Where each fact comes from

| Fact | Source | Never from |
|---|---|---|
| `negotiated_group` | `$ssl_curve` in the access log | the config file |
| `hybrid_negotiated` | derived from the recorded group | `pqc_enabled` config |
| `hybrid_only_enforced` | both classical probes refused | anything else |
| `client_certificate_verified` | `$ssl_client_verify` | assumed |
| `certificate_signature_algorithm` | reading the certificate | the handshake |
| `failed_handshakes` | probe results | the access log |

**`failed_handshakes` cannot come from the log.** A refused handshake never
reaches the HTTP layer, so NGINX writes no line — the absence *is* the
fail-closed behaviour. An HTTP 5xx is a failed request on a *successful*
handshake and is excluded.

### Three tri-states that must not collapse to booleans

- **`negotiated_group` null** — NGINX reported none. A resumed session performs
  no key exchange. Not the same as classical.
- **`client_verify: NONE`** — no client certificate was *requested*. An absence
  of a check, not a failed one.
- **`hybrid_negotiated` null** — no group recorded, so nothing to conclude.

### Authentication is reported separately

Hybrid key exchange protects the session key. It does not change how the
certificate is signed. The accurate phrasing, used verbatim in the UI:

> Hybrid post-quantum key establishment with classical X.509 authentication.

`authentication_quantum_safe` becomes true only with a genuine ML-DSA
certificate, verified by signature-OID lookup — never inferred from the group.

---

## 4. The three key systems

Conflating these is the most common misreading of the platform.

| | Lifetime | Storage | Purpose |
|---|---|---|---|
| **TLS handshake keys** | one handshake | never stored | protect the connection |
| **Login tokens** | 15 min access / 7 day refresh | refresh hashed | authenticate *people* |
| **API keys** | 90 days default | SHA-256 only | authenticate *applications* |

An API key does not participate in any handshake and does not make a
connection quantum-safe.

### Login tokens

Access token: HS384, algorithm allow-list (blocks `alg: none` and the
RS256→HS256 confusion), claims `sub, role, scopes, portal, iat, exp, iss, aud,
jti`, issuer and audience verified.

Refresh token: ≥32 random bytes, SHA-256 at rest, **rotated on every use**,
grouped into families. Presenting an already-rotated token is treated as theft
and revokes the whole family. Browser refresh tokens live in a
Secure/HttpOnly/SameSite cookie — never `localStorage` — with CSRF protection
on the cookie-authenticated routes.

Roles and scopes are **never** read from the login request.

### Scopes

```
tls:read    status, stats, sessions, events, policy, readiness
tls:probe   run probes and validation tests        (implies tls:read)
tls:admin   apply/rollback policy, control service (implies read + probe)
system:admin  everything
```

`tls:probe` exists so a monitoring integration can prove enforcement without
being able to change it. It does **not** imply `tls:admin` in either direction.

### API keys

```bash
# Create (UI: /tls-portal/keys, or API)
curl -X POST https://localhost:8444/api/keys \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"ci-monitor","protocol":"tls","scopes":["tls:read"]}'

# Use — Authorization: Bearer, NOT X-API-Key
curl https://localhost:8444/api/tls/status -H "Authorization: Bearer qsk_live_..."
```

Rules: prefix `qsk_live_`; raw value returned **once**; only
`sha256(key)` stored; default expiry **90 days**; a non-expiring key requires
`system:admin`; requested scopes are intersected with the creator's, so a key
can never exceed the person who made it; revocation takes effect immediately.

---

## 5. API summary

Read (`tls:read`): `GET /api/tls/status`, `/stats`, `/sessions`,
`/sessions/{id}`, `/events`, `/policy`, `/readiness`, `/certificate`,
`/signature-algorithms`.

Admin (`tls:admin`): `POST /api/tls/policy/apply`, `/probe`,
`/tests/hybrid-downgrade`, `/tests/tls12-downgrade`,
`/tests/cipher-downgrade`, `/service/{action}`.

Unauthenticated by design: `GET /api/tls/dataplane/echo` — reachable only
through the `:8443` endpoint, which an `s_client` handshake reaches with no
bearer token to present. It returns only what NGINX already observed about the
caller's own connection, so it discloses nothing the caller did not supply.

`/stats` fields: `total_sessions` (one **connection**, not one request),
`active_sessions`, `hybrid_sessions`, `classical_sessions`, `unknown_sessions`,
`hybrid_coverage`, `tls13_coverage`, `failed_handshakes`, `active_alerts`,
`last_observed_at`, `has_evidence`, `active_window_seconds`.

`hybrid_coverage` excludes unknown-group sessions from the denominator rather
than counting them as classical. `has_evidence` distinguishes a measured zero
from an empty table.

---

## 6. Limitations

**Read this before presenting the platform as protected.**

1. **The dashboard is not on an enforced hybrid channel.** Your browser reaches
   `:8444`, which permits classical fallback. Only `:8443` is enforced.
2. **Certificate authentication is classical.** RSA/ECDSA. No ML-DSA
   certificate is in use, so `authentication_quantum_safe` is false.
3. **mTLS is off** (`TLS_MTLS=false`). `negative_missing_client_cert` therefore
   connects, correctly, and is excluded from the enforcement verdict.
4. **`failed_handshakes` includes stale probe rows** from before the listener
   was first started. Honest data, misleading impression; needs a time window.
5. **Development PKI only.** The CA private key sits on disk beside the server
   key in `~/quanseq-certs`. Not production PKI.
6. **Not implemented**: `events.py`, the validation lab (`attacks.py`), policy
   rollback via `tls_policy_history`, the alert engine, WebSocket ticket
   authentication. The tables exist; the code does not. Portal pages for Docs,
   Readiness, Alerts, SIEM and Validation Lab are absent.
7. **`/api/tls/status` returns ~8 of the 20 specified fields.**
8. **72 pre-existing test errors** in the backend suite, from an `api_client`
   fixture that binds to a per-test event loop. Unrelated to TLS; present
   before this work.
9. **Single-node assumptions.** HS384 with a shared secret suits one backend.
   Multiple independent verifiers would want asymmetric signing.
10. **The collector infers liveness from recency.** NGINX logs no
    connection-close event, so `active_sessions` is "seen within
    `active_window_seconds`", not a live socket count.

---

## 7. Test coverage

```bash
cd quanseq && python3 -m pytest tests/test_tls_enforcement.py tests/test_tls_api.py -q
# 45 passed

cd quanseq-ui && npx tsc --noEmit && npm run build
```

`test_tls_enforcement.py` opens real TLS connections — positive hybrid,
X25519-only, P-256-only, TLS 1.2, AES-128, invalid CA — and asserts the
runtime OpenSSL is 3.5.x, because a probe that silently used the system 3.0.x
would report a failure that says nothing about the server.

`test_tls_api.py` covers the scope algebra, that every TLS route carries a
scope dependency (introspected, with exactly one documented exemption), stats
consistency, that `hybrid_negotiated` never disagrees with the recorded group,
tri-state parsing, policy gating, and that only the key hash is stored.

`npm run lint` reports 20 errors, all the same `react-hooks/set-state-in-effect`
pattern used by every existing portal page. Pre-existing; not build-blocking.
