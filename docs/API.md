# API reference

Complete endpoint reference for the QUANSEC backend.

**Base URL:** `http://localhost:8000` · **Interactive docs:** `/docs` · **OpenAPI:** `/openapi.json`

- [1. Authentication](#1-authentication)
- [2. Conventions](#2-conventions)
- [3. Auth endpoints](#3-auth-endpoints)
- [4. API keys](#4-api-keys)
- [5. IPsec](#5-ipsec)
- [6. SSH](#6-ssh)
- [7. Zero Trust](#7-zero-trust)
- [8. Certificate authority](#8-certificate-authority)
- [9. Scoring](#9-scoring)
- [10. Alerts](#10-alerts)
- [11. Fail-mode](#11-fail-mode)
- [12. SIEM export](#12-siem-export)
- [13. Metrics](#13-metrics)
- [14. WebSocket](#14-websocket)
- [15. System](#15-system)
- [16. Errors](#16-errors)

---

## 1. Authentication

Every endpoint except `/`, `/health`, `/metrics` and `/api/ws/live` requires a
bearer credential.

```http
Authorization: Bearer <credential>
```

Two credential types resolve through the same header:

| Type | Format | Lifetime | Obtain via |
|---|---|---|---|
| **JWT** | `eyJhbGciOiJIUzI1NiIs…` | `JWT_EXPIRE_HOURS` (default 24 h) | `POST /api/auth/login` |
| **API key** | `qsk_live_<43 chars>` | until revoked | `POST /api/keys` |

`core/auth.py:get_current_user` dispatches on the `qsk_live_` prefix; everything
downstream is unaware of which was used. API keys additionally update
`api_keys.last_used` on every request.

### Roles

| Role | Can |
|---|---|
| `operator` | Read everything, run attack simulations, acknowledge alerts, create/revoke their own API keys |
| `admin` | All of the above, plus apply policies, issue certificates, set fail-mode, register users, list users |

The dividing line is *does this change the security posture of a live system*.

### Getting a token

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@quansec.io&password=$ADMIN_PASSWORD" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8000/api/ipsec/stats -H "Authorization: Bearer $TOKEN"
```

Login is an **OAuth2 password form**, not JSON — the field is `username`, and it
carries the email address.

---

## 2. Conventions

| | |
|---|---|
| Content type | `application/json`, except login (`application/x-www-form-urlencoded`), `/metrics` and CEF/syslog exports (`text/plain`) |
| Timestamps | ISO 8601 with timezone (`2026-07-29T14:23:11.482Z`) |
| Pagination | `?limit=&offset=` where supported; every `limit` has a server-side maximum |
| Booleans in queries | `true` / `false` |
| Empty results | `200` with `[]` or a zeroed object — never `404` |
| Missing resource by id | `404` |

---

## 3. Auth endpoints

### `POST /api/auth/login`

OAuth2 password flow. Form-encoded.

```bash
curl -X POST localhost:8000/api/auth/login \
  -d "username=admin@quansec.io&password=<password>"
```

```json
{"access_token":"eyJ…","token_type":"bearer","role":"admin","email":"admin@quansec.io"}
```

`401` on bad credentials. A successful login writes an `audit_events` row.

### `POST /api/auth/login-scoped?portal={ipsec|ssh}`

Portal-scoped login. Same form body. Rejects with `403` when the user's
`users.portal` is neither the requested portal nor `main`. Admins bypass the
check. This is how one deployment serves separate IPsec and SSH tenants from one
user table.

### `POST /api/auth/register` — **admin**

```json
{"email": "operator@example.com", "password": "…", "role": "operator"}
```

`201` with the new user. `409` if the email exists, `400` if the role is not
`admin` or `operator`.

### `GET /api/auth/me`

The authenticated user: `{id, email, role, created_at}`.

### `GET /api/auth/users` — **admin**

All users, ordered by id.

---

## 4. API keys

Long-lived credentials for server-to-server integration.

### `POST /api/keys`

```json
{"name": "prod-monitoring", "scopes": ["read"]}
```

```json
{
  "id": 3, "name": "prod-monitoring",
  "api_key": "qsk_live_xR9k…",
  "key_prefix": "qsk_live_xR9…m2Qp",
  "scopes": ["read"], "created_at": "2026-07-29T14:23:11Z",
  "warning": "This is the only time the full key is shown. Store it securely."
}
```

**`api_key` is returned once and never again.** Only `sha256(key)` is stored.

Note: `scopes` is stored and returned but **not yet enforced** — a key with
`["read"]` currently has the same access as its owning user. Treat it as
documentation of intent, not a control.

### `GET /api/keys`

Your keys, masked. Returns `key_prefix`, never the key.

### `DELETE /api/keys/{id}`

Sets `revoked_at`. Immediate — the next request with that key fails auth.
`404` if not found or already revoked. Users can only revoke their own keys.

---

## 5. IPsec

`/api/ipsec/*` declares `require_user` at the router level.

### `GET /api/ipsec/tunnels`

| Query | Type | Default | Notes |
|---|---|---|---|
| `state` | string | — | `ESTABLISHED`, `INSTALLED`, `DOWN`, `CONNECTING` — upper-cased server-side |
| `pqc` | bool | — | Filter by `pqc_enabled` |
| `limit` | int | 50 | 1–200 |
| `offset` | int | 0 | |

```json
[{
  "id": 1, "name": "pqc-tunnel/net",
  "local_host": "192.168.1.6", "local_id": "vm-a",
  "remote_host": "192.168.1.7", "remote_id": "vm-b",
  "state": "INSTALLED", "ike_version": 2,
  "ike_proposal": "AES_CBC-256-HMAC_SHA2_256_128-PRF_HMAC_SHA2_256-ML_KEM_1024",
  "esp_proposal": "AES_CBC-256-HMAC_SHA2_256_128",
  "pqc_kem": "ML-KEM-1024", "pqc_enabled": true,
  "bytes_in": 8432, "bytes_out": 8432, "packets_in": 84, "packets_out": 84,
  "established_at": "2026-07-29T14:01:03Z",
  "last_seen": "2026-07-29T14:23:11Z", "created_at": "2026-07-29T13:58:44Z"
}]
```

### `GET /api/ipsec/tunnels/{id}` · `POST /api/ipsec/tunnels`

`GET` returns one tunnel or `404`. `POST` seeds a tunnel config before
StrongSwan establishes it, with state `CONNECTING`:

```json
{"name":"branch-office","local_host":"10.0.0.1","remote_host":"10.1.0.1",
 "ike_version":2,"pqc_kem":"kyber1024"}
```

The collector takes over once a real SA with the same name appears.

### `GET /api/ipsec/stats`

```json
{"total_tunnels":1,"established":1,"down":0,"pqc_enabled":1,
 "pqc_coverage":100.0,"total_bytes_in":8432,"total_bytes_out":8432,
 "last_updated":"2026-07-29T14:23:11.482Z"}
```

`established` counts both `ESTABLISHED` and `INSTALLED` — StrongSwan uses
`ESTABLISHED` for an IKE_SA and `INSTALLED` for a CHILD_SA, and both mean up.

### `GET /api/ipsec/events` · `GET /api/ipsec/handshakes`

`events`: `?tunnel_name=&event_type=&limit=100` (max 500). `event_type` is
upper-cased server-side.

`handshakes`: the same rows plus `stage_order` for timeline rendering
(`IKE_SA_INIT` 1 → `IKE_AUTH` 2 → `ESTABLISHED` 3 → `CHILD_UP` 4 → rekeys 5 →
`CHILD_DOWN` 6 → `DOWN` 7; unknown types get 99).

### `POST /api/ipsec/refresh`

Runs a poll cycle immediately. Returns `{"status":"ok","tunnels_in_db":N}`.

### `GET /api/ipsec/policies` · `POST /api/ipsec/policies/apply` · `GET /api/ipsec/policies/compare`

Policies: `classical`, `pqc-level3`, `pqc-level5`. Apply is **admin**:

```json
{"policy_name": "pqc-level5", "tunnel_name": "pqc-tunnel"}
```

```json
{"status":"applied","policy":"pqc-level5",
 "ike_proposal":"aes256-sha256-mlkem1024","pqc_enabled":true,
 "dev_mode":false,
 "message":"Reload successful. Re-initiate tunnel to use new policy."}
```

**Check `dev_mode`.** When `true`, StrongSwan is absent and the config was
written to `/tmp/quansec/swanctl/swanctl.conf` — nothing on the live system
changed. Also note that existing SAs keep their old proposal until the next
rekey. Details: [protocols/IPSEC.md §9](protocols/IPSEC.md#9-the-policy-engine).

### `POST /api/ipsec/attacks/{name}` · `GET /api/ipsec/attacks/results`

`name` ∈ `downgrade`, `shors`, `harvest`, `factoring`, `kyber-resist`.

Each reads the live tunnel state and branches on whether PQC is active. Verdicts
are `BLOCKED`/`VULNERABLE`, `RESISTANT`/`VULNERABLE`, `PROTECTED`/`VULNERABLE`,
or `BROKEN`. `results` returns the last 50 from the audit trail.

`factoring` performs real Pollard's rho factoring of a generated 64-bit key. The
others are reasoned demonstrations against live configuration — see
[protocols/IPSEC.md §10.1](protocols/IPSEC.md#101-what-is-real-and-what-is-illustrative).

---

## 6. SSH

### `GET /api/ssh/stats`

```json
{"total_connections":3,"active":1,"closed":2,"pqc_enabled":1,
 "pqc_coverage":100.0,"total_bytes_sent":14208,"total_bytes_received":9112,
 "last_updated":"2026-07-29T14:23:11.482Z"}
```

`pqc_coverage` is over **active** sessions only; `total_connections` counts every
row ever recorded.

### `GET /api/ssh/connections` · `GET /api/ssh/handshakes`

`connections` returns all sessions, active first then by `last_seen`.
`handshakes?limit=10` returns recent KEX negotiations.

```json
[{"id":7,"session_key":"192.168.1.6:41022->192.168.1.7:2222",
  "local_host":"192.168.1.6:41022","remote_host":"192.168.1.7:2222",
  "remote_user":null,
  "kex_algorithm":"mlkem768x25519-sha256","kem_label":"ML-KEM-768",
  "pqc_enabled":true,"state":"ACTIVE",
  "bytes_sent":14208,"bytes_received":9112,
  "established_at":"2026-07-29T14:19:02Z","last_seen":"2026-07-29T14:23:11Z"}]
```

`remote_user` is always `null` — `ss` cannot see the SSH username, which is
negotiated inside the encrypted channel. The authenticated principal is in the
Zero Trust audit instead.

### `GET /api/ssh/policies` · `POST /api/ssh/policies/apply` · `GET /api/ssh/policies/history` · `POST /api/ssh/policies/rollback`

Policies: `classical`, `pqc-hybrid`. Apply and rollback are **admin**.

```json
{"status":"applied","policy":"pqc-hybrid","kex":"mlkem768x25519-sha256",
 "pqc_enabled":true,"dev_mode":false,
 "message":"sshd restarted. New SSH connections use the new KEX. Reconnect to apply."}
```

Rollback reverts to the previous policy; `400` if there is no history to revert
to. Existing sessions keep the KEX they negotiated.

### `GET /api/ssh/policies/compare`

Classical vs hybrid comparison rows plus `current_kex` (read live via `sshd -T`),
`cnsa_deadline: "2030 (SSH)"` and a `days_remaining` countdown.

### `POST /api/ssh/attacks/{name}`

`name` ∈ `downgrade`, `shors`, `harvest`. Reads the most recent active session's
KEX (falling back to `sshd -T`) and branches. `404` on an unknown name.

---

## 7. Zero Trust

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/ssh/zt/events?limit=50` | Certificate auth events |
| `GET` | `/api/ssh/zt/status` | Posture summary |
| `GET` | `/api/ssh/zt/policy` | Enforcement statement + principles |

```json
// GET /api/ssh/zt/events
[{"event_time":"2026-07-29T14:19:02Z","identity":"alice@quansec.io",
  "cert_serial":"3","ca_fingerprint":"SHA256:Xk9…","source_ip":"192.168.1.6",
  "principal":"hd6441","result":"accepted","reason":"ok"}]
```

```json
// GET /api/ssh/zt/status
{"total_auth_events":42,"accepted":38,"rejected":4,"rejected_expired":3,
 "cert_only":true,"passwords_disabled":true}
```

`cert_only` and `passwords_disabled` are **static assertions** describing the
intended posture, not live reads of `sshd_config`.

---

## 8. Certificate authority

### `GET /api/ssh/ca/info`

```json
{"ca_public_key":"ssh-ed25519 AAAAC3… QUANSEC CA",
 "fingerprint":"256 SHA256:Xk9… QUANSEC CA (ED25519)",
 "trusted_by":"all QUANSEC PQC SSH servers"}
```

### `POST /api/ssh/ca/issue` — **admin**

```json
{"public_key":"ssh-ed25519 AAAAC3NzaC1… alice@laptop",
 "identity":"alice@quansec.io","principals":"hd6441","valid_hours":8}
```

`valid_hours` is bounded 1–168 by Pydantic. The response includes the signed
certificate, a suggested filename, and the ssh command to use it.

`400` if the input is not a single well-formed public key line, or if it looks
like a private key. **Never submit a private key** — the endpoint rejects it, but
the correct behaviour is not to send it.

### `GET /api/ssh/ca/issued`

Last 50 issued certificates with a computed `expired` flag. Note that
`expires_at` ignores the 1-hour validity backdate — see
[protocols/SSH.md §7.4](protocols/SSH.md#74-known-limitations).

---

## 9. Scoring

| Method | Path |
|---|---|
| `GET` | `/api/scoring/ipsec` |
| `GET` | `/api/scoring/ssh` |
| `GET` | `/api/scoring/overall` |

```json
{"protocol":"ssh","score":92.5,"grade":"A",
 "factors":{"coverage":100.0,"algorithm_strength":90.0,
            "downgrade_resistant":true,"hybrid_construction":true,
            "zero_trust_events":38},
 "weights":{"coverage":"40%","algorithm_strength":"35%",
            "downgrade_resistance":"15%","hybrid":"10%"},
 "sessions_evaluated":1}
```

The model:

```
score = coverage×0.40 + algorithm_strength×0.35
      + (downgrade_resistant ? 100 : 0)×0.15 + hybrid_bonus×0.10
```

- **coverage** — % of active connections using PQC
- **algorithm_strength** — mean of a per-algorithm table (ML-KEM-1024 = 100,
  `mlkem768x25519` = 90, ML-KEM-768 = 85, sntrup761 = 80, curve25519 = 30,
  ECDH = 25, DH = 20)
- **downgrade_resistant** — every evaluated connection is PQC
- **hybrid_bonus** — 100 when a hybrid construction is in use, else 60

Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 50, F below.

`overall` averages IPsec and SSH and reports `cnsa_ready` when ≥ 90.

Two behaviours worth knowing: when no connections are in the preferred state the
scorer falls back to *all* rows rather than reporting nothing; and with zero rows
`total` is forced to 1, so the score is 0 rather than a division error.

---

## 10. Alerts

| Method | Path | Auth |
|---|---|---|
| `GET` | `/api/alerts` | user |
| `GET` | `/api/alerts/rules` | user |
| `POST` | `/api/alerts/{id}/ack` | user |

```json
{"active_count":1,
 "alerts":[{"id":12,"rule":"downgrade_detected","severity":"critical",
            "protocol":"ssh",
            "message":"SSH session using classical KEX: curve25519-sha256 (192.168.1.9)",
            "acked":false,"raised_at":"2026-07-29T14:20:00Z"}]}
```

Rules evaluated every 10 s:

| Rule | Severity | Fires when |
|---|---|---|
| `downgrade_detected` | critical | An established IPsec tunnel or active SSH session is not PQC |
| `zt_rejection` | medium | A Zero Trust certificate auth was rejected |
| `pqc_coverage_drop` | high | Declared in `RULES`; **not currently evaluated** |
| `tunnel_down` | high | Declared in `RULES`; **not currently evaluated** |

Alerts are deduplicated by a `fingerprint` (`UNIQUE`), so a persistent condition
raises one row rather than one every 10 seconds. There is no auto-resolve — an
alert stays until acknowledged.

---

## 11. Fail-mode

| Method | Path | Auth |
|---|---|---|
| `GET` | `/api/failmode` | user |
| `POST` | `/api/failmode/set` | **admin** |

```json
{"ssh":{"mode":"fail-closed","kex":"mlkem768x25519-sha256",
        "desc":"PQC only — classical refused"},
 "ipsec":{"mode":"fail-closed","proposal":"aes256-sha256-mlkem1024",
          "desc":"PQC only — classical refused"},
 "recommendation":"fail-closed for maximum quantum safety; fail-open only where uptime outweighs downgrade risk"}
```

```json
// POST /api/failmode/set
{"protocol":"ssh","mode":"fail-open"}
```

**This endpoint records intent; it does not reconfigure anything.** State lives in
an in-memory dict that resets to `fail-closed` on restart, and the response says
so: *"Apply via the protocol policy engine to enforce on the live daemon."* Use
`/api/{ipsec,ssh}/policies/apply` to change actual behaviour.

---

## 12. SIEM export

| Method | Path |
|---|---|
| `GET` | `/api/siem/events?format={json\|cef\|syslog}` |
| `GET` | `/api/siem/cef` |

```
CEF:0|QUANSEC|PQC-Platform|1.0|zt_rejected|Zt Rejected|8|rt=2026-07-29T14:19:02+00:00 act=zt_rejected outcome=ssh-zero-trust msg=identity=alice@quansec.io src=192.168.1.6 reason=expired
```

CEF severities: attacks 6, policy changes 5, key revocation 6, key creation 4,
ZT rejection 8, login 3, default 3.

**Known issue:** the audit-events query selects `audit_events.created_at`, but the
column is `occurred_at`. The query is wrapped in `try/except` and logged at DEBUG,
so exports currently contain **Zero Trust events only** and silently omit audit
events. Fixing it is a one-word change in `protocols/siem/router.py`.

---

## 13. Metrics

`GET /metrics` — Prometheus text exposition. **No authentication** (scrapers do
not carry bearer tokens); restrict at the network layer.

```
# HELP quansec_ipsec_tunnels_total Total IPsec tunnels
# TYPE quansec_ipsec_tunnels_total gauge
quansec_ipsec_tunnels_total 1
quansec_ipsec_tunnels_established 1
quansec_ipsec_tunnels_pqc 1
quansec_ipsec_pqc_coverage_percent 100.0
quansec_ipsec_bytes_in_total 8432
quansec_ipsec_bytes_out_total 8432
quansec_ssh_sessions_total 3
quansec_ssh_sessions_active 1
quansec_ssh_sessions_pqc 1
quansec_ssh_pqc_coverage_percent 100.0
quansec_ssh_bytes_sent_total 14208
quansec_ssh_bytes_received_total 9112
quansec_zt_auth_accepted_total 38
quansec_zt_auth_rejected_total 4
```

Each metric block is independently wrapped in `try/except`, so one failing query
does not empty the whole response.

Scrape config:

```yaml
scrape_configs:
  - job_name: quansec
    static_configs: [{targets: ['quansec-host:8000']}]
```

---

## 14. WebSocket

```
ws://localhost:8000/api/ws/live
```

On accept:

```json
{"type":"connected","message":"QUANSEC live feed connected","channel":"quansec:live"}
```

Then every message published to `quansec:live`:

```json
// collector summary, every poll
{"protocol":"ipsec","total":1,"up":1,"down":0,
 "pqc_count":1,"pqc_pct":100.0,"timestamp":"2026-07-29T14:23:11Z"}
```

```json
// lifecycle event, as it happens
{"protocol":"ipsec","kind":"lifecycle","tunnel":"pqc-tunnel",
 "event":"ESTABLISHED",
 "detail":{"stage":"ESTABLISHED","local_host":"192.168.1.6",
           "remote_host":"192.168.1.7","encr_alg":"AES_CBC",
           "integ_alg":"HMAC_SHA2_256_128",
           "key_exchange":"ML_KEM_1024","pqc":true},
 "timestamp":"2026-07-29T14:23:11Z"}
```

**Currently unauthenticated** — see [SECURITY.md](SECURITY.md#websocket).

The socket carries notifications, not authoritative state. Clients should refetch
over REST on a `lifecycle` message rather than mutating local state from the
payload.

---

## 15. System

### `GET /health`

```json
{"status":"ok","database":"connected",
 "collectors":["ipsec-collector","ipsec-events","alerts","zt-audit","ssh-collector"]}
```

`collectors` lists only tasks that are still running — a dead collector
disappears from the list. Monitor its **length**, not just `status`.

### `GET /`

Service banner: name, version, docs link, protocol list.

---

## 16. Errors

| Code | Meaning | Typical cause |
|---|---|---|
| `400` | Bad request | Unknown policy name, malformed public key, invalid role |
| `401` | Unauthenticated | Missing, expired or invalid token; revoked API key |
| `403` | Forbidden | Operator hitting an admin endpoint; wrong portal on scoped login |
| `404` | Not found | Unknown tunnel id, key id, or attack name |
| `409` | Conflict | Email already registered |
| `422` | Validation error | Pydantic rejected the body — the response names the field |
| `500` | Server error | Config write failed, `sshd -t` rejected the config, CA unavailable |

```json
{"detail": "Admin privileges required"}
```

`422` uses FastAPI's structured form:

```json
{"detail":[{"loc":["body","valid_hours"],"msg":"ensure this value is <= 168",
            "type":"value_error.number.not_le"}]}
```

`401` responses include `WWW-Authenticate: Bearer`.

---

*See also:* [SECURITY.md](SECURITY.md) · [protocols/IPSEC.md](protocols/IPSEC.md) · [protocols/SSH.md](protocols/SSH.md) · [OPERATIONS.md](OPERATIONS.md)
