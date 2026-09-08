# TLS module

**Status:** implemented · **Transport:** real TLS 1.3 · **Target KEX:** `X25519MLKEM768` (hybrid, **not enforced**) · **CNSA 2.0 deadline:** 2030

> ## Read this before quoting any figure from this module
>
> The TLS transport is real. TLS 1.3 enforcement, certificate-chain
> verification, hostname verification and mutual TLS all work and are covered by
> tests. **Post-quantum key exchange is a different matter:**
>
> 1. **Hybrid is not enforced.** A client offering only classical X25519
>    completes a handshake against the service. Python's `ssl` module exposes no
>    TLS 1.3 group-selection API, so this cannot be fixed in Python.
> 2. **The negotiated group is not observable from Python.** `negotiated_group`
>    is always `null`. Establishing which group was used requires the OpenSSL CLI
>    or a packet capture.
> 3. **On stock Ubuntu 24.04 hybrid is unavailable outright.** OpenSSL 3.0.13 has
>    no `X25519MLKEM768`. The group needs OpenSSL 3.5.5+.
>
> The module is built so none of this can be papered over: `pqc_enabled` is
> written `TRUE` only when a verified evidence row exists, and a test asserts
> that a runtime version alone never promotes the status.

- [1. What this module measures](#1-what-this-module-measures)
- [2. Architecture](#2-architecture)
- [3. Hybrid status model](#3-hybrid-status-model)
- [4. Module structure](#4-module-structure)
- [5. Schema](#5-schema)
- [6. API](#6-api)
- [7. Configuration](#7-configuration)
- [8. Running it](#8-running-it)
- [9. Cross-cutting integration](#9-cross-cutting-integration)
- [10. Tests](#10-tests)
- [11. Known limitations](#11-known-limitations)
- [12. Future work](#12-future-work)

---

## 1. What this module measures

QUANSEQ runs its own TLS 1.3 service and connects to it, in the same way the
IPsec module talks to StrongSwan and the SSH module reads sshd. Every poll is a
real handshake; every recorded value was read off a live socket.

This is telemetry Option C from the original design (application instrumentation),
not Option A (nginx log tailing). Option A remains valid future work for observing
third-party traffic — see [§12](#12-future-work).

**What it does not measure:** traffic between a browser and the QUANSEQ dashboard.
That is ordinary HTTP on port 8000 and is untouched by this module. The TLS
service is a separate process on its own port that QUANSEQ observes.

---

## 2. Architecture

```
 browser :3000 ─── HTTP ───► FastAPI :8000            (dashboard transport, unchanged)
   (Next.js)                    │
                                │ TLS *client* only
                                │ real TLS 1.3 handshake, cert verification, optional mTLS
                                ▼
                     TLS transport service :8443       ← separate OS process
                     protocols/tls/service_main.py
                                │
                                ▼
                     PostgreSQL   tls_sessions / tls_hybrid_evidence / tls_certificates

 out-of-band verifier (admin-triggered):
   openssl s_client -connect :8443 -tls1_3 -groups X25519MLKEM768 -brief
        → the only thing that can promote hybrid status to "negotiated & verified"
```

### Why a separate process

The FastAPI app never starts the TLS server. Three reasons:

- The server is blocking and thread-per-connection. Running it beside an asyncio
  event loop invites the loop to be starved by a slow handshake.
- Process exit releases the listening socket unconditionally, which removes the
  shutdown/port-reuse race an in-process server must defend against.
- Moving the service to a second machine becomes an environment variable rather
  than a rewrite.

### Two machines, no rewrite

```bash
# On the peer machine
QUANSEQ_TLS_BIND_HOST=0.0.0.0  bash scripts/run_tls_service.sh
# Regenerate the server cert so its SAN covers the peer address
python scripts/generate_tls_certs.py --extra-ip 192.168.1.50 --force

# On the QUANSEQ machine
QUANSEQ_TLS_HOST=192.168.1.50
```

Nothing else changes.

---

## 3. Hybrid status model

Two independent axes, because availability and enforcement are different
questions and conflating them is how a platform ends up overstating its posture.

| `availability` | Meaning | How it is reached |
|---|---|---|
| `unavailable` | The runtime cannot do the group at all | Linked OpenSSL < 3.5.5, **or** the group is absent from `openssl list -tls-groups` |
| `supported` | The group exists here; nothing more is known | Runtime lists the group, no verification on record |
| `negotiated_verified` | A real handshake was verified to use it | A `tls_hybrid_evidence` row with `verified = TRUE` for this host, port and group |

| `enforcement` | Meaning |
|---|---|
| `not_enabled` | Always, today. `enforcement_reason` is `python-ssl-cannot-select-tls13-groups` |

Rules the code enforces:

- A new OpenSSL version **never** produces `negotiated_verified`. Only stored
  evidence does. `test_new_openssl_version_alone_does_not_claim_pqc` fakes a
  3.5.5 runtime and asserts the status stops at `supported`.
- `tls_sessions.pqc_enabled` is `TRUE` only when evidence covers that exact
  endpoint and group. Evidence for a different port or a different group does
  not apply.
- The UI renders the server-generated `label`, which always carries the
  enforcement qualifier. There is no code path producing an unqualified
  reassurance, and a test asserts no label contains "quantum safe".

---

## 4. Module structure

```
protocols/tls/
├── tls13/            vendored TLS 1.3 transport (see tls13/VENDOR.md)
│   ├── VENDOR.md     upstream URL, pinned commit, every patch and its rationale
│   ├── config.py     TLSConfig dataclass
│   ├── utils.py      SSLContext builders, TLS 1.3 pinning, session facts
│   ├── server.py     TLSServer — bounded handshakes, joinable shutdown
│   ├── client.py     TLSClient — verification always on
│   ├── cert_manager.py   development PKI generation (CLI only)
│   └── exceptions.py
├── settings.py       TlsSettings.from_env() + validate()
├── hybrid.py         runtime capability probe + out-of-band verification
├── certs.py          structured certificate inspection (cryptography)
├── adapter.py        TlsServiceAdapter — the only thing routers call
├── collector.py      collect_once(pool) + collect_loop()
├── models.py         pydantic request/response schemas
├── router.py         APIRouter(prefix="/api/tls")
└── service_main.py   standalone TLS service entry point
```

`tls13/` is **vendored**, not a submodule or a pip dependency. It is a copy of
the live path from an upstream repository, patched for this platform. The
excluded files and the reason for each patch are recorded in `tls13/VENDOR.md`.
Notably the upstream `phase2_server.py` was excluded outright because it emitted
`"tls_native_hybrid": True` as handshake evidence — a hardcoded post-quantum
claim, which is precisely what this module must never produce.

### Layering rule

Routers call `TlsServiceAdapter` and nothing else. Every adapter method runs the
blocking `ssl` work in `asyncio.to_thread` under an explicit timeout, so a
stalled handshake cannot block the event loop and a hung service surfaces as a
504 rather than a request that never returns.

---

## 5. Schema

`migrations/007_tls.sql`, idempotent like every other migration.

| Table | Purpose |
|---|---|
| `tls_sessions` | One row per observed handshake, successful or failed |
| `tls_hybrid_evidence` | Out-of-band group verification results |
| `tls_certificates` | Certificate inventory, for the eventual ML-DSA migration |

One row per handshake rather than per-minute aggregate buckets: this module
observes a service QUANSEQ runs and polls, which is a bounded low-rate stream.
The bucketed design in earlier revisions of this document belongs to the future
nginx collector.

Columns worth calling out in `tls_sessions`:

- `named_group` — always `NULL`. `group_source` (`unavailable-python-ssl`)
  records *why*, so a `NULL` is never misread as "no group was used".
- `pqc_enabled` — gated on verified evidence, per [§3](#3-hybrid-status-model).
- `outcome` — `success | handshake_failed | cert_failed | timeout | unreachable |
  config_error`, with a `CHECK` constraint. Failures are recorded, not dropped:
  an operator needs to see that the service was unreachable at 14:03.

---

## 6. API

All under `/api/tls`, all requiring an authenticated user except where noted.

| Method | Path | Auth | Returns |
|---|---|---|---|
| `GET` | `/api/tls/status` | user | Service reachability, runtime facts, hybrid state |
| `POST` | `/api/tls/test-connection` | user | Performs a real handshake and records it |
| `GET` | `/api/tls/session` | user | Most recent recorded observation |
| `GET` | `/api/tls/sessions` | user | `?limit=&pqc=&outcome=` |
| `GET` | `/api/tls/stats` | user | Aggregates over recorded observations |
| `GET` | `/api/tls/certificate` | user | Certificate facts + chain verification |
| `GET` | `/api/tls/policies/compare` | user | Classical vs hybrid + CNSA countdown |
| `POST` | `/api/tls/hybrid/verify` | **admin** | Runs `openssl s_client`, stores evidence |

### Two endpoints that deliberately do not exist

**Certificate generation.** It rotates the trust anchor for the whole module, so
it lives in `scripts/generate_tls_certs.py` and requires shell access. The
upstream example project exposed `POST /certs/regenerate`; that was not ported.

**`POST /api/tls/policies/apply`.** There is nothing to apply. Group selection is
not reachable from Python's `ssl`, so an "apply hybrid policy" button would
change nothing while implying enforcement — the exact class of fabricated control
this module exists to replace. `MODES["tls"]` in the fail-mode engine is marked
`enforceable: false` for the same reason.

### Error mapping

| Condition | Status |
|---|---|
| Service not listening | `503` |
| Certificates missing / module disabled / hybrid required but unavailable | `503` |
| Certificate or hostname verification failure | `502` |
| Handshake failure (including mTLS rejection) | `502` |
| Timeout | `504` |
| Malformed request body | `422` |

A failed handshake is **persisted before** the error is raised.

---

## 7. Configuration

Every variable is documented in `quanseq/.env.example`. The ones that change
behaviour most:

| Variable | Default | Notes |
|---|---|---|
| `QUANSEQ_TLS_ENABLED` | `true` | `false` makes every TLS route return 503 |
| `QUANSEQ_TLS_HOST` / `_PORT` | `127.0.0.1:8443` | Where the backend connects |
| `QUANSEQ_TLS_BIND_HOST` | `127.0.0.1` | Service only; `0.0.0.0` for two machines |
| `QUANSEQ_TLS_SERVER_HOSTNAME` | `localhost` | Must appear in the certificate SAN |
| `QUANSEQ_TLS_CERT_DIR` | `~/quanseq-certs` | Keep **outside** the repository |
| `QUANSEQ_TLS_MTLS` | `false` | Requires a client certificate signed by the CA |
| `QUANSEQ_TLS_HANDSHAKE_TIMEOUT` | `5` | Per-connection cap; see the DoS note below |
| `QUANSEQ_TLS_REQUIRE_HYBRID` | `false` | Gates startup on a *capable* runtime; does **not** enforce |
| `QUANSEQ_TLS_OPENSSL_BIN` | `openssl` | Point at a 3.5+ build if you have one |
| `QUANSEQ_TLS_LOG_PAYLOADS` | `false` | Logs message bodies in cleartext. Debugging only |

`TlsSettings.validate()` runs at startup and fails loudly on unreadable
certificates, impossible timeouts, mTLS without client material, or
`REQUIRE_HYBRID=true` on a runtime that lacks the group.

---

## 8. Running it

```bash
# 1. Development PKI (writes outside the repo, keys mode 600)
python scripts/generate_tls_certs.py --cert-dir ~/quanseq-certs

# 2. TLS transport service — its own terminal, its own process
bash scripts/run_tls_service.sh

# 3. Backend
uvicorn main:app --host 0.0.0.0 --port 8000

# 4. Confirm with an independent tool
openssl s_client -connect 127.0.0.1:8443 -tls1_3 \
        -CAfile ~/quanseq-certs/ca.crt -servername localhost -brief </dev/null
```

Expected on stock Ubuntu 24.04:

```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Verification: OK
Server Temp Key: X25519, 253 bits      ← classical: this runtime has no hybrid group
```

That last line is the honest result on OpenSSL 3.0.13, and it is what the portal
reports.

---

## 9. Cross-cutting integration

**Scoring** (`protocols/scoring/router.py`) — `score_tls()` uses the same weights
as the other protocols, with one difference: `downgrade_resistant` is `False`
unconditionally, because the hybrid group is not enforced. Awarding that 15%
would inflate the score with a property the platform does not have. TLS is
included in `score_overall()`.

**Metrics** (`protocols/metrics/router.py`) — `quanseq_tls_handshakes_total`,
`_successful`, `_failed`, `_pqc`, `quanseq_tls_pqc_coverage_percent`,
`quanseq_tls13_handshakes`, `quanseq_tls_handshake_duration_ms`,
`quanseq_tls_hybrid_verifications_total`, and `quanseq_tls_hybrid_enforced`
(a constant `0`, exported so an operator can alert on it ever flipping).

**Alerts** (`protocols/alerts/router.py`) — deliberately does **not** alert per
classical handshake. On a runtime without the group every handshake is classical,
and per-session alerts would be constant noise that trains operators to ignore
the list. It alerts on the service becoming unreachable, and on coverage
regressing after hybrid has actually been verified to work.

**Fail-mode** — `MODES["tls"]` exists but is advisory: `enforceable: false`,
with a note explaining why.

---

## 10. Tests

`quanseq/tests/`, run with `.venv/bin/pytest tests/`.

| File | Covers |
|---|---|
| `test_tls_transport.py` | Handshake, encrypted exchange (verified with a recording TCP relay), chain verification, hostname mismatch, untrusted CA, mTLS success and rejection, TLS 1.2 rejection, malformed input, port reuse, slow-handshake isolation, concurrency |
| `test_tls_hybrid_status.py` | Every rule in [§3](#3-hybrid-status-model), plus source-level guards |
| `test_tls_api.py` | All eight endpoints, error mapping, auth, absence of cert-generation and policy-apply routes |
| `test_tls_persistence.py` | What gets written, and that `pqc_enabled` requires evidence |
| `test_tls_redaction.py` | Payloads absent from logs and from API responses |

Two are regression tests for defects found in the upstream module
(`test_port_is_reusable_immediately_after_stop`,
`test_slow_handshake_does_not_block_other_clients`), and three are guards against
the platform overstating itself (`test_new_openssl_version_alone_does_not_claim_pqc`,
`test_tls_native_hybrid_appears_nowhere_in_the_backend`,
`test_no_source_hardcodes_a_successful_pqc_negotiation`).

`test_classical_only_client_is_accepted_documenting_no_enforcement` is a
**negative test that asserts a known weakness on purpose**. It skips with an
explicit reason on OpenSSL < 3.5.5. If enforcement is ever added, that test must
be inverted rather than deleted.

---

## 11. Known limitations

| # | Limitation | Consequence |
|---|---|---|
| 1 | Hybrid is not enforced | A classical X25519-only client connects successfully |
| 2 | `negotiated_group` is unobservable from Python | Group evidence needs the OpenSSL CLI or a capture |
| 3 | OpenSSL 3.0.13 has no `X25519MLKEM768` | On stock Ubuntu 24.04 hybrid is `unavailable` |
| 4 | Cipher suite is not enforced either | An AES-128-GCM-only client is accepted |
| 5 | Browser↔dashboard traffic is plain HTTP | The module measures the TLS service, not the dashboard |
| 6 | Development PKI, CA key on disk | Not production key management |
| 7 | No application-layer replay protection | Fine for probes, not for state-changing commands |
| 8 | Certificate signatures are classical RSA-2048 | ML-DSA (FIPS 204) migration is later work |
| 9 | `tls_sessions` grows unbounded | ~2 900 rows/day at the 30 s default; needs a retention policy for long runs |

Limitations 1, 2 and 4 share a root cause: Python's `ssl` module has no API for
TLS 1.3 group or cipher-suite selection. Fixing them requires OpenSSL `SSL_CONF`,
native bindings, or a terminating proxy with a strict policy — a different
architecture, not a patch.

---

## 12. Future work

**Making hybrid available on this machine.** `scripts/provision-openssl35.sh`
builds OpenSSL 3.5.5 into `/opt/openssl-3.5` and, with `--with-python`, a Python
linked against it. It is **optional** — nothing in the platform needs it, and the
module is designed to work correctly and report honestly on stock OpenSSL 3.0.13.
Run `--check` first; it reports state and changes nothing. Note what it gets you:
`unavailable` → `supported`, and `negotiated_verified` becomes reachable. It does
**not** give you enforcement.

**Enforcement.** The only change that would let this module claim a guarantee.
Requires one of: an OpenSSL `SSL_CONF`-based context builder, `cryptography`'s
Rust bindings, or fronting the service with a proxy configured for
`X25519MLKEM768` only. When it lands, invert the negative enforcement test and
change `hybrid.ENFORCEMENT_NOT_ENABLED` from a constant to a computed value.

**Traffic collector (the original Option A).** Tail an nginx access log with
`$ssl_curve` to observe real client traffic to servers QUANSEQ does not
instrument. `NGINX_ACCESS_LOG` is still reserved for it. That collector genuinely
does need per-minute aggregate buckets, since a busy server produces thousands of
handshakes per second.

**Retention.** Roll `tls_sessions` up per hour after 7 days, or apply a hard
window.

**Certificate migration.** Record ML-DSA signature OIDs once certificates using
them exist; `certs.py` already looks the OID up in `PQC_SIGNATURE_OIDS` rather
than assuming.

---

*See also:* [IPSEC.md](IPSEC.md) · [SSH.md](SSH.md) · [ARCHITECTURE.md](../ARCHITECTURE.md) · [SECURITY.md](../SECURITY.md) · [API.md](../API.md) · [`protocols/tls/tls13/VENDOR.md`](../../quanseq/protocols/tls/tls13/VENDOR.md)
