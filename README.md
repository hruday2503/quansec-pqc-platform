<div align="center">

# QUANSEQ

**Post-Quantum Cryptography Management Platform**

Real-time discovery, enforcement, scoring and audit of post-quantum key exchange
across IPsec, SSH and TLS.

`FastAPI` · `PostgreSQL` · `Redis` · `Next.js 16` · `StrongSwan + ML-KEM` · `OpenSSH PQC`

</div>

---

## Table of contents

1. [What QUANSEQ is](#1-what-quanseq-is)
2. [The problem it solves](#2-the-problem-it-solves)
3. [System architecture](#3-system-architecture)
4. [Repository layout](#4-repository-layout)
5. [Module catalogue](#5-module-catalogue)
6. [Quick start](#6-quick-start)
7. [Technology choices — and why](#7-technology-choices--and-why)
8. [Protocol modules](#8-protocol-modules)
9. [Full documentation index](#9-full-documentation-index)
10. [Current status and known gaps](#10-current-status-and-known-gaps)

---

## 1. What QUANSEQ is

QUANSEQ is a control plane for post-quantum cryptography (PQC) migration.

It does four things, continuously, against **live** cryptographic daemons — not
against a simulation:

| Capability | What it means concretely |
|---|---|
| **Observe** | Background collectors poll StrongSwan (via the VICI socket) and sshd (via `ss` + journald) every few seconds and record the *actually negotiated* key exchange for every tunnel and session. |
| **Enforce** | Policy engines rewrite `swanctl.conf` / `sshd_config` and reload the daemon, switching a live deployment between classical and post-quantum key exchange on demand. |
| **Score** | A weighted readiness model turns live state into a 0–100 PQC readiness score and an A–F grade per protocol. |
| **Prove** | An attack lab runs real cryptographic attacks (Pollard's rho factoring, downgrade, harvest-now-decrypt-later) against the current configuration and shows classical crypto breaking while ML-KEM holds. |

Everything is exposed through a REST + WebSocket API, a Prometheus `/metrics`
endpoint, a SIEM export (CEF / syslog / JSON), and two Next.js operator portals.

**Version:** 2.0.0 · **Protocols live:** IPsec, SSH, TLS · **Planned:** VPN

---

## 2. The problem it solves

A cryptographically relevant quantum computer breaks every key exchange in
production use today. Shor's algorithm solves the discrete logarithm and integer
factorisation problems in polynomial time, which retires ECDH, DH and RSA
simultaneously.

Two consequences drive this project:

**Harvest now, decrypt later.** An adversary recording ECDH-protected traffic
today can decrypt it the day a quantum computer arrives. Data with a long
confidentiality lifetime — banking records, health data, state secrets — is
*already* compromised if it crosses a classical tunnel. Migration deadlines are
not about future traffic; they are about traffic in flight right now.

**Mandated deadlines.** NSA CNSA 2.0 requires post-quantum key establishment for
SSH and TLS by **2030** and for IPsec/IKEv2 by **2033**. NIST finalised
**FIPS 203 (ML-KEM)** on 13 August 2024, so the standard exists and the clock is
running.

The hard part of migration is not choosing an algorithm — it is *knowing what
your estate actually negotiates*. A config file that lists `mlkem1024` proves
nothing; the peer may have downgraded, the plugin may not have loaded, a
fallback proposal may have won. QUANSEQ closes that gap by reading negotiated
state out of the running daemons and alerting the moment a session goes
classical.

---

## 3. System architecture

QUANSEQ is a three-tier system with a strict rule: **the API never talks to a
cryptographic daemon during a request.** Collectors own that boundary.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  PRESENTATION                        Next.js 16 · React 19 · Tailwind 4   │
│                                                                           │
│   /                landing — protocol picker                              │
│   /ipsec/login  → /portal/*        IPsec operator portal                  │
│   /ssh/login    → /ssh-portal/*    SSH operator portal                    │
│   /tls/login    → /tls-portal/*    TLS operator portal                    │
│                                                                           │
│   5 s REST polling  +  WebSocket push on lifecycle events                 │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │  HTTPS / WS · Bearer JWT or qsk_live_ key
┌───────────────────────────────▼───────────────────────────────────────────┐
│  APPLICATION                                    FastAPI · uvicorn · Py3.12│
│                                                                           │
│  ┌─── core/ ────────────────┐  ┌─── protocols/ ───────────────────────┐   │
│  │ config   env settings    │  │ ipsec/    collector, events, policy, │   │
│  │ database asyncpg pool    │  │           attacks, websocket, router │   │
│  │ auth     JWT + API keys  │  │ ssh/      collector, policy, ca,     │   │
│  │ redis_client  pub/sub    │  │           ztaudit, router            │   │
│  └──────────────────────────┘  │ tls/      transport service, adapter,│   │
│                                │           hybrid probe, collector    │   │
│                                │ scoring/  readiness model            │   │
│  ┌─── background tasks ─────┐  │ alerts/   rule engine                │   │
│  │ ipsec-collector    5 s   │  │ siem/     CEF · syslog · JSON        │   │
│  │ ipsec-events    (push)   │  │ metrics/  Prometheus /metrics        │   │
│  │ ssh-collector      5 s   │  │ failmode/ fail-closed / fail-open    │   │
│  │ tls-collector     30 s   │  │ auth_*    login, RBAC, API keys      │   │
│  │ alerts            10 s   │  └──────────────────────────────────────┘   │
│  │ zt-audit           8 s   │                                             │
│  └──────────────────────────┘                                             │
└───────────┬───────────────────────────────────────────┬───────────────────┘
            │                                           │
   ┌────────▼─────────┐  ┌──────────────┐    ┌──────────▼──────────────────┐
   │  PostgreSQL 14+  │  │  Redis 6+    │    │  DATA PLANE (the real thing)│
   │  system of record│  │  pub/sub bus │    │                             │
   │  tunnels·sessions│  │ quanseq:live │    │  StrongSwan charon          │
   │  events·audit·ZT │  └──────────────┘    │   └ ml-kem plugin (liboqs)  │
   │  users·API keys  │                      │   └ VICI unix socket        │
   └──────────────────┘                      │                             │
                                             │  OpenSSH PQC :2222          │
                                             │   └ mlkem768x25519-sha256   │
                                             │   └ CA-signed certs only    │
                                             │                             │
                                             │  QUANSEQ TLS service :8443  │
                                             │   └ separate process        │
                                             │   └ TLS 1.3 only, mTLS      │
                                             │   └ hybrid NOT enforced     │
                                             └─────────────────────────────┘
```

### The one data flow that matters

```
StrongSwan charon
   │  VICI list-sas / event subscription
   ▼
ViciClient.list_sas()          protocols/ipsec/vici_client.py
   │  raw bytes-keyed dicts
   ▼
normalise_sa()                 flattens IKE_SA + CHILD_SAs, classifies PQC
   │  clean Python dicts
   ▼
upsert_tunnels()               protocols/ipsec/collector.py → PostgreSQL
   │
   ├─► PostgreSQL  ──► REST GET /api/ipsec/tunnels ──► portal table
   └─► Redis PUBLISH quanseq:live ──► WS /api/ws/live ──► portal live badge
```

The SSH path is identical in shape (`ss` + journald → `ssh_connections` → REST +
alerts), which is the whole point of the modular design: **every protocol
implements the same contract**, so the API surface, the scoring model, the alert
rules and the UI patterns are reused verbatim.

TLS follows the same contract with one difference in where the telemetry comes
from: instead of reading a daemon's state, the collector performs a real TLS 1.3
handshake against QUANSEQ's own TLS service and records what the socket
reported.

Full detail: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**

Phase 1 container deployment: **[docs/CONTAINERS.md](docs/CONTAINERS.md)**

---

## 4. Repository layout

```
quanseq-pqc-platform/
├── README.md                  ← you are here
├── docs/                      ← full documentation set
│   ├── ARCHITECTURE.md            layering, module contract, data flows
│   ├── SETUP.md                   end-to-end build, two-VM lab, verification
│   ├── TECHNOLOGY-CHOICES.md      every dependency, and why it was chosen
│   ├── API.md                     complete endpoint reference
│   ├── DATA-MODEL.md              schema, indexes, lifecycle of every table
│   ├── SECURITY.md                auth model, threat model, hardening
│   ├── OPERATIONS.md              running, monitoring, troubleshooting
│   └── protocols/
│       ├── IPSEC.md               IPsec module, deep
│       ├── SSH.md                 SSH module, deep
│       └── TLS.md                 TLS module, deep
│
├── quanseq/                   ← backend (FastAPI). Run uvicorn from HERE.
│   ├── main.py                    app factory, lifespan, router mounting
│   ├── core/                      config · database · auth · redis_client
│   ├── protocols/                 one package per protocol + cross-cutting
│   ├── migrations/                001…007 SQL, applied on startup
│   ├── strongswan/                swanctl.conf templates
│   ├── strongswan-configs/        ml-kem.conf · liboqs.conf · private-algs.conf
│   ├── compiled-backup/           ML-KEM StrongSwan plugin source + build
│   ├── two-vm-configs/            VM A peer config
│   ├── setup_backend.sh           one-shot Postgres + Redis + venv + migrate
│   ├── provision_postgres.sh      DB role/database provisioning only
│   ├── setup_phase1.sh            StrongSwan + system dependency install
│   └── launch_ns_tunnel.sh        single-host netns tunnel lab
│
├── quanseq-ui/                ← frontend (Next.js 16 App Router)
│   └── src/
│       ├── app/portal/*           IPsec portal pages
│       ├── app/ssh-portal/*       SSH portal pages
│       ├── app/tls-portal/*       TLS portal pages
│       ├── lib/api.ts             typed API client + token handling
│       └── components/            sidebar, UI primitives
│
└── vm-b/                      ← peer VM configuration (IPsec responder + PQC sshd)
```

---

## 5. Module catalogue

Every module is self-contained: its own router, its own tables, its own
collector where applicable. Adding a protocol means adding a package — no
existing module changes.

| Module | Path | Responsibility | Background task |
|---|---|---|---|
| **IPsec** | `protocols/ipsec/` | VICI polling, SA normalisation, lifecycle events, swanctl policy, attack lab | `ipsec-collector` (5 s), `ipsec-events` (push) |
| **SSH** | `protocols/ssh/` | Session discovery, KEX classification, sshd policy, certificate authority, Zero Trust audit | `ssh-collector` (5 s), `zt-audit` (8 s) |
| **TLS** | `protocols/tls/` | Real TLS 1.3 transport service, handshake observation, certificate inventory, evidence-based hybrid status | `tls-collector` (30 s) |
| **Scoring** | `protocols/scoring/` | Weighted 0–100 readiness score, A–F grade, per protocol and overall | — |
| **Alerts** | `protocols/alerts/` | Rule evaluation against live state, deduplicated firings, acknowledgement | `alerts` (10 s) |
| **SIEM** | `protocols/siem/` | Export in CEF, RFC 5424 syslog, and JSON | — |
| **Metrics** | `protocols/metrics/` | Prometheus text exposition at `/metrics` | — |
| **Fail-mode** | `protocols/failmode/` | fail-closed (reject non-PQC) vs fail-open (classical fallback) | — |
| **Auth** | `protocols/auth_router.py`, `auth_api_keys.py` | JWT login, portal scoping, RBAC, `qsk_live_` API keys | — |

### The protocol module contract

Any new protocol package implements the same five pieces:

```python
protocols/<name>/
    collector.py   async def collect_loop()      # no-arg, gets its own pool
    router.py      router = APIRouter(prefix="/api/<name>")
    policy.py      router  # GET "" list, POST /apply, GET /compare
    models.py      pydantic response models
    __init__.py
```

`collect_loop()` takes no arguments and acquires its own pool so `main.py` can
schedule every collector identically:

```python
task = asyncio.create_task(<name>_collect_loop(), name="<name>-collector")
```

That single convention is what makes the platform genuinely modular rather than
merely folder-organised.

---

## 6. Quick start

> Ubuntu 22.04 / 24.04. Full instructions, including building StrongSwan with the
> ML-KEM plugin and OpenSSH with PQC key exchange, are in
> **[docs/SETUP.md](docs/SETUP.md)**.

### Backend

```bash
cd quanseq

# Provisions PostgreSQL + Redis, creates .venv, installs deps,
# writes .env, runs migrations, seeds the admin user.
chmod +x setup_backend.sh
./setup_backend.sh

source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

`main.py` imports as `core.*` and `protocols.*`, so **uvicorn must be started
from inside `quanseq/`**. Running it from the repository root fails on import.

Verify:

```bash
curl -s localhost:8000/health | python3 -m json.tool
# {"status":"ok","database":"connected",
#  "collectors":["ipsec-collector","ipsec-events","alerts","zt-audit","ssh-collector"]}
```

Interactive API docs: <http://localhost:8000/docs>

### Frontend

```bash
cd quanseq-ui
npm install
echo "NEXT_PUBLIC_QUANSEQ_API=http://localhost:8000" > .env.local
npm run dev
```

Open <http://localhost:3000> and pick a protocol module. Default credentials are
printed by `setup_backend.sh` (`admin@quanseq.io`); change them before any
non-lab use.

### Data plane (optional, but this is the point of the platform)

Without StrongSwan and the PQC sshd, collectors log a warning each cycle and the
dashboard shows zeros — the API still runs. To see real data you need at least
one of:

- **IPsec:** StrongSwan built with the `ml-kem` plugin, `swanctl.conf` loaded,
  VICI socket readable. See [docs/protocols/IPSEC.md](docs/protocols/IPSEC.md).
- **SSH:** OpenSSH built with `mlkem768x25519-sha256`, running on port 2222 with
  `LogLevel VERBOSE`. See [docs/protocols/SSH.md](docs/protocols/SSH.md).

---

## 7. Technology choices — and why

Short version below; the full reasoning, including what was rejected and why,
is in **[docs/TECHNOLOGY-CHOICES.md](docs/TECHNOLOGY-CHOICES.md)**.

| Choice | Why this and not the alternative |
|---|---|
| **FastAPI** | Collectors are long-lived `asyncio` tasks living in the same process as the API. FastAPI's `lifespan` context manager owns their start/stop as a first-class concept. Django/Flask would need Celery or a separate supervisor for the same result. Pydantic response models also generate the OpenAPI schema the portal's typed client is written against. |
| **asyncpg (not an ORM)** | The write path is a single `INSERT … ON CONFLICT DO UPDATE` executed every 5 s per tunnel, and the read path is aggregate SQL (`COUNT(*) FILTER (WHERE pqc_enabled)`). An ORM adds object mapping to queries that never manipulate objects. asyncpg is also the fastest Python driver and is natively async, so a collector never blocks the event loop. |
| **PostgreSQL** | Needs `JSONB` for heterogeneous lifecycle event payloads, `TEXT[]` for cert principals and KEX allow-lists, partial indexes, `TIMESTAMPTZ`, and real `ON CONFLICT` upsert semantics. SQLite has none of the first four and would serialise writes against five concurrent collectors. |
| **Redis** | Used strictly as a pub/sub bus on channel `quanseq:live`, not as a cache of record. It decouples collectors (publishers) from WebSocket clients (subscribers) and lets the API scale to multiple uvicorn workers without collectors needing to know about sockets. If Redis is down, collectors degrade to DB-only and the UI falls back to 5 s polling. |
| **StrongSwan + custom `ml-kem` plugin** | StrongSwan is the only production IKEv2 daemon with a VICI control socket that exposes *negotiated* SA parameters — the single fact the whole platform is built on. Upstream ML-KEM support was not available for the target release, so `compiled-backup/ml_kem_source/` implements a plugin registering ML-KEM-768 and ML-KEM-1024 as IKE key-exchange methods `1050`/`1051` backed by **liboqs**. |
| **Pure ML-KEM for IPsec, hybrid for SSH** | Deliberate, not inconsistent. IPsec uses pure `mlkem1024` (NIST Level 5) to demonstrate a CNSA 2.0 end-state and prove the plugin negotiates standalone. SSH uses hybrid `mlkem768x25519-sha256` because that is what OpenSSH ships and what the IETF hybrid drafts specify — if either half breaks, the other still protects the session. |
| **OpenSSH on port 2222** | The PQC build lives at `/opt/openssh-pqc` on a non-standard port so the system sshd on :22 keeps working. That also gives a live A/B: port 22 is the classical control, port 2222 the PQC treatment, and the collector maps port → expected KEX. |
| **Next.js 16 App Router** | Portals are behind authentication, so SSR/SEO is irrelevant — what matters is nested layouts. `/portal/layout.tsx` and `/ssh-portal/layout.tsx` each own an auth guard plus a module-specific sidebar, so every page under them inherits the guard for free. |
| **Polling + WebSocket together** | REST polling every 5 s guarantees eventual correctness even if the socket drops. The WebSocket only carries *lifecycle* events, which triggers an immediate refetch. The UI is never wrong for more than 5 s, and rekeys appear instantly. |
| **JWT for humans, `qsk_live_` keys for machines** | Different lifetimes and revocation stories. JWTs are 24 h and stateless; API keys never expire, are stored only as SHA-256 hashes, and are revocable by row. `get_current_user` dispatches on the `qsk_live_` prefix, so both arrive in the same `Authorization: Bearer` header. |
| **Prometheus + CEF export** | Enterprises do not adopt a new dashboard; they ingest into what they already run. `/metrics` in text exposition format works with any Prometheus/Grafana/OpenTelemetry stack, and CEF is the ArcSight/Splunk/QRadar lingua franca. |

---

## 8. Protocol modules

| | IPsec | SSH | TLS |
|---|---|---|---|
| **Status** | Live | Live | Live — transport real, hybrid **not enforced** |
| **Daemon** | StrongSwan `charon` | OpenSSH PQC `/opt/openssh-pqc` :2222 | QUANSEQ TLS service :8443 (separate process) |
| **KEM** | ML-KEM-1024 (pure) | ML-KEM-768 + X25519 (hybrid) | X25519MLKEM768 requested, not enforced |
| **NIST level** | Level 5 (FIPS 203) | Level 3 (FIPS 203) | Level 3 (where the runtime provides it) |
| **CNSA 2.0 deadline** | 2033 | 2030 | 2030 |
| **Telemetry source** | VICI unix socket (poll + event subscription) | `ss -tnp` + journald `kex: algorithm:` lines | Real TLS 1.3 handshakes performed by the backend |
| **Policy target** | `/etc/swanctl/swanctl.conf` + `swanctl --load-all` | `/opt/openssh-pqc/etc/sshd_config` + daemon restart | *None* — Python `ssl` cannot select TLS 1.3 groups |
| **Extras** | Attack lab, lifecycle event stream | Certificate authority, Zero Trust audit | Certificate inventory, out-of-band group verification |
| **Deep doc** | [docs/protocols/IPSEC.md](docs/protocols/IPSEC.md) | [docs/protocols/SSH.md](docs/protocols/SSH.md) | [docs/protocols/TLS.md](docs/protocols/TLS.md) |

**On TLS — read this before quoting a coverage figure.** The transport is real:
TLS 1.3 is enforced, certificate chains and hostnames are verified, mutual TLS
works, and every recorded value is read off a live socket. Post-quantum key
exchange is a separate question, and the module is built so it cannot be
overstated:

- **Hybrid is not enforced.** A client offering only classical X25519 completes a
  handshake against the service. Python's `ssl` module exposes no TLS 1.3
  group-selection API, so this is not fixable in Python — it needs OpenSSL
  `SSL_CONF`, native bindings, or a terminating proxy with a strict policy.
- **The negotiated group is not observable from Python.** It is reported as
  `null` alongside a `negotiated_group_source` explaining why. Establishing it
  requires `openssl s_client` or a packet capture, and that evidence is stored
  with a timestamp.
- **On stock Ubuntu 24.04 hybrid is unavailable outright** — OpenSSL 3.0.13 has
  no `X25519MLKEM768`. The portal reports `unavailable` rather than implying
  otherwise, and a test asserts that a newer OpenSSL version *on its own* never
  promotes the status.

`tls_sessions.pqc_enabled` is written `TRUE` only when verified evidence covers
that exact endpoint and group, so the seeded grade-F `tls` row in `pqc_scores` is
now backed by a measurement — one that currently scores low, accurately.

The TLS service runs as its **own process**; the backend never starts it:

```bash
bash scripts/run_tls_service.sh          # terminal 1 — TLS service on :8443
uvicorn main:app --port 8000             # terminal 2 — backend, a TLS client
```

---

## 9. Full documentation index

| Document | Read it when you want to |
|---|---|
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Understand layering, the module contract, collector lifecycle, and every data flow end to end |
| **[SETUP.md](docs/SETUP.md)** | Build the whole thing from a bare Ubuntu box, including liboqs, the StrongSwan ML-KEM plugin, OpenSSH PQC, and the two-VM lab |
| **[TECHNOLOGY-CHOICES.md](docs/TECHNOLOGY-CHOICES.md)** | Know why each dependency was picked, what was rejected, and what the trade-offs cost |
| **[API.md](docs/API.md)** | Call the API — every endpoint, auth requirement, request and response shape |
| **[DATA-MODEL.md](docs/DATA-MODEL.md)** | Understand the schema, which table each writer owns, and the migration model |
| **[SECURITY.md](docs/SECURITY.md)** | Review the auth model, RBAC, secret handling, threat model, and hardening checklist |
| **[OPERATIONS.md](docs/OPERATIONS.md)** | Run it — health checks, Prometheus, SIEM, alert tuning, and a troubleshooting matrix |
| **[protocols/IPSEC.md](docs/protocols/IPSEC.md)** | Work on IPsec — VICI, SA normalisation, the ML-KEM plugin, policy switching, attack lab |
| **[protocols/SSH.md](docs/protocols/SSH.md)** | Work on SSH — KEX detection, the certificate authority, Zero Trust audit, policy rollback |
| **[protocols/TLS.md](docs/protocols/TLS.md)** | Work on TLS — the transport service, the hybrid status model, and exactly which post-quantum claims the platform may make |
| **[protocols/TLS.md](docs/protocols/TLS.md)** | Build the TLS module against the existing contract |

---

## 10. Current status and known gaps

Stated plainly, because a production-level document that hides these is not
useful.

**Working end to end**

- IPsec collection, lifecycle events, policy switching, attack lab, WebSocket push
- SSH collection, KEX classification, policy switching with rollback, certificate issuance, Zero Trust audit
- JWT + API key auth, RBAC, portal scoping, audit trail
- Readiness scoring, alerting, Prometheus export, SIEM export in three formats
- Both operator portals

**Gaps and rough edges**

| Area | Detail |
|---|---|
| **TLS hybrid enforcement** | The TLS transport is real, but hybrid key exchange is **not enforced** and the negotiated group is not observable from Python. On stock Ubuntu 24.04 (OpenSSL 3.0.13) the hybrid group does not exist at all. Reported honestly per-state; see [docs/protocols/TLS.md](docs/protocols/TLS.md) §11. |
| **TLS retention** | `tls_sessions` grows unbounded — roughly 2 900 rows/day at the default 30 s poll. Needs a retention or rollup policy before a long-running deployment. |
| **VPN module** | Not implemented. `protocols/vpn/` is an empty package; config keys (`WG_INTERFACE`) exist but nothing reads them. |
| **SIEM audit source** | `protocols/siem/router.py` selects `audit_events.created_at`, but migration 001 defines that column as `occurred_at`. The query is wrapped in `try/except` and logs at DEBUG, so SIEM exports currently return Zero Trust events only and silently omit audit events. |
| **Duplicate table definitions** | Several modules `CREATE TABLE IF NOT EXISTS` at runtime with schemas that differ from the migrations: runtime `zt_audit` vs migration `zt_ssh_audit`; runtime `alerts` vs migration `alert_rules`/`alert_firings`. The runtime tables are the ones actually used. See [DATA-MODEL.md](docs/DATA-MODEL.md#runtime-created-tables). |
| **Migration versioning** | `run_migrations()` re-executes every `.sql` file on each startup and swallows errors. It works because every statement is `IF NOT EXISTS` / `ON CONFLICT DO NOTHING`, but there is no applied-migrations ledger and no rollback. |
| **Fail-mode persistence** | Current mode lives in the in-memory `_CURRENT` dict in `protocols/failmode/router.py` and resets to `fail-closed` on restart. The `fail_mode_policies` table exists but is not read. |
| **Redis client duplication** | `core/redis_client.py` provides a managed singleton with graceful degradation, but the IPsec collector, event listener and WebSocket endpoint each construct their own `aioredis` client. `close_redis()` is never called on shutdown. |
| **`/metrics` is unauthenticated** | Intentional — Prometheus scrapers do not carry bearer tokens — but it must be restricted at the network layer. See [SECURITY.md](docs/SECURITY.md). |
| **Policy engines need privilege** | Writing `/etc/swanctl/swanctl.conf` and restarting sshd requires root or scoped `sudoers` rules. Without them both engines fall back to **dev mode**, writing to `/tmp/quanseq/` and returning `dev_mode: true` instead of failing. |

---

<div align="center">
<sub>Samsung PRISM Research · NIST FIPS 203 · NSA CNSA 2.0</sub>
</div>
