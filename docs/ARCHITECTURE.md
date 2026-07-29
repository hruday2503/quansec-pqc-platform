# Architecture

How QUANSEC is put together, why the boundaries sit where they do, and what
happens on every request and every collector tick.

- [1. Design principles](#1-design-principles)
- [2. Layers](#2-layers)
- [3. The protocol module contract](#3-the-protocol-module-contract)
- [4. Application lifecycle](#4-application-lifecycle)
- [5. Data flows](#5-data-flows)
- [6. Concurrency model](#6-concurrency-model)
- [7. Frontend architecture](#7-frontend-architecture)
- [8. Failure and degradation](#8-failure-and-degradation)
- [9. Extending the platform](#9-extending-the-platform)

---

## 1. Design principles

Five rules shape every file in the backend.

### 1.1 The request path never touches a daemon

An HTTP handler must not open the VICI socket, shell out to `ss`, or read
journald. All of that belongs to background collectors that write to PostgreSQL;
handlers read PostgreSQL.

*Why.* Daemon calls are slow, blocking and failure-prone. A `GET /api/ipsec/stats`
that opened a unix socket would take tens of milliseconds on a good day and hang
forever on a bad one, and it would block the event loop for every other request
in the process. Reading a table is sub-millisecond and cannot hang.

*The deliberate exceptions*, each documented at its call site:

| Endpoint | What it does | Why it is allowed |
|---|---|---|
| `POST /api/ipsec/refresh` | Runs `collect_once()` inline | Explicitly an "act now" control, not a read |
| `POST /api/{ipsec,ssh}/policies/apply` | Writes config, reloads the daemon | A write to the data plane is the entire purpose |
| `POST /api/ssh/ca/issue` | Invokes `ssh-keygen -s` | Signing is inherently a subprocess |
| `GET /api/ssh/policies/compare` | Runs `sshd -T` | Reads the *configured* KEX, ~5 ms, timeout-bounded |

### 1.2 Every protocol implements the same contract

Collector, router, policy engine, models — identical shape for IPsec, SSH and
any future protocol. This is what lets `scoring`, `alerts`, `siem` and `metrics`
serve every protocol without a single protocol-specific branch beyond a table
name.

### 1.3 PostgreSQL is the system of record; Redis is a bus

Nothing lives only in Redis. If Redis vanishes, the platform loses live push and
falls back to 5-second polling — no data is lost. This is why the WebSocket
carries only *notifications*, never authoritative state.

### 1.4 Degrade, do not crash

A missing StrongSwan, an unreadable journald, an absent Redis, a non-root
process — each of these produces a warning and a reduced-capability cycle, never
a 500 or a dead collector. The policy engines take this furthest: with no
`/etc/swanctl` present they enter **dev mode**, write the config to `/tmp` and
return `dev_mode: true`, so the platform is fully demonstrable on a laptop.

### 1.5 Detection is behavioural, not declarative

PQC status is derived from the *negotiated* proposal string reported by the
daemon, never from the config file — except as an explicitly-labelled fallback.
`vici_client._is_pqc()` normalises the proposal (strips `-` and `_`, lowercases)
and matches against a keyword set, so `ML_KEM_1024`, `mlkem1024` and `ML-KEM-1024`
all classify identically.

---

## 2. Layers

### 2.1 `core/` — infrastructure, zero protocol knowledge

| File | Responsibility |
|---|---|
| `config.py` | Loads `.env` via `python-dotenv` into a `Settings` singleton. Every value has a default, so the app boots with no `.env` at all. |
| `database.py` | Module-level `asyncpg` pool (min 2, max 10, 30 s command timeout). `get_db()` is the FastAPI dependency yielding one connection per request. |
| `auth.py` | Password hashing (`pbkdf2_sha256`), JWT encode/decode, and `get_current_user` — the dual-mode credential resolver. `require_user` / `require_admin` are the dependencies routers declare. |
| `redis_client.py` | Managed async Redis singleton with ping-on-connect and `get_redis_optional()` for graceful degradation. |

`core/` imports nothing from `protocols/`. The dependency arrow points one way,
always.

### 2.2 `protocols/` — one package per concern

Protocol packages (`ipsec/`, `ssh/`, `tls/`, `vpn/`) own a daemon. Cross-cutting
packages (`scoring/`, `alerts/`, `siem/`, `metrics/`, `failmode/`) consume what
protocol packages produce, and read only from PostgreSQL.

Auth lives at `protocols/auth_router.py` and `protocols/auth_api_keys.py` — flat
modules rather than a package, because they are two files with no collector and
no policy engine.

### 2.3 `main.py` — composition root

The only file that knows about every module. It does exactly four things:

1. Defines `lifespan` — migrations, then collector startup, then teardown.
2. Constructs the `FastAPI` app and CORS middleware.
3. Mounts every router.
4. Serves `/health` and `/`.

No business logic. Adding a protocol touches this file in exactly two places: an
import line and an `include_router` line.

---

## 3. The protocol module contract

```
protocols/<name>/
├── __init__.py
├── collector.py     async def collect_loop()        # required
├── router.py        router = APIRouter(prefix="/api/<name>")
├── policy.py        router = APIRouter(prefix="/api/<name>/policies")
└── models.py        pydantic models (optional; SSH returns plain dicts)
```

### 3.1 The collector contract

```python
async def collect_loop():
    """No arguments. Acquires its own pool. Runs forever."""
    from core.database import get_pool
    pool = await get_pool()
    while True:
        try:
            await collect_once(pool)
        except Exception as e:
            logger.error(f"collect error: {e}")     # never propagates
        await asyncio.sleep(POLL_INTERVAL)
```

Three requirements, all load-bearing:

- **No arguments.** `main.py` schedules every collector with the same one-liner.
  The SSH module keeps a `ssh_collector_task(pool)` variant for direct use and
  wraps it in a no-arg `collect_loop()` to satisfy the contract.
- **Own pool.** `get_pool()` is idempotent and returns the shared singleton, so
  "own pool" costs nothing but removes an ordering dependency on startup.
- **Never raise.** A collector that propagates an exception dies silently inside
  its task and stops collecting with no visible error. The `try/except` inside
  the loop is mandatory; `/health` reports live task names so a dead collector is
  still detectable.

### 3.2 The policy engine contract

```
GET  /api/<name>/policies          list available policies with algorithm detail
POST /api/<name>/policies/apply    write config, reload daemon  (require_admin)
GET  /api/<name>/policies/compare  classical vs PQC comparison table
```

`apply` follows a fixed five-step sequence:

1. Look up the named policy; 400 on unknown name.
2. Detect whether the real daemon is present (`os.path.isdir("/etc/swanctl")`,
   `os.path.exists(PQC_SSHD_CONFIG)`).
3. **Dev mode** — write to `/tmp/quansec/…`, log a warning, set `dev_mode: true`.
   **Production** — write the real config, validate it, reload the daemon.
4. Insert an `audit_events` row with severity `warning`.
5. Return `{status, policy, pqc_enabled, dev_mode, message}`.

Step 2 is the reason the whole platform demos on a laptop with no crypto daemons
installed while the identical code path drives a real tunnel on the lab VM.

### 3.3 The comparison contract

`GET .../policies/compare` returns rows of
`{field, classical, pqc, why_changed, standard}` plus `cnsa_deadline` and a
computed `days_remaining`. The UI renders it as a table without knowing which
protocol produced it — which is why both portals share one component.

---

## 4. Application lifecycle

### 4.1 Startup

```
uvicorn main:app
  │
  ├─ lifespan() enters
  │    ├─ get_pool()                 asyncpg pool, 2–10 connections
  │    ├─ run_migrations(pool)       sorted glob of migrations/*.sql, executed
  │    │                             in filename order; errors logged, not raised
  │    └─ asyncio.create_task(...)   five background tasks:
  │         ipsec-collector   poll VICI every IPSEC_POLL_INTERVAL (5 s)
  │         ipsec-events      VICI event subscription in a thread executor
  │         ssh-collector     poll ss + journald every 5 s
  │         alerts            evaluate rules every 10 s
  │         zt-audit          parse cert-auth log every 8 s
  │
  ├─ yield  ← application serves traffic
  │
  └─ shutdown
       ├─ task.cancel() + await for each background task
       └─ close_pool()
```

`run_migrations` executes each file inside its own `try/except`, logging failures
and continuing. That is only safe because every migration is idempotent — see
[DATA-MODEL.md](DATA-MODEL.md#migrations).

Note that `close_redis()` is **not** called on shutdown, and collectors construct
their own Redis clients rather than using `core/redis_client.py`. Connections are
reclaimed by process exit; it is a tidiness gap, not a leak across restarts.

### 4.2 Router mount order

```python
app.include_router(auth_router)        # /api/auth
app.include_router(api_keys_router)    # /api/keys
app.include_router(ipsec_router)       # /api/ipsec        ← router-level require_user
app.include_router(ws_router)          # /api/ws/live      ← no auth (see SECURITY.md)
app.include_router(policy_router)      # /api/ipsec/policies
app.include_router(attacks_router)     # /api/ipsec/attacks
app.include_router(ssh_router)         # /api/ssh
app.include_router(ssh_ca_router)      # /api/ssh/ca
app.include_router(scoring_router)     # /api/scoring
app.include_router(metrics_router)     # /metrics          ← no auth, intentional
app.include_router(siem_router)        # /api/siem
app.include_router(alerts_router)      # /api/alerts
app.include_router(failmode_router)    # /api/failmode
app.include_router(ssh_policy_router)  # /api/ssh/policies
app.include_router(zt_router)          # /api/ssh/zt
```

Two auth styles coexist. `ipsec_router` declares `dependencies=[Depends(require_user)]`
on the `APIRouter` itself, so every route inherits it. Every other router declares
the dependency per route. Both are correct; the per-route form is preferred for
new modules because it makes an unauthenticated route impossible to add by
accident.

---

## 5. Data flows

### 5.1 IPsec collection (poll)

```
every IPSEC_POLL_INTERVAL seconds
  │
  ViciClient.connect()                    AF_UNIX socket → vici.Session
  │   └─ fails → log warning, skip cycle  (StrongSwan not running)
  │
  ViciClient.list_sas()                   → list of bytes-keyed dicts
  │
  _decode()                               recursive bytes → str
  │
  normalise_sa(raw)                       for each IKE_SA:
  │     ike_proposal = f"{encr}-{keysize}-{integ}-{prf}-{dh}"
  │     for each CHILD_SA: emit "ike_name/child_name" with its own ESP proposal
  │     no CHILD_SAs → emit the IKE_SA alone
  │     pqc_enabled  = _is_pqc(ike_proposal) or _is_pqc(esp_proposal)
  │     pqc_kem      = _extract_pqc_kem(...)   → "ML-KEM-1024" | "Kyber768" | …
  │
  upsert_tunnels()                        INSERT … ON CONFLICT (name) DO UPDATE
  │                                       inside one transaction
  mark_stale_tunnels_down()               rows not seen and last_seen > 30 s ago
  │                                       → state='DOWN' + ipsec_events row
  │
  publish_summary()                       Redis PUBLISH quansec:live
```

`ENSURE_UNIQUE` runs a `DO $$ … $$` block before every upsert batch to guarantee
the `ipsec_tunnels_name_key` constraint exists. Migration 003 already declares
`name TEXT NOT NULL UNIQUE`, so this is belt-and-braces for databases created
before that migration.

### 5.2 IPsec lifecycle events (push)

The VICI event API is a blocking generator, which cannot live on the event loop.
The solution is a thread bridge:

```
event_listen_loop()                       asyncio
  │
  ├─ run_in_executor(_listen_blocking)    a worker thread
  │     session.listen(["ike-updown", "child-updown",
  │                     "ike-rekey", "child-rekey"])
  │     for each message:
  │         asyncio.run_coroutine_threadsafe(queue.put(...), loop)
  │
  └─ while True: await queue.get()        back on the event loop
        _classify_ike_event()   → ESTABLISHED | IKE_SA_INIT | DOWN
        _classify_child_event() → CHILD_UP | CHILD_DOWN
        _store_event()          → ipsec_events + Redis PUBLISH
```

`run_coroutine_threadsafe` is the only correct way to hand data from a thread to
a running loop. The listener auto-reconnects after a 5 s pause if the socket drops.

### 5.3 SSH collection

```
every 5 s
  │
  _active_sessions()      ss -tnp state established
  │                       keep rows where local or peer port ∈ {22, 2222}
  │                       tag each with which port matched
  │
  _live_kex_by_peer()     journalctl -u ssh -u sshd --since -10min
  │                       track "Connection from <ip> port <n>"
  │                       then "kex: algorithm: <name>"  → map peer → KEX
  │                       (requires sshd LogLevel VERBOSE)
  │
  _read_bytes_by_peer()   ss -tin → bytes_sent / bytes_received per peer
  │
  _read_configured_kex()  sshd -T, else parse /etc/ssh/sshd_config
  │
  resolution order:  live KEX  →  port-implied KEX  →  configured KEX  →  "unknown"
  │
  _classify(kex)          PQC_KEX / CLASSICAL_KEX lookup → (label, kem, pqc_bool)
  │                       unknown names fall back to substring match on
  │                       "mlkem" / "sntrup"
  │
  upsert into ssh_connections; anything not seen this cycle → state='CLOSED'
```

The three-tier fallback is why the module still reports meaningful policy state
on a host where journald is unreadable: it degrades from *what was negotiated* to
*what this port enforces* to *what the daemon is configured to offer*, and each
tier is strictly less authoritative than the one above it.

### 5.4 Zero Trust audit

```
every 8 s
  _fetch_log_text()       local /var/log/auth.log
  │                       or, if QUANSEC_ZT_REMOTE is set, over the PQC ssh:
  │                       /opt/openssh-pqc/bin/ssh -i KEY -o CertificateFile=CERT
  │                            -p 2222 host "sudo tail -n 400 /var/log/auth.log"
  │
  ACCEPT_RE               "Accepted|Failed publickey for <principal> from <ip>
  │                        port N ssh2: …-CERT … ID <identity> (serial N)
  │                        CA … SHA256:<fp>"
  REASON_RE               "Certificate invalid: <reason>"
  │
  standalone rejections   an expired cert never reaches the Failed line, so the
  │                       parser looks ahead, correlates the sshd-session PID to
  │                       recover the source IP, and records it separately
  │
  raw_hash = sha256(...)  UNIQUE column → ON CONFLICT DO NOTHING makes the
                          collector idempotent across overlapping log windows
```

The dedupe hash is what makes it safe to re-read the last 400 log lines every
8 seconds.

### 5.5 Read path

```
GET /api/ipsec/stats
  │
  require_user      decode JWT, or hash a qsk_live_ key and look it up
  get_db            acquire one pooled connection
  │
  single aggregate query:
      COUNT(*) FILTER (WHERE state IN ('ESTABLISHED','INSTALLED'))
      COUNT(*) FILTER (WHERE pqc_enabled)
      ROUND(pqc / NULLIF(total,0) * 100, 1)
      SUM(bytes_in), SUM(bytes_out), MAX(last_seen)
  │
  IPsecStats pydantic model → JSON
```

One query, no N+1, no ORM. `FILTER (WHERE …)` computes every counter in a single
table scan.

### 5.6 Live push

```
collector / event listener
        │  PUBLISH quansec:live {"protocol":"ipsec","kind":"lifecycle",…}
        ▼
     Redis
        │  SUBSCRIBE
        ▼
WS /api/ws/live  ──►  browser
        │
        └─ use-live-stats.ts: on kind === "lifecycle" → immediate refetch
```

The socket never carries authoritative state — only "something changed, refetch".
That keeps the client's source of truth singular (the REST API) and makes a
dropped socket a latency problem rather than a correctness problem.

---

## 6. Concurrency model

Everything runs in **one process, one event loop**.

| Work | Mechanism | Blocking? |
|---|---|---|
| HTTP + WebSocket | uvicorn / asyncio | no |
| PostgreSQL | asyncpg | no |
| Redis | `redis.asyncio` | no |
| IPsec polling | `vici` library, sync, called from async | **yes**, briefly |
| IPsec events | blocking generator in `run_in_executor` | isolated to a thread |
| `ss`, `journalctl`, `sshd -T`, `ssh-keygen` | `subprocess.run(timeout=…)` | **yes**, briefly |

The blocking calls are accepted deliberately: each is bounded by an explicit
timeout (5–15 s) and runs at most once per poll interval. Moving them to a thread
pool would add complexity for microseconds of benefit at this scale. The one call
that genuinely cannot block — the VICI event subscription, which blocks
*indefinitely* by design — is the one that was moved to an executor.

**Pool sizing.** `min_size=2, max_size=10`. Five collectors hold a connection
only for the duration of a write, so steady-state usage is 1–2 connections, and
the remaining headroom serves HTTP. Under a burst of concurrent dashboard
requests, asyncpg queues rather than erroring.

---

## 7. Frontend architecture

```
src/
├── app/
│   ├── page.tsx                    landing — protocol picker
│   ├── layout.tsx                  <AuthProvider> wraps everything
│   ├── ipsec/login/page.tsx        portal-scoped login
│   ├── ssh/login/page.tsx
│   ├── portal/
│   │   ├── layout.tsx              auth guard + IPsec sidebar
│   │   └── {page,tunnels,policy,attacks,readiness,alerts,integrations,keys,docs}
│   └── ssh-portal/
│       ├── layout.tsx              auth guard + SSH sidebar
│       └── {page,sessions,policy,zero-trust,certificates,readiness,alerts,…}
├── lib/
│   ├── api.ts                      QuansecClient — typed methods, token handling
│   ├── auth-context.tsx            React context: user, loading, login, logout
│   └── use-live-stats.ts           polling + WebSocket hook
└── components/
    ├── sidebar.tsx
    └── ui-primitives.tsx
```

**Auth guard in the layout, not the page.** Each portal's `layout.tsx` checks
`useAuth()`, renders `AUTHENTICATING…` while `loading`, and redirects to the
module's login when there is no user. Every page under that layout inherits the
guard — a new page cannot forget it.

**One client, one token.** `QuansecClient` holds the JWT in memory and mirrors it
to `localStorage` so a refresh survives. Every request goes through one private
`request<T>()` that attaches `Authorization: Bearer` and throws on non-2xx.

**Portal scoping.** Login posts to `/api/auth/login-scoped?portal=ipsec|ssh`. The
backend rejects a user whose `users.portal` matches neither the requested portal
nor `main`, and admins bypass the check. This is how one deployment serves
separate IPsec and SSH customer tenants from one user table.

**The live-data hook.** `useLiveStats(intervalMs = 5000)` fetches stats and
tunnels in parallel, repeats on an interval, and opens the WebSocket. Fetch
errors are swallowed — the UI keeps showing the last good data rather than
flashing an error on a transient blip. On a `lifecycle` message it refetches
immediately, so a rekey appears without waiting for the next tick.

---

## 8. Failure and degradation

| Failure | Behaviour | Visible where |
|---|---|---|
| StrongSwan down / VICI missing | Warning per cycle, cycle skipped, existing rows age out to `DOWN` after 30 s | Backend log; tunnels go DOWN in UI |
| journald unreadable | SSH KEX falls back to port-implied, then to configured | `kex_algorithm` reflects policy, not negotiation |
| Redis down | Collectors log and continue; no `quansec:live` publishes | WebSocket badge disconnects; UI polls at 5 s |
| PostgreSQL down | Collectors error and retry; `/health` returns `degraded` | `/health`; API 500s |
| A collector task dies | Task disappears from `/health.collectors` | `/health` |
| Backend unreachable | `useLiveStats` swallows the error | Stale data, no crash |
| No `/etc/swanctl` | Policy engine enters dev mode, writes `/tmp/quansec/swanctl/swanctl.conf` | `dev_mode: true` in the response |
| No PQC sshd | Same, writes `/tmp/quansec/sshd/sshd_config` | `dev_mode: true` |
| Non-root backend | `PermissionError` → HTTP 500 with a remediation message | Policy apply fails loudly |

---

## 9. Extending the platform

Adding a protocol — say WireGuard — end to end:

**1. Create the package.**

```
protocols/wireguard/
├── __init__.py
├── collector.py    collect_once(pool) + no-arg collect_loop()
├── router.py       APIRouter(prefix="/api/wireguard")
├── policy.py       APIRouter(prefix="/api/wireguard/policies")
└── models.py
```

**2. Add a migration** — `migrations/007_wireguard.sql`, idempotent
(`CREATE TABLE IF NOT EXISTS`, `INSERT … ON CONFLICT DO NOTHING`).

**3. Wire `main.py`** — one import line, one `include_router`, one
`create_task(wg_collect_loop(), name="wireguard-collector")`.

**4. Extend the cross-cutting modules** — add a `score_wireguard()` in
`scoring/router.py` following `score_ssh()`, a rule block in
`alerts/evaluate_once()`, and a metrics block in `metrics/router.py`. Each is
roughly ten lines because the shape is fixed.

**5. Frontend** — copy `app/ssh-portal/` to `app/wireguard-portal/`, change the
nav array and endpoint paths. The layout, guard, sidebar and primitives are
reused unchanged.

Nothing in `core/`, and nothing in any existing protocol package, needs to
change. That is the property the contract exists to guarantee.

---

*See also:* [SETUP.md](SETUP.md) · [API.md](API.md) · [DATA-MODEL.md](DATA-MODEL.md) · [TECHNOLOGY-CHOICES.md](TECHNOLOGY-CHOICES.md)
