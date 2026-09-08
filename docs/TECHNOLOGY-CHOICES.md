# Technology choices

Every significant dependency, why it was chosen, what was rejected, and what the
choice costs.

- [1. Cryptography](#1-cryptography)
- [2. Backend framework](#2-backend-framework)
- [3. Data layer](#3-data-layer)
- [4. Real-time transport](#4-real-time-transport)
- [5. Telemetry sources](#5-telemetry-sources)
- [6. Authentication](#6-authentication)
- [7. Frontend](#7-frontend)
- [8. Integration surfaces](#8-integration-surfaces)
- [9. Rejected alternatives](#9-rejected-alternatives)
- [10. Accepted debt](#10-accepted-debt)

---

## 1. Cryptography

### 1.1 ML-KEM (FIPS 203) as the KEM

**Chosen because it is the standard.** NIST finalised ML-KEM as FIPS 203 on
13 August 2024, after a six-year, three-round public competition. NSA CNSA 2.0
names it for national security systems. Every major TLS, SSH and IKEv2
implementation has converged on it. Choosing anything else in 2025 means
choosing something that will have to be migrated again.

**Why lattices survive Shor.** Shor's algorithm efficiently solves the *hidden
subgroup problem over abelian groups*, which is what integer factorisation and
discrete logarithm reduce to. ML-KEM's security rests on **Module Learning With
Errors** — recovering a secret from noisy linear equations over a polynomial
ring. That is not a hidden subgroup problem, and no quantum algorithm is known
that beats classical lattice reduction by more than a polynomial factor.

Grover's algorithm gives a quadratic speedup on unstructured search, which halves
the effective security of symmetric primitives. This is why AES-256 and SHA-384
are kept throughout while only the key exchange changes: AES-256 retains 128 bits
against Grover, which is fine. **The key exchange is the only part that is
actually broken.**

**Parameter selection:**

| Parameter set | NIST level | Classical equivalent | Used for |
|---|---|---|---|
| ML-KEM-512 | 1 | AES-128 | not used |
| ML-KEM-768 | 3 | AES-192 | **SSH** — OpenSSH's hybrid default |
| ML-KEM-1024 | 5 | AES-256 | **IPsec** — CNSA 2.0 target |

ML-KEM-768 is the industry consensus for interactive transport: it is what
OpenSSH, Chrome and Cloudflare ship, its public key is 1184 bytes, and it is
strictly stronger than the 128-bit classical baseline it replaces. ML-KEM-1024 is
CNSA 2.0's requirement for national security systems; its 1568-byte public key
costs an extra packet on IKE_SA_INIT, which is irrelevant for a long-lived
site-to-site tunnel.

### 1.2 Pure ML-KEM for IPsec, hybrid for SSH

This asymmetry is deliberate and is the most-questioned design decision in the
project.

**IPsec: `aes256-sha256-mlkem1024` — pure.**

- It demonstrates a CNSA 2.0 *end state*, not a transition step.
- It proves the ML-KEM plugin negotiates standalone rather than riding along
  behind an ECDH exchange that might be doing the real work.
- Site-to-site IPsec is a controlled two-endpoint deployment. Both peers run the
  same build, so there is no interoperability population to protect.
- Fail-closed is trivially achievable: a single proposal with no classical
  option cannot be downgraded, because there is nothing to downgrade to.

**SSH: `mlkem768x25519-sha256` — hybrid.**

- It is what OpenSSH ships. Deviating would mean patching OpenSSH.
- The IETF hybrid key-exchange drafts specify combining a classical and a PQC
  share precisely because ML-KEM is young. If a lattice break appears, X25519
  still protects the session; if X25519 falls to Shor, ML-KEM still protects it.
  The session key derives from both.
- SSH clients are heterogeneous — a hybrid that includes a familiar classical
  half is what makes deployment realistic.

The honest summary: **hybrid is the correct production default, pure is the
correct demonstration of the destination.** The platform runs both so it can
argue either case with live evidence.

### 1.3 liboqs as the ML-KEM implementation

The Open Quantum Safe project's liboqs is the reference C implementation for
NIST PQC candidates and finalists, is actively maintained, exposes one uniform
`OQS_KEM` API across every algorithm, and is what the OQS forks of OpenSSL,
OpenSSH and StrongSwan already use.

The alternative — writing an ML-KEM implementation — would mean hand-rolling
NTT-based polynomial arithmetic, constant-time rejection sampling, and Fujisaki–
Okamoto transform hardening. Every one of those is a well-known side-channel
footgun. Using the reference implementation is the only defensible choice.

The custom code in `compiled-backup/ml_kem_source/` is deliberately thin: it is
an *adapter*, translating StrongSwan's `key_exchange_t` interface into liboqs
calls. All cryptography lives in liboqs.

### 1.4 StrongSwan as the IKEv2 daemon

**The deciding factor is VICI.** StrongSwan's Versatile IKE Configuration
Interface is a unix-socket protocol that exposes the *negotiated* parameters of
every live SA — `encr-alg`, `integ-alg`, `prf-alg`, `dh-group`, byte counters,
established time — plus a push event subscription for `ike-updown`,
`child-updown`, `ike-rekey` and `child-rekey`.

That single capability is what makes the entire platform possible. Everything
else — the collector, the PQC classification, the scoring model, the alert
rules — is downstream of "the daemon will tell you what it actually negotiated".

Alternatives and why they lost:

| Daemon | Problem |
|---|---|
| **Libreswan** | Control interface is `ipsec status` text output. Screen-scraping a human-readable format is fragile, and there is no event push. |
| **Linux kernel XFRM directly** | The kernel holds the *installed* SA (ESP keys, SPIs) but not the IKE negotiation detail. It cannot tell you which key exchange method was used. |
| **strongSwan's legacy `ipsec` CLI** | Deprecated in favour of `swanctl`/VICI, and text-parsing again. |

StrongSwan is also plugin-based, which is what allowed ML-KEM to be added
without forking the daemon.

### 1.5 OpenSSH with a separate PQC build

OpenSSH 9.9+ implements `mlkem768x25519-sha256` natively — no patching. The
build is installed to `/opt/openssh-pqc` on port 2222 rather than replacing the
system sshd, for three reasons:

1. **Safety.** A misconfigured PQC sshd cannot lock you out of a remote machine.
2. **Measurement.** Port 22 (classical) and port 2222 (PQC) run simultaneously,
   giving a live A/B. The collector's `SSH_PORT_KEX` map encodes exactly this.
3. **Blast radius.** Zero Trust enforcement — certificate-only, passwords
   disabled — applies to the PQC daemon without changing system-wide policy.

---

## 2. Backend framework

### FastAPI

**Chosen for lifespan, async, and generated schema — in that order.**

**Lifespan owns the collectors.** QUANSEQ's defining characteristic is five
long-lived background tasks that must start with the app and stop cleanly with
it. FastAPI's `@asynccontextmanager lifespan` makes that a first-class concept:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = await get_pool()
    await run_migrations(pool)
    _background_tasks.append(asyncio.create_task(ipsec_collect_loop(), name="ipsec-collector"))
    yield
    for task in _background_tasks:
        task.cancel()
    await close_pool()
```

In Flask or Django this would require Celery, APScheduler or a separate
supervised process — a second deployment unit, a second failure mode, and a
message broker, all to run a loop that sleeps for five seconds.

**Native async throughout.** Collectors, database access and the Redis
subscription are all `async`. A synchronous framework would need a thread per
collector and a thread pool for the database.

**WebSocket support is built in.** `@router.websocket("/api/ws/live")` is a
decorator, not an add-on library.

**OpenAPI comes free.** Pydantic response models generate `/docs` and the schema
the frontend's typed client mirrors. `IPsecStats` in `models.py` and
`IPsecStats` in `api.ts` are the same contract in two languages.

The cost: FastAPI's dependency-injection system is easy to misuse (a slow
dependency blocks the loop), and there is no built-in admin, ORM or migration
tooling — all of which had to be hand-rolled or omitted.

### uvicorn

The reference ASGI server, `uvloop`-backed. `--reload` for development.
**Single worker in production** — see [OPERATIONS.md](OPERATIONS.md#scaling) for
why, and what to do about it.

---

## 3. Data layer

### 3.1 PostgreSQL

Four features are load-bearing:

| Feature | Where it is used |
|---|---|
| `JSONB` | `ipsec_events.detail`, `siem_events.detail`, `pqc_scores.detail` — event payloads differ per event type, and JSONB is queryable, not an opaque blob |
| `TEXT[]` | `api_keys.scopes`, `ssh_policies.allowed_kex`, `ssh_cert_audit.principals` — native arrays with `= ANY($1::text[])` semantics used directly by the SSH collector |
| `INSERT … ON CONFLICT DO UPDATE` | The core collector write. Every 5 s, per tunnel, "insert or update" must be one atomic statement |
| `COUNT(*) FILTER (WHERE …)` | The entire stats endpoint is one query with five filtered aggregates over one scan |

Plus `TIMESTAMPTZ` — every timestamp in the system is timezone-aware, because
correlating a tunnel event with an SSH log line across hosts requires absolute
time.

**Rejected: SQLite.** No `JSONB`, no arrays, no `FILTER`, and a single-writer
lock that five concurrent collectors would serialise against.

**Rejected: MongoDB.** The data is relational — tunnels have events, users have
API keys, certificates have audit rows — and the read path is aggregate SQL.
Denormalising it would trade a join for consistency problems.

**Rejected: InfluxDB/TimescaleDB.** Genuinely tempting for `protocol_metrics`,
which is a time series. But most of the schema is *current state* (one row per
tunnel, upserted) rather than an append-only series, and adding a second database
for one table is not worth the operational cost at this scale. If retention of
`protocol_metrics` becomes a problem, TimescaleDB is a PostgreSQL extension and
can be added without migrating anything else.

### 3.2 asyncpg, not an ORM

**The write path** is one prepared statement executed in a loop:

```sql
INSERT INTO ipsec_tunnels (...) VALUES ($1, ..., $16)
ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state, ...
```

**The read path** is aggregate SQL that returns numbers, not objects.

Neither path ever constructs a domain object, mutates it, and persists it — the
scenario ORMs exist for. SQLAlchemy would add a session lifecycle, identity map,
lazy-loading footguns and `ON CONFLICT` construct gymnastics for zero benefit.

asyncpg additionally:

- is the fastest PostgreSQL driver for Python (it implements the binary wire
  protocol directly rather than wrapping libpq);
- is natively async, so a collector write never blocks the event loop;
- has built-in pooling with `min_size`/`max_size`;
- uses `$1` positional parameters, which are always server-side prepared —
  **SQL injection is structurally impossible on any parameterised query.**

The cost: raw SQL strings, no compile-time schema checking, and the two places
where the codebase builds SQL by string interpolation (`list_tunnels` and
`list_events` build `WHERE` clauses and a `LIMIT` placeholder index). Both
interpolate only integers and generated `$n` placeholders — never user data —
but they are the spots to watch. See [SECURITY.md](SECURITY.md#sql).

`psycopg2-binary` is also in `requirements.txt` for synchronous scripting paths;
the application itself uses asyncpg exclusively.

### 3.3 The migration approach

`main.py` globs `migrations/*.sql`, sorts by filename, and executes each file on
every startup, logging failures rather than raising.

**Why not Alembic.** Alembic's value is autogenerating diffs from ORM models.
With no ORM there is nothing to diff, and Alembic's version table would add a
dependency to solve a problem six hand-written files do not have.

**What it costs.** No applied-migrations ledger, no rollback, no ordering
guarantee beyond filename sort, and errors are swallowed. It only works because
every statement is idempotent — `CREATE TABLE IF NOT EXISTS`,
`CREATE INDEX IF NOT EXISTS`, `INSERT … ON CONFLICT DO NOTHING`. **That
idempotency is a hard requirement on every future migration.** A migration
containing `ALTER TABLE … ADD COLUMN` without a guard will error on the second
startup, and the error will be logged at ERROR and then ignored.

This is acceptable for a research platform and is the first thing to replace
before production. See [DATA-MODEL.md](DATA-MODEL.md#migrations).

---

## 4. Real-time transport

### 4.1 Redis as a pub/sub bus

Redis carries exactly one thing: messages on channel `quanseq:live`.

```
collector / event listener  ──PUBLISH──►  Redis  ──SUBSCRIBE──►  WS endpoint  ──►  browser
```

**Why a broker at all.** Without one, a collector would need direct references to
every connected WebSocket — coupling a background task to HTTP connection state,
and making multi-worker deployment impossible. Pub/sub inverts that: publishers
know nothing about subscribers.

**Why Redis and not RabbitMQ/Kafka.** The message is fire-and-forget: if no
dashboard is open, nobody needs it; if one connects a second later, the next tick
covers it. Durability, ordering guarantees and consumer groups are all
unnecessary. Redis pub/sub is the smallest thing that works, and Redis is a
single apt package with no broker configuration.

**Why not a cache.** Redis holds no authoritative state. `core/redis_client.py`
documents intended cache keys (`quanseq:ipsec:snapshot` and friends), but the
collectors do not currently write them — everything goes to PostgreSQL. This is
deliberate: a cache introduces an invalidation problem, and the read path is
already sub-millisecond.

**Degradation:** if Redis is unreachable, collectors log and continue, the
WebSocket badge goes grey, and the UI's 5-second polling covers everything. No
data is lost.

### 4.2 WebSocket *and* polling, not one or the other

| Mechanism | Carries | Guarantees |
|---|---|---|
| REST poll, 5 s | Full stats + tunnel list | Eventual correctness regardless of socket state |
| WebSocket | Lifecycle notifications only | Sub-second latency on rekeys and state changes |

The socket never carries authoritative state — only "something changed". The
client's reaction is to refetch over REST. Consequences:

- A dropped socket is a *latency* problem, never a *correctness* problem.
- There is one source of truth (the REST API), so the two paths cannot disagree.
- The UI is never stale by more than 5 seconds, and an IKE rekey shows up
  immediately.

Server-Sent Events would have worked equally well for the notification channel
and are simpler; WebSocket was chosen to keep a bidirectional channel available
for future client→server controls.

---

## 5. Telemetry sources

### 5.1 IPsec — VICI, two ways

**Polling** (`list_sas` every 5 s) gives a complete picture including byte and
packet counters, which only exist as a snapshot. It also self-heals: a missed
event is corrected within one cycle.

**Event subscription** gives sub-second lifecycle notification. It cannot replace
polling because events carry no counters and a missed event would leave state
wrong indefinitely.

The subscription is a blocking generator, so it runs in a thread and hands
messages back via `asyncio.run_coroutine_threadsafe`. Running it on the event
loop would freeze the entire application.

Together: polling for correctness, events for latency.

### 5.2 SSH — three sources, ranked

There is no VICI for sshd. Detection composes three sources in strict priority
order:

| Priority | Source | What it proves | Fails when |
|---|---|---|---|
| 1 | `journalctl` → `kex: algorithm: <name>` | What was **actually negotiated** | `LogLevel DEBUG1` not set, journald unreadable, entry rotated out |
| 2 | Port → KEX map (`2222 → mlkem768x25519`) | What this listener **enforces** | Only valid for known ports |
| 3 | `sshd -T` → `KexAlgorithms` | What the daemon **offers** | Never fails, but is the weakest claim |

Each tier is strictly less authoritative than the one above. The module degrades
rather than going blind, and the response always says which KEX it settled on, so
the claim is inspectable.

`ss -tnp state established` provides session discovery and `ss -tin` provides
byte counters. Both are read-only, cheap, and require no privilege beyond
process visibility.

**Rejected: an sshd PAM module or patch.** It would give authoritative
per-session data, but requires patching OpenSSH, running privileged code in the
authentication path, and would break on every OpenSSH upgrade. Log parsing is
observation, not interception.

### 5.3 Zero Trust — auth log parsing with deduplication

The ZT collector re-reads the last 400 auth-log lines every 8 seconds, so it sees
the same lines repeatedly. Idempotency comes from a content hash:

```python
raw_hash = sha256(f"{ts}{identity}{serial}{ip}{result}{reason}").hexdigest()
# INSERT ... ON CONFLICT (raw_hash) DO NOTHING
```

This is why overlapping read windows are safe, and why the collector can be
restarted without producing duplicate audit rows.

The parser also handles a real edge case: an **expired certificate never reaches
the `Failed publickey` line**. sshd logs `error: Certificate invalid: expired`
standalone. The parser detects that, looks ahead, and correlates the
`sshd-session[PID]` to recover the source IP from a nearby line — otherwise every
expired-cert rejection would be recorded as coming from `unknown`.

---

## 6. Authentication

### 6.1 Two credential types, one header

| | JWT | API key |
|---|---|---|
| For | Humans in the dashboard | Servers and CI |
| Lifetime | 24 h (`JWT_EXPIRE_HOURS`) | Until revoked |
| Storage | Stateless — signed claims | SHA-256 hash in `api_keys` |
| Revocation | Wait for expiry | `revoked_at = NOW()`, immediate |
| Format | `eyJ…` | `qsk_live_<43 url-safe chars>` |

Both arrive as `Authorization: Bearer <credential>`. `get_current_user`
dispatches on the prefix:

```python
if token.startswith("qsk_live_"):
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    # SELECT … FROM api_keys JOIN users … WHERE key_hash = $1 AND revoked_at IS NULL
    # UPDATE api_keys SET last_used = NOW() …
else:
    payload = decode_token(token)   # JWT path
```

One dependency, one header, two credential models. Every router below it is
unaware of which was used.

**Why JWT for sessions.** Stateless verification means no session store and no
database round-trip to validate a token — the signature is the proof. The cost is
that a compromised token is valid until expiry, which is why the lifetime is
capped at 24 h.

**Why hash API keys.** The raw key is shown exactly once, at creation. Only
`sha256(key)` is stored. A database dump therefore yields no usable credentials.
`key_prefix` (`qsk_live_abcd…wxyz`) is stored separately purely so the UI can
show a recognisable label.

Both are unsalted SHA-256 — correct here, unlike for passwords, because the key
is 256 bits of `secrets.token_urlsafe(32)` entropy. There is no dictionary to
attack and no rainbow table to build. Salting would only break the ability to
look the key up by hash.

### 6.2 `pbkdf2_sha256` for passwords

Passwords use passlib's `pbkdf2_sha256`, not bcrypt or argon2.

PBKDF2-SHA256 is FIPS 140-approved, which matters for a platform whose entire
premise is NIST standards compliance — recommending FIPS 203 while hashing
passwords with a non-approved KDF would be inconsistent. It is also pure Python
in passlib with no native compilation, so it never breaks on a Python upgrade the
way bcrypt bindings do.

Argon2id is the stronger choice against GPU attack and would be the right call if
FIPS alignment were not a goal. `passlib`'s `CryptContext` is configured with
`deprecated="auto"`, so migrating means adding a scheme to the list — existing
hashes are re-hashed transparently on next login.

### 6.3 RBAC and portal scoping

Two roles, deliberately:

- **`operator`** — reads everything, runs attack simulations, acknowledges alerts.
- **`admin`** — everything above, plus applies policies, issues certificates,
  creates users, and sets fail-mode.

The dividing line is *does this change the security posture of a live system*.
Anything that rewrites a daemon config or mints a credential is admin-only.

**Portal scoping** adds a tenancy dimension via `users.portal`. Login through
`/api/auth/login-scoped?portal=ssh` rejects a user whose `portal` is neither
`ssh` nor `main`; admins bypass the check. This lets one deployment serve
separate IPsec and SSH customer groups from one user table without a full
multi-tenancy model.

---

## 7. Frontend

### Next.js 16 App Router

The portals are entirely behind authentication, so SSR and SEO are irrelevant —
every meaningful page is `"use client"`. **The App Router was chosen for nested
layouts.**

```
app/portal/layout.tsx       auth guard + IPsec sidebar
app/portal/tunnels/page.tsx inherits both, unconditionally
```

Each portal's layout owns the guard, so a newly added page under it cannot forget
to check authentication. In the Pages Router this would be an HOC that every page
must remember to apply.

**React 19** for `use`, improved Suspense and the stable concurrent renderer.
**TypeScript** end to end — `api.ts` declares the response shape of every
endpoint, so a backend field rename becomes a compile error rather than a runtime
`undefined`.

**Tailwind CSS v4 plus CSS custom properties.** Layout uses utility classes;
colour uses CSS variables (`--pqc-cyan`, `--lattice-violet`, `--bg-void`) applied
via inline `style`. This keeps the security-domain palette themeable from one
place while retaining Tailwind's layout ergonomics.

**Recharts** for charts — declarative React components over D3, which is the
right level of abstraction for dashboard time series. **lucide-react** for icons:
tree-shakeable SVG components, no icon font.

**No state management library.** Server state lives in `useLiveStats`; auth state
lives in one React context. Redux/Zustand would add a store for two pieces of
state.

---

## 8. Integration surfaces

The design assumption is that **nobody adopts a new dashboard**. Enterprises have
a monitoring stack and a SIEM already, so QUANSEQ exports into both rather than
asking to replace them.

### Prometheus text exposition at `/metrics`

Plain text, `# HELP` / `# TYPE` / value. Consumed unmodified by Prometheus,
Grafana Agent, OpenTelemetry Collector, VictoriaMetrics and Datadog's OpenMetrics
integration. No client library dependency — the format is a dozen lines of string
building.

Unauthenticated by design, because scrapers do not carry bearer tokens. It
exposes counts and coverage percentages, never identities or keys, and must be
restricted at the network layer.

### CEF, syslog and JSON for SIEM

**CEF** (`CEF:0|QUANSEQ|PQC-Platform|1.0|…`) is the ArcSight format that Splunk
and QRadar also parse — the closest thing to a lingua franca for security events.
**RFC 5424 syslog** covers everything with a syslog receiver. **JSON** covers
Elastic and anything modern.

Three formats from one `_gather_events()` call, selected by a query parameter.
The alternative — an HTTP forwarder per SIEM vendor — would mean maintaining
credentials, retries and vendor-specific schemas for each. Pull-based export
keeps the platform stateless with respect to its consumers.

---

## 9. Rejected alternatives

| Rejected | In favour of | Reason |
|---|---|---|
| Django / Flask | FastAPI | No first-class lifespan for background tasks; sync by default |
| SQLAlchemy | raw asyncpg | No object graph to map; adds a session lifecycle to a stats query |
| Alembic | idempotent SQL files | Its value is ORM diffing; there is no ORM |
| SQLite | PostgreSQL | No JSONB, arrays or `FILTER`; single-writer lock vs 5 collectors |
| MongoDB | PostgreSQL | Data is relational; reads are aggregates |
| InfluxDB / Timescale | PostgreSQL | Most tables are current-state, not series; not worth a second datastore yet |
| Celery / APScheduler | asyncio tasks in lifespan | A broker and a second deployment unit to run `await sleep(5)` |
| RabbitMQ / Kafka | Redis pub/sub | Fire-and-forget notifications need no durability or ordering |
| Libreswan | StrongSwan | No structured control interface, no event push |
| Kernel XFRM only | StrongSwan VICI | The kernel holds the installed SA, not the negotiation detail |
| Patching sshd | Log parsing | Privileged code in the auth path; breaks on every upgrade |
| Custom ML-KEM | liboqs | Constant-time lattice arithmetic is not something to hand-roll |
| bcrypt / argon2 | pbkdf2_sha256 | FIPS 140 approval, consistent with the platform's compliance story |
| Redux / Zustand | React context + one hook | Two pieces of state |
| Server-Sent Events | WebSocket | Equivalent today; WS keeps a bidirectional channel open for future controls |

---

## 10. Accepted debt

Choices made knowingly, with the cost stated.

| Debt | Why it was accepted | What it costs | Trigger to fix |
|---|---|---|---|
| Single uvicorn worker | Collectors are in-process and would duplicate under multiple workers | No horizontal scaling of the API | Sustained request load, or an HA requirement |
| No migration ledger | Six idempotent files do not need one | No rollback; a non-idempotent migration fails silently on rerun | The first `ALTER TABLE` |
| Blocking `subprocess` in collectors | Bounded by explicit timeouts, once per poll | A hung `journalctl` stalls the loop for its timeout | Poll intervals below 1 s |
| Runtime `CREATE TABLE IF NOT EXISTS` in several modules | Made modules independently deployable during development | Two definitions of the same concept (`zt_audit` vs `zt_ssh_audit`, `alerts` vs `alert_firings`) | Now — see [DATA-MODEL.md](DATA-MODEL.md#runtime-created-tables) |
| Fail-mode state in memory | Simplest working version | Resets to `fail-closed` on restart; the `fail_mode_policies` table is unused | Any real deployment |
| Duplicate Redis clients | Predates `core/redis_client.py` | Extra connections; `close_redis()` never called | Connection-count pressure |
| `/metrics` unauthenticated | Scrapers cannot carry tokens | Requires network-layer protection | Exposure outside a trusted network |
| Attack simulations are illustrative | Real Pollard's rho on a 64-bit key is genuine; the Shor and harvest results are reasoned narratives, not executed quantum attacks | Must not be read as measurement | Never — but the docs must keep saying so |

---

*See also:* [ARCHITECTURE.md](ARCHITECTURE.md) · [SECURITY.md](SECURITY.md) · [DATA-MODEL.md](DATA-MODEL.md)
