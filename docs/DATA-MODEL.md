# Data model

Schema reference: what each table holds, who writes it, and where the migrations
and the runtime disagree.

- [1. Overview](#1-overview)
- [2. Migrations](#2-migrations)
- [3. Identity and audit](#3-identity-and-audit)
- [4. IPsec tables](#4-ipsec-tables)
- [5. SSH tables](#5-ssh-tables)
- [6. Cross-cutting tables](#6-cross-cutting-tables)
- [7. Runtime-created tables](#7-runtime-created-tables)
- [8. Indexing strategy](#8-indexing-strategy)
- [9. Growth and retention](#9-growth-and-retention)

---

## 1. Overview

PostgreSQL is the system of record. Redis holds nothing authoritative.

```
IDENTITY                     users · api_keys · audit_events
   │
IPSEC          ipsec_tunnels (current state)  ·  ipsec_events (history)
   │
SSH            ssh_connections (current state)
               zt_audit ⁽ʳ⁾ · issued_certs ⁽ʳ⁾ · ssh_policy_history ⁽ʳ⁾
   │
CROSS-CUTTING  alerts ⁽ʳ⁾ · siem_events · protocol_metrics · pqc_scores
               fail_mode_policies · ipsec_policies · ssh_policies
               alert_rules · alert_firings

⁽ʳ⁾ created at runtime by module code, not by a migration — see §7
```

**Current-state tables** (`ipsec_tunnels`, `ssh_connections`) are upserted on a
natural key and hold one row per live object. **History tables**
(`ipsec_events`, `zt_audit`, `audit_events`) are append-only.

---

## 2. Migrations

`migrations/*.sql`, applied by `main.py:run_migrations()` on every startup:

```python
sql_files = sorted(migrations_dir.glob("*.sql"))
for sql_file in sql_files:
    try:
        await conn.execute(sql_file.read_text())
    except Exception as e:
        logger.error(f"Migration {sql_file.name} error: {e}")   # logged, not raised
```

| File | Creates |
|---|---|
| `001_users.sql` | `users`, `audit_events` |
| `002_api_keys.sql` | `api_keys` |
| `003_ipsec.sql` | `ipsec_tunnels`, `ipsec_events` |
| `004_ssh.sql` | `ssh_connections`, `ssh_cert_audit`, `zt_ssh_audit` |
| `005_siem_alerts_policies.sql` | `siem_events`, `alert_rules`, `alert_firings`, `fail_mode_policies`, `ipsec_policies`, `ssh_policies` |
| `006_metrics_scoring.sql` | `protocol_metrics`, `pqc_scores` |

### Idempotency is a hard requirement

Every file re-executes on every startup. This works only because every statement
is guarded:

```sql
CREATE TABLE  IF NOT EXISTS …
CREATE INDEX  IF NOT EXISTS …
INSERT INTO … ON CONFLICT (…) DO NOTHING
```

**Any future migration must be idempotent.** A bare
`ALTER TABLE … ADD COLUMN` will succeed once and error on every subsequent
startup — and because errors are logged rather than raised, that failure will be
invisible unless someone reads the log. Guard it:

```sql
ALTER TABLE ipsec_tunnels ADD COLUMN IF NOT EXISTS new_field TEXT;
```

### What this approach lacks

No applied-migrations ledger, no rollback, no ordering beyond filename sort, and
swallowed errors. Acceptable for a research platform; the first thing to replace
before production. See
[TECHNOLOGY-CHOICES.md §3.3](TECHNOLOGY-CHOICES.md#33-the-migration-approach).

`setup_backend.sh` also applies the same files via `psql` before first start, so
migrations run twice on a fresh install — harmless, by the same idempotency.

---

## 3. Identity and audit

### `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `SERIAL PK` | |
| `email` | `TEXT UNIQUE NOT NULL` | The login identifier |
| `password_hash` | `TEXT NOT NULL` | passlib `pbkdf2_sha256` |
| `role` | `TEXT` | `CHECK IN ('admin','operator')`, default `operator` |
| `portal` | `TEXT` | Default `main`. Tenancy scope — `main` sees everything |
| `created_at` | `TIMESTAMPTZ` | |

`portal` drives `/api/auth/login-scoped`: a user whose portal is neither the
requested portal nor `main` is rejected with 403. Admins bypass.

### `api_keys`

| Column | Type | Notes |
|---|---|---|
| `user_id` | `INTEGER REFERENCES users(id) ON DELETE CASCADE` | Migration 002 cascades; the runtime `CREATE TABLE` in `auth_api_keys.py` omits the cascade |
| `key_prefix` | `TEXT` | `qsk_live_abcd…wxyz` — display only |
| `key_hash` | `TEXT UNIQUE` | **`sha256(full_key)`. The raw key is never stored.** |
| `scopes` | `TEXT[]` | Default `{read}`. Stored and returned but **not enforced** |
| `last_used` | `TIMESTAMPTZ` | Updated on every authenticated request |
| `revoked_at` | `TIMESTAMPTZ` | `NULL` = active. Revocation is immediate |

Unsalted SHA-256 is correct here: the key is 256 bits of
`secrets.token_urlsafe(32)` entropy, so there is no dictionary to attack, and
lookup-by-hash requires a deterministic digest.

### `audit_events`

| Column | Type | Notes |
|---|---|---|
| `user_id` | `INTEGER REFERENCES users(id) ON DELETE SET NULL` | `NULL` for system actions |
| `action` | `TEXT` | `login`, `policy_apply`, `ssh_policy_apply`, `attack_simulation`, `cert_issued`, `api_key_created`, `api_key_revoked`, `failmode_set`, `create_user` |
| `resource` | `TEXT` | `auth`, `ipsec`, `ssh`, `ssh-ca` |
| `detail` | `TEXT` | JSON **as a string**, not JSONB |
| `severity` | `TEXT` | `CHECK IN ('info','warning','critical')` |
| `occurred_at` | `TIMESTAMPTZ` | |

Two things to know:

- **`detail` is `TEXT`, not `JSONB`** — writers build JSON with f-strings
  (`f'{{"policy":"{name}"}}'`). It is not queryable as JSON, and a value
  containing a quote would produce malformed JSON. All current values are
  controlled identifiers, so it holds, but it is fragile.
- **The column is `occurred_at`.** `protocols/siem/router.py` selects
  `created_at`, which does not exist. The query is wrapped in `try/except` and
  logged at DEBUG, so SIEM exports silently omit audit events. One-word fix.

---

## 4. IPsec tables

### `ipsec_tunnels` — current state

Written by `protocols/ipsec/collector.py` every 5 s.

| Column | Type | Notes |
|---|---|---|
| `name` | `TEXT NOT NULL UNIQUE` | **Upsert conflict target.** `"ike_name/child_name"` when children exist |
| `local_host` / `remote_host` | `TEXT` | Endpoint IPs |
| `local_id` / `remote_id` | `TEXT` | IKE identities (`vm-a`, `vm-b`) |
| `state` | `TEXT` | `ESTABLISHED`, `INSTALLED`, `CONNECTING`, `DOWN` |
| `ike_version` | `INTEGER` | 2 — PQC requires IKEv2 |
| `ike_proposal` | `TEXT` | `encr-keysize-integ-prf-dh` as reported by VICI |
| `esp_proposal` | `TEXT` | CHILD_SA proposal, `NULL` for a bare IKE_SA |
| `pqc_kem` | `TEXT` | Normalised label: `ML-KEM-1024` |
| `pqc_enabled` | `BOOLEAN` | `_is_pqc(ike) or _is_pqc(esp)` |
| `bytes_in/out`, `packets_in/out` | `BIGINT` | From the CHILD_SA; 0 for a bare IKE_SA |
| `established_at` | `TIMESTAMPTZ` | `NOW() - established_seconds`, `COALESCE`d on update so it survives a poll that cannot compute it |
| `last_seen` | `TIMESTAMPTZ` | `NOW()` every poll — drives stale detection |
| `created_at` | `TIMESTAMPTZ` | First sighting. Never updated |

`INSERT … ON CONFLICT (name) DO UPDATE` is the whole write path. `created_at` is
deliberately excluded from the update set.

### `ipsec_events` — append-only history

| Column | Type | Notes |
|---|---|---|
| `tunnel_name` | `TEXT` | Not a FK — events outlive tunnels |
| `event_type` | `TEXT` | `ESTABLISHED`, `IKE_SA_INIT`, `CHILD_UP`, `CHILD_DOWN`, `DOWN` |
| `detail` | `JSONB` | Shape varies by event type |
| `occurred_at` | `TIMESTAMPTZ` | |

Two writers: the event listener (real-time, from VICI) and the collector
(synthetic `DOWN` on stale detection).

`detail` is genuine `JSONB` here — inserted via `json.dumps()` — unlike
`audit_events.detail`.

---

## 5. SSH tables

### `ssh_connections`

Written by `protocols/ssh/collector.py` every 5 s.

| Column | Type | Notes |
|---|---|---|
| `session_key` | `TEXT UNIQUE` | **Conflict target.** `"<local>-><peer>"` |
| `remote_user` | `TEXT` | **Always `NULL`** — `ss` cannot see the SSH username |
| `kex_algorithm` | `TEXT` | Negotiated, port-implied or configured (see [SSH.md §4](protocols/SSH.md#4-session-and-kex-detection)) |
| `kem_label` | `TEXT` | `ML-KEM-768`, `X25519`, `sntrup761` |
| `pqc_enabled` | `BOOLEAN` | From the classification table |
| `state` | `TEXT` | `CHECK IN ('ACTIVE','CLOSED')` |
| `bytes_sent` / `bytes_received` | `BIGINT` | From `ss -tin` |

Closure is immediate rather than grace-period based: `ss` reads established TCP
connections straight from the kernel, so absence is authoritative.

```sql
UPDATE ssh_connections SET state='CLOSED'
WHERE session_key <> ALL($1::text[]) AND state='ACTIVE'
```

The array comparison keeps this one parameterised statement regardless of session
count.

### `ssh_cert_audit` and `zt_ssh_audit` — defined but unused

Migration 004 creates both. Neither is written to. The live equivalents are the
runtime-created `issued_certs` and `zt_audit` (§7). See the divergence note below.

---

## 6. Cross-cutting tables

### `siem_events`

Created by migration 005 with `JSONB` detail and severity checks. Currently
**unused** — `protocols/siem/router.py` gathers from `audit_events` and `zt_audit`
at request time rather than maintaining its own event store. Reserved for a
future push-based export.

### `protocol_metrics`

`(protocol, metric_name, value, unit, captured_at)` — a time series.
Currently **unused**: `/metrics` computes everything live from the state tables
rather than reading history. Populating it is what would enable trend charts.

### `pqc_scores`

Seeded with one row per protocol (`ipsec`, `ssh`, `tls`, `vpn`) at score 0.0,
grade F, risk `critical`. The scoring API computes live and does **not** write
back, so these rows remain at their seeded values. **This is why `tls` and `vpn`
show grade F** — a placeholder, not a measurement.

### `fail_mode_policies`

Seeded with sensible defaults (IPsec/SSH/TLS `fail-secure`, VPN `fail-open`).
**Not read.** `protocols/failmode/router.py` keeps state in an in-memory
`_CURRENT` dict that resets on restart. Wiring the endpoint to this table is a
small, worthwhile change.

### `ipsec_policies` / `ssh_policies`

Intended for database-driven policy definitions. **Not read** — both policy
engines hold their policies as Python dicts (`POLICIES`, `SSH_POLICIES`).
Migration 005 seeds a `default-pqc` SSH policy that nothing consumes.

### `alert_rules` / `alert_firings`

Migration 005's alerting schema. **Not used** — `protocols/alerts/router.py`
creates its own simpler `alerts` table at runtime and holds rules as a Python
list.

---

## 7. Runtime-created tables

Four tables are created by `CREATE TABLE IF NOT EXISTS` inside module code rather
than by a migration.

| Table | Created by | Migration equivalent | Status |
|---|---|---|---|
| `zt_audit` | `protocols/ssh/ztaudit.py` | `zt_ssh_audit` (004) — **different schema** | Runtime one is live |
| `issued_certs` | `protocols/ssh/ca.py` | `ssh_cert_audit` (004) — **different schema** | Runtime one is live |
| `ssh_policy_history` | `protocols/ssh/policy.py` | none | Runtime only |
| `alerts` | `protocols/alerts/router.py` | `alert_rules`/`alert_firings` (005) — **different schema** | Runtime one is live |

### Why this happened

Modules were developed to be independently deployable — dropping in
`ztaudit.py` and having it work without also remembering to apply a migration.
The migrations were written separately and drifted.

### Why it matters

- Two schemas describe the same concept, and the wrong one looks authoritative.
- `setup_backend.sh` creates the migration tables; the app then creates the
  runtime tables. A fresh database ends up with both, and the migration ones stay
  empty forever.
- A reader inspecting the schema sees `zt_ssh_audit` with `trust_score` and
  `risk_flags` columns and reasonably concludes those features exist. They do not.

### The fix

Promote the runtime definitions into `migrations/007_consolidate.sql`, drop the
`CREATE TABLE` calls from module code, and either migrate or drop the unused
migration tables. Until then, **the runtime tables are the real ones.**

### `zt_audit` — live schema

| Column | Type | Notes |
|---|---|---|
| `event_time` | `TIMESTAMPTZ` | Parsed from the log line, falling back to now |
| `identity` | `TEXT` | Certificate Key ID, or `invalid-certificate` for a standalone rejection |
| `cert_serial` | `TEXT` | |
| `ca_fingerprint` | `TEXT` | `SHA256:…` |
| `source_ip` | `TEXT` | `unknown` when PID correlation fails |
| `principal` | `TEXT` | The Unix login |
| `result` | `TEXT` | `accepted` \| `rejected` |
| `reason` | `TEXT` | `ok`, `expired`, `revoked`, `denied` |
| `raw_hash` | `TEXT UNIQUE` | **Dedupe key** — `ON CONFLICT DO NOTHING` makes re-reads idempotent |

### `issued_certs`

`serial`, `identity`, `principals`, `valid_hours`, `issued_by`, `issued_at`,
`expires_at`, `revoked`.

`serial` has **no unique constraint** and is allocated as `MAX(serial)+1` in a
separate statement from the insert — concurrent issuance can collide. Use a
sequence.

`expires_at` is `NOW() + valid_hours` and ignores the certificate's 1-hour
validity backdate, so it reads up to an hour later than the real `valid_before`.
Cosmetic in the audit view; do not treat it as authoritative.

### `alerts`

`rule`, `severity`, `protocol`, `message`, `fingerprint UNIQUE`, `acked`,
`raised_at`. The `fingerprint` is what stops a persistent condition from raising
a row every 10 seconds.

---

## 8. Indexing strategy

Every index exists because a query uses it.

| Table | Index | Serves |
|---|---|---|
| `users` | `email` | Login lookup |
| `api_keys` | `key_hash` | Every API-key authenticated request |
| `api_keys` | `user_id` | `GET /api/keys` |
| `ipsec_tunnels` | `state` | `?state=` filter |
| `ipsec_tunnels` | `pqc_enabled` | `?pqc=` filter, scoring, alerts |
| `ipsec_tunnels` | `last_seen DESC` | Default ordering, stale detection |
| `ipsec_events` | `tunnel_name`, `event_type`, `occurred_at DESC` | The three event filters |
| `ssh_connections` | `state`, `pqc_enabled`, `last_seen DESC` | Same pattern |
| `zt_audit` | `raw_hash` (UNIQUE) | Dedupe on every insert |
| `alerts` | `fingerprint` (UNIQUE) | Dedupe on every raise |

`DESC` on every timestamp index matters — all timestamp queries are
"most recent first", and a `DESC` index serves them without a sort step.

The unique constraints on `name`, `session_key`, `key_hash`, `raw_hash` and
`fingerprint` are not just integrity guards; each is the conflict target that
makes its writer idempotent. **They are load-bearing.**

---

## 9. Growth and retention

| Table | Growth | Bounded? |
|---|---|---|
| `ipsec_tunnels` | One row per tunnel, upserted | ✅ |
| `ssh_connections` | One row per TCP session, forever | ❌ |
| `ipsec_events` | One row per lifecycle transition | ❌ |
| `zt_audit` | One row per certificate auth | ❌ |
| `audit_events` | One row per privileged action | ❌ |
| `alerts` | Deduplicated by fingerprint | ✅ in practice |

**No retention policy exists for anything.**

The two that will grow fastest:

- **`ipsec_events`** — a tunnel rekeying every hour produces ~24 events a day per
  tunnel. Modest, until you have hundreds of tunnels.
- **`ssh_connections`** — every SSH session ever seen keeps a `CLOSED` row.
  A CI system opening connections in a loop will fill this table.

Suggested retention, once the platform runs continuously:

```sql
-- keep 90 days of history
DELETE FROM ipsec_events WHERE occurred_at < NOW() - INTERVAL '90 days';
DELETE FROM zt_audit     WHERE event_time  < NOW() - INTERVAL '90 days';
DELETE FROM audit_events WHERE occurred_at < NOW() - INTERVAL '90 days';

-- keep 30 days of closed sessions
DELETE FROM ssh_connections
 WHERE state = 'CLOSED' AND last_seen < NOW() - INTERVAL '30 days';
```

Run from cron or a `pg_cron` job. Note that `audit_events` is a compliance record
— check retention requirements before deleting from it.

---

*See also:* [ARCHITECTURE.md](ARCHITECTURE.md) · [API.md](API.md) · [protocols/IPSEC.md](protocols/IPSEC.md) · [protocols/SSH.md](protocols/SSH.md)
