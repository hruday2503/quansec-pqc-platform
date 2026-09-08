# TLS Portal — build checkpoint

Resume point for the TLS portal work. Written because the build spans more
context than one session holds. **Do not re-run a broad workspace inspection**
— the canonical paths below are verified from running processes.

Last commit: `258331f`. Work after it is **uncommitted** (instructed not to commit).

## Canonical paths (verified, do not re-derive)

| | Path |
|---|---|
| Backend | `quanseq/` — `uvicorn main:app` on `:8000`, `--reload` |
| Frontend | `quanseq-ui/` (top level) — `next dev` on `:3000` |
| PQC runtime | `~/.quanseq/pqc-tls/` — OpenSSL 3.5.7, NGINX 1.27.5 |
| Dev PKI | `~/quanseq-certs/` — ca/server/client `.crt` + `.key` |
| Ignore | `quanseq-pqc-platform/` and `TLS-SMOAD-HSC/` — separate repos, gitignored |

Listeners: `:8443` strict-hybrid (probes/evidence, `/dataplane/` only),
`:8444` portal (proxies `/`→Next.js, `/api/`→FastAPI, classical fallback
permitted, logged separately, never probed).

Admin: `admin@quanseq.io` / `Admin@QuanSeq2024!` (from `quanseq/.env`).
API keys authenticate via `Authorization: Bearer qsk_live_…`, **not** `X-API-Key`.

## Completed and verified

**Migrations** — `010_tls_portal.sql` applied, idempotent. Added
`tls_policy_history`, `tls_alerts`, `ws_tickets`; extended `tls_sessions`
(`connection_id`, `hybrid_negotiated`, `mtls_enabled`,
`client_certificate_verified`, `certificate_signature_algorithm`,
`started_at`, `last_seen`, `request_count`, `evidence_source`) and `api_keys`
(`revoked_by`, `revoke_reason`).

**Data plane** — `policies.py` with `strict-hybrid` / `hybrid-preferred` /
`classical-lab` and `validate_selection()`. Enforcement proven:

```
positive_hybrid      connect  X25519MLKEM768
negative_x25519      reject
negative_prime256v1  reject
negative_tls12       reject
negative_aes128      reject
negative_invalid_ca  reject
```

`negative_missing_client_cert` connects — correct, `TLS_MTLS=false`; it is
opt-in (`include_mtls`) and excluded from `ENFORCEMENT_PROBES`.

**Event loop** — `main.py` shutdown bounded (`SHUTDOWN_TIMEOUT = 5.0`);
startup `validate()` and the collector's file I/O moved to `asyncio.to_thread`.
Root cause of an earlier total hang: unbounded `await task` on a collector
blocked in sync I/O wedged `uvicorn --reload`.

**Stats** — `/api/tls/stats` aggregates per **connection**, returns
`total_sessions, active_sessions, hybrid_sessions, classical_sessions,
unknown_sessions, hybrid_coverage, tls13_coverage, failed_handshakes,
active_alerts, last_observed_at, has_evidence, active_window_seconds`.

**Scopes / keys** — `tls:probe` added between read and admin
(`tls:admin ⊃ {tls:read, tls:probe}`, `tls:probe ⊃ {tls:read}`). Keys default
to 90 days; `never_expires` requires `system:admin` (403 otherwise).

**Pages** — Overview, Sessions, Certificate, Policy, **Keys**. Sidebar updated.
`tsc --noEmit` exit 0; `npm run build` passes (31 routes).

**Client methods present**: `getTlsStatus, getTlsStats, getTlsSessions,
getTlsSession, getTlsEvents, getTlsPolicy, applyTlsPolicy, getTlsReadiness,
runTlsProbe, testHybridDowngrade, testTls12Downgrade, testCipherDowngrade,
getTlsCertificate, getTlsSignatureAlgorithms, createTlsApiKey,
listTlsApiKeys, revokeTlsApiKey, getGrantableScopes`.

## Evidence chain (criterion 13) — reproduced end to end

```
OpenSSL     negotiated X25519MLKEM768
NGINX log   connection_id 197, listener 8443, group X25519MLKEM768
PostgreSQL  connection_id "8443:197", hybrid_negotiated true
FastAPI     /api/tls/sessions returns it
/stats      total_sessions 4->5, active_sessions 0->1
dashboard   /tls-portal/sessions renders 200
```

## Next task — Phase 5 remainder, in this order

1. **`events.py`** — TLS lifecycle events + Redis publish. `tls_events` exists
   with a CHECK constraint on `event_type`; extend it in a new migration if a
   new type is needed.
2. **`attacks.py` / validation module** — the 8 tests. Targets **must** be
   localhost or an admin allowlist (SSRF); require `tls:admin`; timeouts and
   rate limits; store raw evidence with secrets stripped. Reuse
   `probe.py::TlsProber` rather than writing new subprocess code.
3. **`/api/tls/status` field expansion** — currently ~8 of the 20 specified.
   Missing: `transport_reachable, runtime_name, runtime_version,
   tls13_configured, configured_group, last_negotiated_group,
   certificate_expires_at, certificate_signature_algorithm, last_probe_at,
   telemetry_fresh`. `stats.py::telemetry_is_fresh()` already exists.
4. **Policy rollback** — `POST /api/tls/policy/rollback` against
   `tls_policy_history`. `previous_config` stores full config text, so rollback
   is a restore, not a re-render. Must: validate → store previous → apply →
   reload → health probe → auto-rollback on failure → audit.
5. **Alert engine** — 16 `alert_type` values already in the `tls_alerts` CHECK.
   Use `dedupe_key` (partial unique index on unacknowledged rows).
6. **WebSocket tickets** — `ws_tickets` table ready; hashed, single-use,
   seconds-long. Existing socket is `protocols/ipsec/websocket.py`.

Then Phase 7 pages (Docs, Readiness, Alerts, SIEM, Validation Lab),
Phase 8 tests, Phase 9 docs.

## Known issues to fix

- **`failed_handshakes` is inflated** by probe rows from before NGINX was
  running. Scope it to a time window rather than deleting evidence.
- **Collector `os.path.getsize`** inside `NginxLogReader.size()` is still sync
  (called from the threaded path, so it does not block the loop — but if
  `size()` is ever called directly from async code, it would).
- **Lint**: 20 repo-wide errors, all the same `react-hooks/set-state-in-effect`
  pattern used by every existing portal page. Pre-existing, not build-blocking.

## Not verified

- **Browser click-testing of the Keys page.** Page renders 200 over both
  `:3000` and `:8444`, and every API call it makes is verified by direct
  request, but no automated browser drove the create/copy/revoke flow.
