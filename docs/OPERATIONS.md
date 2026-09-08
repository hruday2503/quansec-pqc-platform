# Operations

Running QUANSEQ: process management, monitoring, integration, and a
troubleshooting matrix.

> **Phase 1 deployment note:** the systemd monolith described below is retained
> only as historical reference. The current backend is four independently
> restartable containers and policy changes go through a restricted host agent;
> there is no sudo/dev-mode path in the application. Follow
> [CONTAINERS.md](CONTAINERS.md) for current startup and health procedures.

- [1. Running the services](#1-running-the-services)
- [2. Health monitoring](#2-health-monitoring)
- [3. Prometheus and Grafana](#3-prometheus-and-grafana)
- [4. SIEM integration](#4-siem-integration)
- [5. Alerting](#5-alerting)
- [6. Logs](#6-logs)
- [7. Database maintenance](#7-database-maintenance)
- [8. Scaling](#8-scaling)
- [9. Backup and recovery](#9-backup-and-recovery)
- [10. Common tasks](#10-common-tasks)
- [11. Troubleshooting matrix](#11-troubleshooting-matrix)

---

## 1. Running the services

### 1.1 Backend as a systemd unit

```ini
# /etc/systemd/system/quanseq.service
[Unit]
Description=QUANSEQ PQC Platform API
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=exec
User=quanseq
Group=quanseq
WorkingDirectory=/opt/quanseq/quanseq          # ← must be the quanseq/ dir
Environment="PATH=/opt/quanseq/quanseq/.venv/bin"
ExecStart=/opt/quanseq/quanseq/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening — relax only what the policy engines actually need
NoNewPrivileges=false          # required: the engines call sudo
PrivateTmp=false               # required: dev mode writes to /tmp/quanseq
ProtectSystem=full
ProtectHome=read-only          # the CA key lives under ~; read-only is enough

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quanseq
sudo journalctl -u quanseq -f
```

`WorkingDirectory` **must** be the `quanseq/` subdirectory — `main.py` imports as
`core.*` and `protocols.*`.

### 1.2 Frontend

```bash
cd quanseq-ui && npm run build
```

```ini
# /etc/systemd/system/quanseq-ui.service
[Service]
Type=exec
User=quanseq
WorkingDirectory=/opt/quanseq/quanseq-ui
ExecStart=/usr/bin/npm run start
Environment="NODE_ENV=production"
Restart=on-failure
```

`NEXT_PUBLIC_QUANSEQ_API` is inlined at **build** time — changing it requires
`npm run build` again.

### 1.3 Reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name quanseq.example.com;
    ssl_certificate     /etc/ssl/certs/quanseq.crt;
    ssl_certificate_key /etc/ssl/private/quanseq.key;

    location /api/ { proxy_pass http://127.0.0.1:8000; include /etc/nginx/proxy_params; }
    location /docs { proxy_pass http://127.0.0.1:8000; }

    location /api/ws/ {                       # WebSocket needs upgrade headers
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;             # the live feed is long-lived
    }

    location /metrics {                       # unauthenticated — restrict here
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://127.0.0.1:8000;
    }

    location / { proxy_pass http://127.0.0.1:3000; }   # Next.js
}
```

Three things that bite without them: the `Upgrade` headers (the WebSocket fails
silently otherwise), the long `proxy_read_timeout` (the feed drops every 60 s at
the default), and the `/metrics` ACL.

### 1.4 Startup order

PostgreSQL → Redis → backend → frontend. The backend tolerates Redis being down
(degrades to no live push) but not PostgreSQL.

---

## 2. Health monitoring

```bash
curl -s localhost:8000/health
```

```json
{"status":"ok","database":"connected",
 "collectors":["ipsec-collector","ipsec-events","alerts","zt-audit","ssh-collector"]}
```

**Monitor the length of `collectors`, not just `status`.** A dead collector
disappears from the list while `status` stays `ok` — the API is fine, but data
has silently stopped flowing.

```bash
# alert if fewer than 5 collectors are alive
curl -s localhost:8000/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if len(d['collectors'])==5 else 1)"
```

Expected collectors: `ipsec-collector`, `ipsec-events`, `ssh-collector`,
`alerts`, `zt-audit`.

### Data freshness

Health says nothing about whether collectors are producing anything. Check
staleness directly:

```sql
SELECT name, state, last_seen, NOW() - last_seen AS age FROM ipsec_tunnels
ORDER BY last_seen DESC LIMIT 5;
```

`age` should stay under ~10 s (two poll intervals) for an active tunnel.

---

## 3. Prometheus and Grafana

```yaml
scrape_configs:
  - job_name: quanseq
    scrape_interval: 15s
    static_configs:
      - targets: ['quanseq-host:8000']
```

### Exported metrics

| Metric | Type | Meaning |
|---|---|---|
| `quanseq_ipsec_tunnels_total` | gauge | Tunnels known |
| `quanseq_ipsec_tunnels_established` | gauge | Currently up |
| `quanseq_ipsec_tunnels_pqc` | gauge | PQC-enabled |
| `quanseq_ipsec_pqc_coverage_percent` | gauge | PQC ÷ established |
| `quanseq_ipsec_bytes_{in,out}_total` | counter | Traffic |
| `quanseq_ssh_sessions_total` | gauge | Sessions ever seen |
| `quanseq_ssh_sessions_active` | gauge | Currently active |
| `quanseq_ssh_sessions_pqc` | gauge | Active and PQC |
| `quanseq_ssh_pqc_coverage_percent` | gauge | PQC ÷ active |
| `quanseq_ssh_bytes_{sent,received}_total` | counter | Traffic |
| `quanseq_zt_auth_{accepted,rejected}_total` | counter | Certificate auths |

### Alerting rules

```yaml
groups:
  - name: quanseq-pqc
    rules:
      - alert: PQCCoverageDropped
        expr: quanseq_ipsec_pqc_coverage_percent < 100
        for: 2m
        labels: {severity: critical}
        annotations:
          summary: "IPsec PQC coverage at {{ $value }}% — a tunnel is classical"

      - alert: SSHPQCCoverageDropped
        expr: quanseq_ssh_pqc_coverage_percent < 100
        for: 2m
        labels: {severity: critical}

      - alert: ZeroTrustRejectionSpike
        expr: rate(quanseq_zt_auth_rejected_total[5m]) > 0.1
        for: 5m
        labels: {severity: warning}
        annotations:
          summary: "Elevated certificate rejections — expired certs or an intrusion attempt"

      - alert: QuanseqDown
        expr: up{job="quanseq"} == 0
        for: 1m
        labels: {severity: critical}
```

`quanseq_ipsec_tunnels_established == 0` while `_total > 0` is the clearest
"everything went down" signal.

### Dashboard panels worth building

1. PQC coverage % over time, both protocols — the headline chart.
2. Established tunnels and active sessions — capacity.
3. Traffic rate — `rate(quanseq_*_bytes_*_total[5m])`.
4. Zero Trust accept/reject rate.
5. A single stat: days until the CNSA 2.0 deadline (from
   `/api/{ipsec,ssh}/policies/compare`).

---

## 4. SIEM integration

Pull-based. QUANSEQ exports; the SIEM ingests on its own schedule.

```bash
# CEF — ArcSight, Splunk, QRadar
curl -s "https://quanseq/api/siem/events?format=cef" -H "Authorization: Bearer $KEY"

# RFC 5424 syslog
curl -s "https://quanseq/api/siem/events?format=syslog" -H "Authorization: Bearer $KEY"

# JSON — Elastic
curl -s "https://quanseq/api/siem/events?format=json" -H "Authorization: Bearer $KEY"
```

Use an **API key**, not a JWT — it does not expire mid-poll.

```
CEF:0|QUANSEQ|PQC-Platform|1.0|zt_rejected|Zt Rejected|8|rt=2026-07-29T14:19:02+00:00 act=zt_rejected outcome=ssh-zero-trust msg=identity=alice@quanseq.io src=192.168.1.6 reason=expired
```

CEF severities: ZT rejection 8, attacks 6, key revocation 6, policy change 5,
key creation 4, login 3.

Splunk forwarder:

```conf
# inputs.conf
[script://./bin/quanseq_poll.sh]
interval = 60
sourcetype = quanseq:cef
```

**Known gap:** the export currently returns **Zero Trust events only**. The
audit-events query selects `audit_events.created_at`, but the column is
`occurred_at`; the failure is caught and logged at DEBUG. Until that one-word fix
lands, policy changes and certificate issuance do **not** reach the SIEM. If you
need them now, query the table directly.

---

## 5. Alerting

The built-in engine evaluates every 10 seconds and writes to the `alerts` table.

| Rule | Severity | Fires when |
|---|---|---|
| `downgrade_detected` | critical | An established IPsec tunnel or active SSH session is not PQC |
| `zt_rejection` | medium | A certificate auth was rejected |
| `pqc_coverage_drop` | high | Declared in `RULES` but **not evaluated** |
| `tunnel_down` | high | Declared in `RULES` but **not evaluated** |

Deduplication is by `fingerprint` (`UNIQUE`), so a persistent condition raises
one row rather than one every 10 seconds.

```bash
curl -s localhost:8000/api/alerts -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8000/api/alerts/12/ack -H "Authorization: Bearer $TOKEN"
```

**There is no auto-resolve.** An alert stays until acknowledged, even after the
condition clears. Acknowledgement is not audited — an attacker with an operator
token can silence a genuine downgrade alert. For anything important, alert in
Prometheus (§3) rather than relying on the built-in engine alone.

Adding a rule means editing `evaluate_once()` in `protocols/alerts/router.py`;
rules are Python, not database rows, despite the `alert_rules` table existing.

---

## 6. Logs

Structured by logger name:

```
2026-07-29 14:23:11  INFO   quanseq.ipsec.collector  IPsec poll: 1 tunnels, 1 PQC-enabled
2026-07-29 14:23:11  INFO   quanseq.ssh.collector    SSH poll: 1 sessions, 1 PQC-enabled
2026-07-29 14:23:14  INFO   quanseq.ipsec.events     Lifecycle event: pqc-tunnel -> ESTABLISHED
2026-07-29 14:24:02  WARNING quanseq.ipsec.policy    StrongSwan not installed — policy saved to /tmp/…
```

| Logger | Emits |
|---|---|
| `quanseq.main` | Startup, migrations, shutdown |
| `quanseq.ipsec.collector` | Poll results, VICI availability |
| `quanseq.ipsec.events` | Lifecycle events, listener reconnects |
| `quanseq.ipsec.policy` | Policy applications, dev-mode warnings |
| `quanseq.ssh.collector` | Poll results |
| `quanseq.ssh.policy` | Policy applications and restarts |
| `quanseq.ssh.ca` | Certificate issuance |
| `quanseq.ssh.ztaudit` | ZT collection errors |
| `quanseq.alerts` | Rule evaluation errors |

Lines worth alerting on:

```bash
journalctl -u quanseq | grep "VICI socket not available"   # data plane blind
journalctl -u quanseq | grep "collect error"               # collector failing
journalctl -u quanseq | grep "dev_mode=true"               # policy not enforced
journalctl -u quanseq | grep "Migration .* error"          # schema problem
```

Raise verbosity with `LOG_LEVEL` in `.env` — note that several failures
(SIEM audit gather, ZT log read, metrics blocks) are logged at **DEBUG**, so
`INFO` hides them.

---

## 7. Database maintenance

### Retention

No retention policy exists. Add one before running continuously:

```sql
DELETE FROM ipsec_events    WHERE occurred_at < NOW() - INTERVAL '90 days';
DELETE FROM zt_audit        WHERE event_time  < NOW() - INTERVAL '90 days';
DELETE FROM ssh_connections WHERE state='CLOSED' AND last_seen < NOW() - INTERVAL '30 days';
-- audit_events is a compliance record — check requirements before deleting
```

```cron
0 3 * * * psql -U quanseq_user -d quanseq_db -f /opt/quanseq/retention.sql
```

### Size check

```sql
SELECT relname, n_live_tup,
       pg_size_pretty(pg_total_relation_size(relid)) AS size
FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;
```

`ipsec_events` and `ssh_connections` grow fastest.

### Vacuum

Autovacuum handles the upsert-heavy tables adequately. After a large retention
delete, reclaim explicitly:

```sql
VACUUM ANALYZE ipsec_events;
```

---

## 8. Scaling

### Current limits

| Resource | Limit | Why |
|---|---|---|
| uvicorn workers | **1** | Collectors run in-process and would duplicate |
| DB connections | 10 | `max_size` in `core/database.py` |
| Poll interval | 5 s | `IPSEC_POLL_INTERVAL`; SSH has its own constant |
| Tunnels | thousands | Bounded by VICI response size, not the platform |
| SSH sessions | thousands | Bounded by `ss` output parsing |

### Why one worker

Each uvicorn worker executes the full `lifespan`, so N workers means N copies of
all five collectors: duplicate writes, duplicate `quanseq:live` publishes, and N
concurrent VICI connections.

### Splitting collectors from the API

The change that unlocks horizontal scaling:

1. Create `collector_main.py` that runs only the collector tasks.
2. Remove `create_task(...)` from `main.py`'s lifespan.
3. Run one collector process and N API workers.

```ini
ExecStart=…/uvicorn main:app --workers 4        # quanseq-api.service
ExecStart=…/python collector_main.py            # quanseq-collectors.service (one instance)
```

Redis pub/sub already supports this — every API worker subscribes independently,
and each browser gets the feed from whichever worker it connected to. No other
change is needed; the architecture was built for it.

### Tuning

Raise the pool if API workers increase:

```python
_pool = await asyncpg.create_pool(dsn=..., min_size=5, max_size=20, command_timeout=30)
```

Poll intervals below ~2 s are counterproductive: `journalctl` and `ss` calls
start overlapping their own timeouts.

---

## 9. Backup and recovery

### What to back up

| Item | Criticality | Method |
|---|---|---|
| PostgreSQL | **critical** | `pg_dump` |
| CA private key | **critical** | Offline encrypted copy |
| `.env` | high | Secret manager |
| `swanctl.conf` / `sshd_config` | medium | In git (secrets redacted) |
| Redis | none | Transient by design |

```bash
pg_dump -U quanseq_user -d quanseq_db -Fc -f quanseq-$(date +%F).dump
```

### Restore

```bash
sudo systemctl stop quanseq
dropdb -U postgres quanseq_db && createdb -U postgres -O quanseq_user quanseq_db
pg_restore -U quanseq_user -d quanseq_db quanseq-2026-07-29.dump
sudo systemctl start quanseq
```

Migrations re-run on startup and are idempotent, so a restore of an older dump
against newer code self-heals the schema.

### Losing the CA key

Every issued certificate becomes unverifiable and no new ones can be signed.
Recovery is: generate a new CA, distribute the new public key to every server's
`TrustedUserCAKeys`, and reissue every certificate. **Back it up offline.**

---

## 10. Common tasks

### Rotate the JWT secret

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# update JWT_SECRET in .env
sudo systemctl restart quanseq
```

Every existing token is invalidated; all users must log in again. That is the
intended effect.

### Add an operator

```bash
curl -X POST localhost:8000/api/auth/register \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"ops@example.com","password":"…","role":"operator"}'
```

`portal` defaults to `main` (sees both portals). Set it directly for tenancy:

```sql
UPDATE users SET portal = 'ssh' WHERE email = 'ops@example.com';
```

### Switch a protocol to PQC

```bash
curl -X POST localhost:8000/api/ipsec/policies/apply \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"policy_name":"pqc-level5"}'
```

**Check `dev_mode` in the response.** `true` means nothing on the live system
changed. For IPsec, also note that existing SAs keep their old proposal until the
next rekey — force it with `sudo swanctl --initiate --child net`.

### Roll back an SSH policy

```bash
curl -X POST localhost:8000/api/ssh/policies/rollback -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Force an immediate IPsec poll

```bash
curl -X POST localhost:8000/api/ipsec/refresh -H "Authorization: Bearer $TOKEN"
```

### Issue an SSH certificate

See [SETUP.md §6.3](SETUP.md#63-issue-a-certificate).

---

## 11. Troubleshooting matrix

### Backend

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: core` | Started outside `quanseq/` | `WorkingDirectory=/…/quanseq` |
| `/health` → `degraded` | PostgreSQL unreachable | `systemctl status postgresql`; check `DATABASE_URL` |
| Fewer than 5 collectors listed | A task died | `journalctl -u quanseq \| grep -i error`; restart |
| Migration errors on startup | Expected on re-run — all statements are idempotent | Investigate only if a table is genuinely missing |
| 500s on every endpoint | Pool exhausted or DB down | Check `max_size`; check connection count |

### IPsec

| Symptom | Cause | Fix |
|---|---|---|
| `VICI socket not available` every 5 s | charon down, or socket unreadable | `systemctl status strongswan`; [SETUP.md §4.6](SETUP.md#46-vici-socket-permissions) |
| No tunnels in the API | No active SAs | `swanctl --list-sas`. `start_action=trap` needs traffic — ping the peer |
| `pqc_enabled: false` on a live tunnel | Genuinely classical | `swanctl --list-sas` — if it shows `ECP_384`, the peer downgraded. Investigate |
| `NO_PROPOSAL_CHOSEN` | ml-kem plugin unloaded, or `accept_private_algs` missing | `swanctl --stats \| grep ml-kem` |
| Policy applied, nothing changed | Config reload does not renegotiate live SAs | Wait for rekey, or `swanctl --initiate` |
| Tunnels flapping to DOWN | Poll cycles missed for >30 s | Check VICI timeouts and backend CPU |

### SSH

| Symptom | Cause | Fix |
|---|---|---|
| `kex_algorithm: "unknown"` | All three detection tiers failed | `LogLevel DEBUG1`; add user to `systemd-journal` |
| Port-2222 session shows classical | journald read failed; fell back to the *system* sshd's KEX | `journalctl -u ssh --since -5min \| grep "kex:"` |
| No sessions at all | None established | `ss -tnp state established \| grep -E ':(22\|2222)'` |
| Sessions never close | The collector is not completing cycles | Check `/health` |
| Policy apply → "sshd config invalid" | `sshd -t` rejected the rewrite | The daemon was **not** restarted — safe. Inspect the config |
| Policy apply → "sshd restart failed" | The daemon is now down | `bash vm-b/scripts/start-pqc-ssh.sh` |

### Zero Trust

| Symptom | Cause | Fix |
|---|---|---|
| No events | Wrong log path, or auths happen on another host | `QUANSEQ_ZT_LOG`, or `QUANSEQ_ZT_REMOTE` |
| `source_ip: "unknown"` | PID correlation failed on a standalone rejection | Log format differs from the expected `sshd-session[PID]` shape |
| Certs rejected as expired immediately | Clock skew beyond the 1-hour backdate | Sync NTP on both hosts |
| `ca_info` → 500 | `QUANSEQ_CA_KEY` wrong, or `.pub` unreadable | Check the path and permissions |

### Frontend

| Symptom | Cause | Fix |
|---|---|---|
| Stuck on `AUTHENTICATING…` | `/api/auth/me` failing | Check the backend and the token |
| CORS errors | Origin not allowed | Update `allow_origins` in `main.py` |
| Live badge grey | WebSocket failed | Redis down, or the proxy lacks `Upgrade` headers |
| Data never updates | Polling erroring silently — errors are swallowed by design | Open the browser network tab |
| Calls hit the wrong host after a config change | `NEXT_PUBLIC_QUANSEQ_API` is inlined at build time | `npm run build` again |

---

*See also:* [SETUP.md](SETUP.md) · [SECURITY.md](SECURITY.md) · [API.md](API.md) · [ARCHITECTURE.md](ARCHITECTURE.md)
