# SSH module

Hybrid post-quantum SSH with a certificate authority and a Zero Trust audit trail.

**Status:** live · **KEX:** `mlkem768x25519-sha256` (hybrid) · **NIST level:** 3 · **CNSA 2.0 deadline:** 2030

- [1. What this module does](#1-what-this-module-does)
- [2. Files](#2-files)
- [3. Cryptographic design](#3-cryptographic-design)
- [4. Session and KEX detection](#4-session-and-kex-detection)
- [5. The collector](#5-the-collector)
- [6. The policy engine](#6-the-policy-engine)
- [7. The certificate authority](#7-the-certificate-authority)
- [8. Zero Trust audit](#8-zero-trust-audit)
- [9. The attack lab](#9-the-attack-lab)
- [10. API reference](#10-api-reference)
- [11. Data model](#11-data-model)
- [12. Operating notes](#12-operating-notes)

---

## 1. What this module does

```
sshd :2222 ──journald "kex: algorithm:"──┐
ss -tnp    ──sessions + byte counters ───┼──► collector ──► ssh_connections ──► REST
sshd -T    ──configured KEX (fallback)───┘

/var/log/auth.log ──cert auth lines──► zt collector ──► zt_audit ──► ZT API + alerts

policy engine ──rewrites /opt/openssh-pqc/etc/sshd_config──► restart sshd

CA ──ssh-keygen -s──► short-lived certificate ──► user
```

Five responsibilities:

1. **Discover** active SSH sessions and the KEX each negotiated.
2. **Classify** each as PQC-hybrid or classical.
3. **Enforce** a KEX policy on the PQC daemon, with one-click rollback.
4. **Issue** short-lived CA-signed certificates — the Zero Trust onboarding flow.
5. **Audit** every certificate authentication with identity, serial, CA and source.

---

## 2. Files

| File | Lines | Responsibility |
|---|---|---|
| `collector.py` | 261 | Session discovery, three-tier KEX detection, byte counters, upsert |
| `router.py` | 182 | Stats, connections, handshakes, comparison, attack simulations |
| `policy.py` | 203 | Two KEX policies, sshd_config rewrite, restart, history, rollback |
| `ca.py` | 157 | Certificate issuance, CA info, issuance audit |
| `ztaudit.py` | 248 | Auth-log parsing, ZT event storage, posture summary, policy statement |

---

## 3. Cryptographic design

### 3.1 The hybrid KEX

```
KexAlgorithms mlkem768x25519-sha256
```

```
   X25519 ECDH share ────┐
                         ├──► SHA-256 ──► session key
   ML-KEM-768 share ─────┘
```

Both shares feed the KDF. Compromising the session requires breaking **both**.

| Adversary | X25519 | ML-KEM-768 | Session |
|---|---|---|---|
| Classical | secure | secure | secure |
| Quantum (Shor) | **broken** | secure | **secure** |
| Lattice break | secure | **broken** | **secure** |
| Both | broken | broken | broken |

### 3.2 Why hybrid here but pure ML-KEM for IPsec

Not an inconsistency — a different threat and deployment model.

| | SSH | IPsec |
|---|---|---|
| Client population | Heterogeneous, third-party | Two peers, same build |
| Upstream support | OpenSSH ships hybrid | ML-KEM added by our own plugin |
| Standards position | IETF hybrid drafts specify combining shares | CNSA 2.0 targets an ML-KEM end state |
| Risk being hedged | ML-KEM is young; keep a classical fallback | Downgrade; a single proposal has nothing to downgrade to |

Hybrid is the correct production default. Pure ML-KEM is the correct
demonstration of where the standard is heading. The platform runs both so it can
show either with live evidence. See [IPSEC.md §3.4](IPSEC.md#34-pure-ml-kem-not-hybrid).

### 3.3 What is *not* changed

Host keys stay Ed25519, MACs stay HMAC-SHA2, ciphers stay ChaCha20-Poly1305 /
AES-GCM. Signatures and symmetric primitives are quantum-resistant at current
sizes — Grover halves symmetric strength, which 256-bit keys absorb, and forging
a host key signature is only useful during a live handshake, not retroactively.
**Key exchange is the only genuinely broken part**, so it is the only part
replaced.

ML-DSA (FIPS 204) host keys are the natural follow-on, and CNSA 2.0 requires them
by 2030.

### 3.4 Recognised algorithms

```python
PQC_KEX = {
  "mlkem768x25519-sha256":              ("ML-KEM-768 + X25519",  "ML-KEM-768",  True),
  "mlkem1024x25519-sha256":             ("ML-KEM-1024 + X25519", "ML-KEM-1024", True),
  "sntrup761x25519-sha512@openssh.com": ("NTRU Prime + X25519",  "sntrup761",   True),
  "sntrup761x25519-sha512":             ("NTRU Prime + X25519",  "sntrup761",   True),
}

CLASSICAL_KEX = {
  "curve25519-sha256":             ("X25519 (classical)", "X25519",     False),
  "curve25519-sha256@libssh.org":  ("X25519 (classical)", "X25519",     False),
  "ecdh-sha2-nistp256":            ("ECDH P-256",         "ECDH-P256",  False),
  "ecdh-sha2-nistp384":            ("ECDH P-384",         "ECDH-P384",  False),
  "diffie-hellman-group14-sha256": ("DH Group 14",        "DH-2048",    False),
}
```

`sntrup761x25519` is included because OpenSSH shipped it years before ML-KEM was
standardised — a large installed base is already post-quantum via NTRU Prime and
should not be reported as classical.

An unrecognised name falls back to a substring test for `mlkem` or `sntrup`, so a
future algorithm name still classifies correctly.

---

## 4. Session and KEX detection

There is no VICI for sshd. Detection composes three sources in strict priority
order, and the module always reports which one it used.

| Priority | Source | Command | Proves | Fails when |
|---|---|---|---|---|
| **1** | journald | `journalctl -u ssh -u sshd -u quanseq-pqc-sshd.service --since -10min` | What was **actually negotiated** | `LogLevel DEBUG1` unset, journald unreadable, entry aged out |
| **2** | Port map | — | What that listener **enforces** | Only for known ports (22, 2222) |
| **3** | `sshd -T` | `sshd -T \| grep kexalgorithms` | What the daemon **offers** | Never fails; weakest claim |

```python
kex = kex_map.get(peer) or SSH_PORT_KEX.get(ssh_port) or configured or "unknown"
```

### 4.1 Tier 1 — journald

With `LogLevel DEBUG1`, sshd logs two correlated lines per connection:

```
sshd[1234]: Connection from 192.168.1.6 port 54321
sshd[1234]: debug1: kex: algorithm: mlkem768x25519-sha256
```

The parser tracks the most recent `Connection from <ip> port <n>` and attributes
the following `kex: algorithm:` line to it, building a `"ip:port" → kex` map.

This is the only tier that is *evidence*. The other two are *policy*.

### 4.2 Tier 2 — the port map

```python
SSH_PORT_KEX = {"2222": "mlkem768x25519-sha256",   # QUANSEQ PQC sshd
                "22":   "curve25519-sha256"}       # system sshd
```

Because the PQC daemon is configured with a single KEX and no fallback, "this
session is on 2222" implies "this session negotiated ML-KEM-768" — the daemon
would have refused otherwise. The inference is only valid because the
configuration is fail-closed.

### 4.3 Tier 3 — configured KEX

`sshd -T` renders the effective configuration; the first entry in
`KexAlgorithms` is the preferred one. If `sshd -T` is unavailable the collector
parses `/etc/ssh/sshd_config` directly, stripping any `+`, `-` or `^` prefix.

### 4.4 Session discovery and counters

```bash
ss -tnp state established    # sessions; keep rows where local or peer port ∈ {22, 2222}
ss -tin                      # bytes_sent / bytes_received per peer
```

Both directions are captured — this host as SSH server *and* as SSH client — by
checking the local port and the peer port against the known-SSH set.

Session identity is `session_key = "<local>-><peer>"`, which is unique for the
lifetime of a TCP connection and is the upsert conflict target.

---

## 5. The collector

`collector.py` — the `ssh-collector` background task, 5-second interval.

```python
async def collect_once(pool):
    kex_map    = _live_kex_by_peer()       # tier 1
    bytes_map  = _read_bytes_by_peer()
    configured = _read_configured_kex()    # tier 3
    sessions   = _active_sessions()

    for s in sessions:
        kex = kex_map.get(s["peer"]) or SSH_PORT_KEX.get(s["ssh_port"]) or configured or "unknown"
        label, kem, pqc = _classify(kex)
        # INSERT … ON CONFLICT (session_key) DO UPDATE …

    # anything not seen this cycle:
    UPDATE ssh_connections SET state='CLOSED'
     WHERE session_key <> ALL($1::text[]) AND state='ACTIVE'
```

Two design points:

**Closure is immediate, not grace-period based.** Unlike IPsec (30-second
staleness window), an SSH session that disappears from `ss` is closed *now* —
`ss` reports established TCP connections directly from the kernel, so absence is
authoritative rather than a possibly-missed poll.

**`<> ALL($1::text[])`** uses a PostgreSQL array comparison rather than building
a `NOT IN (...)` clause by string concatenation. One parameterised statement,
any number of sessions, no injection surface.

The module also exposes `ssh_collector_task(pool)` — the same loop taking an
explicit pool — while `collect_loop()` is the no-arg form required by the
[collector contract](../ARCHITECTURE.md#31-the-collector-contract).

---

## 6. The policy engine

`policy.py` — `/api/ssh/policies`

### 6.1 Policies

| Name | KEX | Construction | Quantum-safe |
|---|---|---|---|
| `classical` | `curve25519-sha256` | Single ECDH | ❌ |
| `pqc-hybrid` | `mlkem768x25519-sha256` | Hybrid | ✅ NIST L3 |

### 6.2 Applying

```
POST /api/ssh/policies/apply   {"policy_name": "pqc-hybrid"}   [admin]
```

**Dev mode** (no `/opt/openssh-pqc/etc/sshd_config`): writes a simulated config to
`/tmp/quanseq/sshd/sshd_config`, returns `dev_mode: true`.

**Production**, in order:

1. Read the existing `sshd_config`, replace the `KexAlgorithms` line (append it
   if absent) — every other directive is preserved verbatim.
2. `sudo tee` the result back.
3. **`sudo sshd -t -f <config>`** — validate. A non-zero exit aborts with HTTP 500
   *before* the daemon is touched.
4. `sudo pkill -f "<sshd bin>.*2222"` then relaunch.
5. Audit row + `ssh_policy_history` row.

Step 3 is the important one. Validating before restarting means a malformed
config produces an error response, not an sshd that fails to come back. It is
still a **restart, not a reload** — existing sessions survive (sshd forks per
connection) but there is a brief window during which the listener is down and new
connections are refused.

Response:

```json
{"status":"applied","policy":"pqc-hybrid","kex":"mlkem768x25519-sha256",
 "pqc_enabled":true,"dev_mode":false,
 "message":"sshd restarted. New SSH connections use the new KEX. Reconnect to apply."}
```

Existing sessions keep the KEX they negotiated. Only new connections are affected.

### 6.3 History and rollback

```
GET  /api/ssh/policies/history     last 10 applications
POST /api/ssh/policies/rollback    revert to the previous policy   [admin]
```

`ssh_policy_history` records `(policy_name, kex, applied_at)` on every apply.
Rollback reads the two most recent rows and re-applies the second, returning 400
if there is no prior policy.

This is the crypto-agility safety net: switch to `classical` for a demonstration,
then get back to a secure posture with one call rather than by remembering what
was there before.

---

## 7. The certificate authority

`ca.py` — `/api/ssh/ca`

### 7.1 Why certificates instead of `authorized_keys`

| | `authorized_keys` | CA-signed certificate |
|---|---|---|
| Provisioning | Copy a key to every server | Sign once; every server trusts the CA |
| Expiry | None — keys live forever | Built-in `valid_after` / `valid_before` |
| Identity | A key blob | A named identity (`alice@quanseq.io`) |
| Scope | All-or-nothing | Principals, source restrictions, forced commands |
| Revocation | Edit every server | One KRL by serial |
| Audit | "some key authenticated" | Identity + serial + CA fingerprint, logged |

The server-side cost is one line: `TrustedUserCAKeys /opt/openssh-pqc/etc/quanseq_ca.pub`.

### 7.2 The issuance flow

```
1. User generates a keypair locally      ssh-keygen -t ed25519 -f ~/.ssh/alice
2. User submits the PUBLIC key           POST /api/ssh/ca/issue          [admin]
3. QUANSEQ signs it                      ssh-keygen -s <CA> -I <identity>
                                             -n <principals> -V -1h:+8h -z <serial>
4. User pairs cert with private key      ssh -i alice -o CertificateFile=alice-cert.pub
```

**The private key never leaves the user.** Two defences enforce it:

```python
PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S+)?\s*$")
if not PUBKEY_RE.match(pk):
    raise HTTPException(400, "Not a valid SSH public key line")
if "PRIVATE KEY" in pk.upper():
    raise HTTPException(400, "That looks like a PRIVATE key — never submit private keys.")
```

The regex accepts exactly one well-formed public key line, so multi-line input,
shell metacharacters and PEM blocks are all rejected before anything is written
to disk. The explicit private-key check exists for the user who pastes the wrong
file — it produces a clear error rather than a confusing regex failure.

Signing happens in a `tempfile.TemporaryDirectory()`, so the submitted key and
the resulting certificate are removed when the request completes. `ssh-keygen` is
invoked with an argument list (never `shell=True`), so the identity and principal
strings cannot inject a command.

**`-V -1h:+8h`** backdates validity by one hour to absorb clock skew between the
CA host and the SSH server — without it, a server whose clock is two minutes
behind rejects a freshly issued certificate as not-yet-valid.

### 7.3 Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/ssh/ca/info` | user | CA public key + `ssh-keygen -lf` fingerprint — what servers configure as trusted |
| `POST` | `/api/ssh/ca/issue` | **admin** | `valid_hours` bounded 1–168 by Pydantic |
| `GET` | `/api/ssh/ca/issued` | user | Last 50, with a computed `expired` flag |

Response to `issue` includes the certificate, a suggested filename, and the exact
ssh command to use it.

### 7.4 Known limitations

- **Serial allocation** is `MAX(serial) + 1` in a separate statement from the
  insert. Two simultaneous issuances can collide; there is no unique constraint
  on `serial` to catch it. Use a sequence.
- **No KRL generation.** Serials are recorded but no revocation list is produced
  or distributed. Short validity (default 8 h) is the containment mechanism.
  Manual revocation: [SETUP.md §6.4](../SETUP.md#64-revocation).
- **`expires_at`** is computed as `NOW() + make_interval(hours => valid_hours)`,
  which ignores the `-1h` backdate — the recorded expiry is up to an hour later
  than the certificate's actual `valid_before`. Cosmetic in the audit view, but
  do not treat `issued_certs.expires_at` as authoritative.
- The CA private key sits unencrypted on disk at `QUANSEQ_CA_KEY`. An HSM or at
  minimum a passphrase with an agent is the production answer.

---

## 8. Zero Trust audit

`ztaudit.py` — `/api/ssh/zt`, plus the `zt-audit` background task (8 s).

### 8.1 The posture

`GET /api/ssh/zt/policy` returns the enforced posture and maps each Zero Trust
principle to the mechanism that implements it:

| Principle | Mechanism |
|---|---|
| Never trust, always verify | Every session requires a valid CA-signed certificate |
| No implicit network trust | `PasswordAuthentication no` — being on the LAN grants nothing |
| Least privilege | Certificates scoped to specific principals |
| Time-bound access | Certificates expire automatically (default 8 h) |
| Full auditability | Every authentication logged with identity + serial + CA |

Transport is `mlkem768x25519-sha256`, so the Zero Trust control plane is itself
post-quantum — which is the point of combining the two: a certificate-based
identity model is worth little if the channel carrying it is harvestable.

### 8.2 Log parsing

Two patterns:

```python
ACCEPT_RE = r"(Accepted|Failed) publickey for (?P<principal>\S+) from (?P<ip>\S+) "
            r"port \d+ ssh2: \S+-CERT \S+ ID (?P<identity>\S+) \(serial (?P<serial>\d+)\) "
            r"CA \S+ (?P<ca>SHA256:\S+)"
REASON_RE = r"Certificate invalid: (?P<reason>.+)"
```

**The expired-certificate edge case.** An expired certificate never reaches the
`Failed publickey` line — sshd rejects it earlier and logs only
`error: Certificate invalid: expired`. Without special handling, every expired-cert
rejection would be invisible. The parser:

1. Detects a standalone `Certificate invalid:` line.
2. Looks ahead one line; if it is not an `ACCEPT_RE` match, treats it as a
   standalone rejection.
3. Recovers the source IP by correlating the `sshd-session[PID]` token across the
   next few lines, since the reason line itself carries no IP.
4. Records it as `identity: "invalid-certificate"`, `result: "rejected"`.

**Deduplication.** The collector re-reads the last 400 lines every 8 seconds, so
it sees the same entries repeatedly:

```python
raw_hash = sha256(f"{ts}{identity}{serial}{ip}{result}{reason}").hexdigest()
# INSERT … ON CONFLICT (raw_hash) DO NOTHING
```

The `UNIQUE` constraint on `raw_hash` makes overlapping read windows and
collector restarts idempotent.

**Noise filtering.** Lines containing `COMMAND=`, `sudo:` or `CRON[` are skipped
before parsing, so the collector's own `sudo tail` does not appear in its output.

### 8.3 Remote log collection

When QUANSEQ runs on VM A but authentications happen on VM B, the collector pulls
the log across the PQC channel:

```python
["/opt/openssh-pqc/bin/ssh", "-i", ZT_REMOTE_KEY,
 "-o", f"CertificateFile={ZT_REMOTE_CERT}",
 "-o", "StrictHostKeyChecking=no", "-p", "2222",
 ZT_REMOTE, "sudo tail -n 400 /var/log/auth.log"]
```

Configured via `QUANSEQ_ZT_REMOTE`, `QUANSEQ_ZT_KEY`, `QUANSEQ_ZT_CERT`. The
audit channel is itself post-quantum and certificate-authenticated.

`StrictHostKeyChecking=no` accepts any host key — acceptable on a lab LAN,
a MITM opportunity anywhere else. Pin the host key with a `known_hosts` entry
before using this outside a controlled network.

### 8.4 Endpoints

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/ssh/zt/events` | Recent cert auths: time, identity, serial, CA fingerprint, source IP, principal, result, reason |
| `GET` | `/api/ssh/zt/status` | Totals: accepted, rejected, rejected-expired, `cert_only`, `passwords_disabled` |
| `GET` | `/api/ssh/zt/policy` | The posture statement above |

ZT rejections also feed the alert engine as `zt_rejection` (severity medium).

---

## 9. The attack lab

`POST /api/ssh/attacks/{downgrade|shors|harvest}`

Each reads the KEX of the most recent **ACTIVE** session (falling back to
`sshd -T` if there is none) and branches on whether it is PQC.

**`downgrade`** — MITM strips the hybrid KEX and forces `curve25519-sha256`.
PQC → `BLOCKED`: *"sshd offers only PQC-hybrid KEX; classical-only clients are
refused"*, outcome *"Connection rejected — no shared classical KEX"*. This is
`KexAlgorithms mlkem768x25519-sha256` with no fallback doing exactly what it was
configured to do.

**`shors`** — the interesting case for hybrid. PQC → `RESISTANT`: *"Even though
X25519 is present, the ML-KEM-768 share is combined into the session key.
Breaking X25519 with Shor's leaves the Kyber secret intact."* This is the hybrid
argument stated precisely — Shor's does break the X25519 half, and it does not
matter.

**`harvest`** — PQC → `PROTECTED`, `future_decrypt: "IMPOSSIBLE"`. Classical →
`VULNERABLE`: recorded sessions become readable once X25519 falls.

All three are `require_user`. Each writes an `audit_events` row with severity
`warning` when the verdict is `VULNERABLE`, `info` otherwise — so a vulnerable
result surfaces in the SIEM export.

Like the IPsec lab, these are **reasoned demonstrations against live
configuration**, not executed cryptanalysis. The verdicts are computed from the
actual negotiated KEX, so they are honest about the system's state; the break-time
figures are literature estimates.

---

## 10. API reference

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/ssh/stats` | user | Coverage, counts, byte totals |
| `GET` | `/api/ssh/connections` | user | Active first, then by `last_seen` |
| `GET` | `/api/ssh/handshakes` | user | `?limit=10` — recent KEX negotiations |
| `GET` | `/api/ssh/policies` | user | Available KEX policies |
| `POST` | `/api/ssh/policies/apply` | **admin** | Rewrite + restart sshd |
| `GET` | `/api/ssh/policies/history` | user | Last 10 applications |
| `POST` | `/api/ssh/policies/rollback` | **admin** | Revert to previous |
| `GET` | `/api/ssh/policies/compare` | user | Classical vs hybrid table + CNSA countdown |
| `POST` | `/api/ssh/attacks/{name}` | user | `downgrade`, `shors`, `harvest` |
| `GET` | `/api/ssh/ca/info` | user | CA public key + fingerprint |
| `POST` | `/api/ssh/ca/issue` | **admin** | Sign a public key |
| `GET` | `/api/ssh/ca/issued` | user | Issuance audit |
| `GET` | `/api/ssh/zt/events` | user | Certificate auth events |
| `GET` | `/api/ssh/zt/status` | user | ZT posture summary |
| `GET` | `/api/ssh/zt/policy` | user | ZT principles and enforcement |

```jsonc
// GET /api/ssh/stats
{
  "total_connections": 3, "active": 1, "closed": 2,
  "pqc_enabled": 1, "pqc_coverage": 100.0,
  "total_bytes_sent": 14208, "total_bytes_received": 9112,
  "last_updated": "2026-07-29T14:23:11.482Z"
}
```

```jsonc
// GET /api/ssh/connections  →  one element
{
  "id": 7,
  "session_key": "192.168.1.6:41022->192.168.1.7:2222",
  "local_host": "192.168.1.6:41022", "remote_host": "192.168.1.7:2222",
  "remote_user": null,
  "kex_algorithm": "mlkem768x25519-sha256",
  "kem_label": "ML-KEM-768",
  "pqc_enabled": true, "state": "ACTIVE",
  "bytes_sent": 14208, "bytes_received": 9112,
  "established_at": "2026-07-29T14:19:02Z", "last_seen": "2026-07-29T14:23:11Z"
}
```

Note: `pqc_coverage` is computed over **ACTIVE** sessions only, so a closed
classical session does not drag the number down. `total_connections` counts all
rows ever recorded.

---

## 11. Data model

### `ssh_connections`

`session_key` (`"<local>-><peer>"`) is `UNIQUE` and is the upsert target. Indexed
on `state`, `pqc_enabled`, `last_seen DESC`.

`remote_user` is in the schema but the collector never populates it — `ss` does
not expose the SSH username, which is negotiated inside the encrypted channel.
The authenticated principal is available in the ZT audit instead.

### `zt_audit` (runtime-created)

Created by `ztaudit.py` at collector start, **not by a migration**. Migration 004
defines a different table, `zt_ssh_audit`, with a different schema (trust scores
and risk flags) that nothing currently writes. `zt_audit` is the live one.

`raw_hash` is `UNIQUE` — the deduplication key.

### `issued_certs` (runtime-created)

Created by `ca.py`. Records serial, identity, principals, validity, issuer and
expiry. Migration 004's `ssh_cert_audit` is a parallel unused definition.

### `ssh_policy_history` (runtime-created)

Created by `policy.py`. Drives rollback.

Full schema and the runtime-vs-migration divergence:
[DATA-MODEL.md](../DATA-MODEL.md#runtime-created-tables).

---

## 12. Operating notes

| Situation | What to check |
|---|---|
| `kex_algorithm: "unknown"` | Tier 1 and 3 both failed. Set `LogLevel DEBUG1`; add the backend user to `systemd-journal`. |
| A 2222 session shows classical | journald read failed and tier 3 returned the *system* sshd's KEX. Verify `journalctl -u ssh --since -5min \| grep "kex:"`. |
| No sessions at all | `ss -tnp state established \| grep -E ':(22\|2222)'`. If empty, there genuinely are none. |
| Sessions never close | The `CLOSED` sweep runs only when the collector completes a cycle. Check the collector is alive in `/health`. |
| Byte counters stuck at 0 | `ss -tin` output shape differs on some kernels. Cosmetic — KEX detection is unaffected. |
| Policy apply → `dev_mode: true` | `/opt/openssh-pqc/etc/sshd_config` absent. Build the PQC daemon ([SETUP.md §5](../SETUP.md#5-ssh-data-plane--openssh-with-pqc-key-exchange)). |
| Policy apply → 500 "sshd config invalid" | `sshd -t` rejected the rewrite. The daemon was **not** restarted — safe. Inspect the config. |
| Policy apply → 500 "sshd restart failed" | The daemon is now down. Restart manually: `bash vm-b/scripts/start-pqc-ssh.sh`. |
| Certificate rejected as expired immediately | Clock skew beyond the 1-hour backdate. Sync NTP on both hosts. |
| Certificate rejected: "principal" | The `-n` principals do not include the login user. Reissue with the right principal. |
| No ZT events | Wrong log path, or authentications happen on another host. Set `QUANSEQ_ZT_LOG` or `QUANSEQ_ZT_REMOTE`. |
| ZT events show `source_ip: "unknown"` | PID correlation failed on a standalone rejection — the log format differs from the expected `sshd-session[PID]` shape. |
| `ca_info` → 500 "CA not available" | `QUANSEQ_CA_KEY` path wrong, or the `.pub` is unreadable. |

---

*See also:* [IPSEC.md](IPSEC.md) · [TLS.md](TLS.md) · [SETUP.md](../SETUP.md) · [SECURITY.md](../SECURITY.md) · [API.md](../API.md)
