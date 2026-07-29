# Security

The platform's own security posture — authentication, authorisation, secret
handling, threat model, and what must be fixed before production.

> QUANSEC manages cryptographic policy on live systems. Compromising it means
> being able to downgrade every tunnel and session it controls. It is a
> high-value target and must be treated as one.

- [1. Authentication](#1-authentication)
- [2. Authorisation](#2-authorisation)
- [3. Secrets](#3-secrets)
- [4. Input handling](#4-input-handling)
- [5. Privilege and the data plane](#5-privilege-and-the-data-plane)
- [6. Transport](#6-transport)
- [7. Audit](#7-audit)
- [8. Threat model](#8-threat-model)
- [9. Known issues](#9-known-issues)
- [10. Hardening checklist](#10-hardening-checklist)

---

## 1. Authentication

### 1.1 Passwords

passlib `CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")`.

PBKDF2-SHA256 is FIPS 140-approved, which is consistent with a platform whose
premise is NIST standards compliance. Argon2id is stronger against GPU attack and
would be the better choice absent the FIPS consideration; `deprecated="auto"`
means adding it later re-hashes existing passwords transparently on next login.

`verify_password` catches all exceptions and returns `False`, so a malformed hash
in the database is an auth failure rather than a 500.

**No password policy is enforced.** No minimum length, complexity or rotation.
`seed_admin.py` defaults to `CHANGE_ME` when `ADMIN_PASSWORD` is unset, and
`setup_backend.sh` defaults to `Admin@QuanSec2024!`. Both are printed to the
terminal on completion. Change them.

### 1.2 JWT

HS256, 24-hour expiry, claims `{sub, email, role, exp, iat}`.

Verification decodes the signature and then **re-reads the user from the
database**:

```python
payload = decode_token(token)
row = await conn.fetchrow("SELECT id, email, role, created_at FROM users WHERE id = $1", int(user_id))
if not row:
    raise HTTPException(401, "User no longer exists")
```

This costs one indexed query per request and buys real security: a deleted user's
token stops working immediately, and the `role` used for authorisation is the
*current* role, not the role at issuance. A user demoted from admin loses admin
access on their next request rather than 24 hours later.

**What JWT does not give you:** revocation. A stolen token is valid until it
expires. Mitigations are a shorter `JWT_EXPIRE_HOURS` or a token blocklist;
neither is implemented.

`JWT_SECRET` defaults to `change-this-in-production`. With that default, anyone
can mint an admin token. `setup_backend.sh` generates a random 32-byte secret on
first run — verify it did.

### 1.3 API keys

```python
raw       = secrets.token_urlsafe(32)     # 256 bits from the OS CSPRNG
full_key  = f"qsk_live_{raw}"
key_hash  = hashlib.sha256(full_key.encode()).hexdigest()
```

Only the hash is stored. The raw key is returned once, at creation, with a
warning. A database dump therefore yields no usable credentials.

Unsalted SHA-256 is correct here and would be wrong for a password: the key is
256 bits of CSPRNG entropy, so there is no dictionary to attack and no rainbow
table to build, and lookup-by-hash requires a deterministic digest.

Revocation is a row update and takes effect on the next request. Keys are
scoped to their creating user and cannot be revoked by anyone else.

**`scopes` is not enforced.** A key with `["read"]` has exactly the same access as
its owning user, including admin endpoints if that user is an admin. Treat the
field as documentation of intent. Until it is enforced, **create API keys under
an operator account, never an admin account.**

### 1.4 Frontend token storage

The JWT is held in memory and mirrored to `localStorage` so a page refresh
survives.

`localStorage` is readable by any JavaScript on the origin, so an XSS
vulnerability yields the token. The alternative — an `HttpOnly` cookie — is
immune to that but requires CSRF protection and does not fit the bearer-token
API. Given that the portals render no user-supplied HTML and React escapes by
default, the XSS surface is small. It remains the weakest link in the client.

---

## 2. Authorisation

### 2.1 Roles

| Role | Scope |
|---|---|
| `operator` | Read everything, run attack simulations, acknowledge alerts, manage own API keys |
| `admin` | The above, plus policy apply/rollback, certificate issuance, fail-mode, user management |

The rule: **anything that changes the security posture of a live system, or mints
a credential, is admin-only.**

Enforced by dependency:

```python
async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Admin privileges required")
    return user
```

`role` comes from the fresh database read, not the token claim.

### 2.2 Admin-only endpoints

| Endpoint | Why |
|---|---|
| `POST /api/ipsec/policies/apply` | Rewrites `swanctl.conf`, reloads charon |
| `POST /api/ssh/policies/apply` | Rewrites `sshd_config`, restarts sshd |
| `POST /api/ssh/policies/rollback` | Same, via a prior policy |
| `POST /api/ssh/ca/issue` | Mints an access credential |
| `POST /api/failmode/set` | Declares downgrade tolerance |
| `POST /api/auth/register` | Creates users |
| `GET /api/auth/users` | Enumerates users |

Attack simulations are deliberately `require_user`: they read state and write an
audit row, but never touch a live tunnel.

### 2.3 Portal scoping

`users.portal` plus `/api/auth/login-scoped?portal=…` gives coarse tenancy: a
user scoped to `ssh` cannot log into the IPsec portal. `main` is the superuser
portal and admins bypass entirely.

**This is a login-time check only.** Once a token is issued it grants access to
every API endpoint regardless of portal — an SSH-portal user with a valid token
can call `/api/ipsec/*` directly. Portal scoping is UI segregation, **not a
security boundary.** Do not rely on it for multi-tenancy.

---

## 3. Secrets

### 3.1 What is in the repository

`.gitignore` excludes `.env`, `*.pem`, `*_key`, `*_key.pub`, `*-cert.pub`,
`id_ed25519*`, `id_rsa*`, `quansec_ca`, `quansec_ca.pub`, `known_hosts`.

**Committed values that must be changed:**

| Location | Value | Action |
|---|---|---|
| `quansec/two-vm-configs/vm-a-swanctl.conf` | `secret = quansec-shared-key-2026` | Replace with a high-entropy PSK |
| `vm-b/swanctl/swanctl.conf` | `secret = YOUR_IPSEC_PSK_HERE` | Placeholder — replace |
| `quansec/strongswan/swanctl.conf` | `secret = "change-this-psk-in-production"` | Template — replace |
| `core/config.py` | `JWT_SECRET` default `change-this-in-production` | Set in `.env` |
| `core/config.py` | `DATABASE_URL` default password `CHANGE_ME` | Set in `.env` |
| `setup_backend.sh` | `ADMIN_PASSWORD` default `Admin@QuanSec2024!` | Set in `.env` |
| `provision_postgres.sh` | `DB_PASS="quansec_secret"` | Change before use |
| `seed_admin.py` | `ADMIN_PASSWORD` default `CHANGE_ME` | Pass via env |

The IPsec PSKs are the most serious: a committed pre-shared key means anyone with
repository access can impersonate a tunnel endpoint. **Rotate them before any
non-lab deployment**, and prefer `auth = pubkey` with X.509 over PSK.

### 3.2 The CA private key

`~/quansec-ca/quansec_ca`, unencrypted, mode 600.

**This key can mint SSH access to every server trusting the CA.** It is the
highest-value secret in the system. Production options, in increasing order of
assurance: a passphrase with `ssh-agent`; a dedicated signing host the API calls
out to; an HSM or a KMS with an SSH-signing integration.

### 3.3 Secret handling in code

Good:

- Passwords are hashed before storage and never logged.
- The raw API key exists only in the creation response.
- The CA private key is never read by the application — `ssh-keygen -s` reads it.
- Public keys are written to a `TemporaryDirectory` and removed on request exit.

Watch:

- `setup_backend.sh` prints the admin password to the terminal on completion,
  where it lands in shell history and CI logs.
- `SWANCTL_TEMPLATE` in `protocols/ipsec/policy.py` contains a literal
  `${IPSEC_PSK}` that is **not** expanded by Python and is not expanded by
  StrongSwan either. A generated config is a template that still needs its secret
  filled in — do not assume the written file is loadable.

---

## 4. Input handling

### 4.1 SQL

Every query uses asyncpg's `$1` positional parameters, which are server-side
prepared. **Injection is structurally impossible on a parameterised query.**

Two places build SQL by string interpolation:

```python
# protocols/ipsec/router.py — list_tunnels
where = "WHERE " + " AND ".join(where_clauses)   # clauses are literals + $n
rows  = await conn.fetch(f"SELECT * FROM ipsec_tunnels {where} "
                         f"ORDER BY last_seen DESC LIMIT ${i} OFFSET ${i+1}", *args)
```

What is interpolated: generated `$n` placeholders and integer indices. What is
**not** interpolated: any user value — those go through `args`. The pattern is
safe as written, and it is the pattern to review most carefully in any change.
Adding a `?sort=` parameter that interpolated a column name would break it.

`list_events` and `handshake_stages` follow the same shape with the same
constraint.

### 4.2 Subprocess

Every `subprocess.run` uses an argument list, never `shell=True`:

```python
subprocess.run(["ssh-keygen", "-s", CA_KEY, "-I", req.identity,
                "-n", req.principals, "-V", f"-1h:+{req.valid_hours}h",
                "-z", str(serial), pub_path],
               capture_output=True, text=True, timeout=15)
```

No shell means no metacharacter interpretation, so `identity` and `principals`
cannot inject a command. Every call has an explicit timeout.

**`identity` and `principals` are not otherwise validated.** They are written into
the certificate as-is. A principal string containing a comma creates multiple
principals — which is `ssh-keygen`'s documented behaviour, not an injection, but
it means an admin could grant broader access than intended by typo. Validate them
against a character allow-list.

### 4.3 SSH public key validation

```python
PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S+)?\s*$")
```

Anchored at both ends, so multi-line input is rejected — a submission cannot
smuggle a second key or shell content past it. The explicit `"PRIVATE KEY"` check
produces a clear error for the user who pastes the wrong file.

### 4.4 Pydantic

Request bodies are validated by Pydantic models before a handler runs.
`valid_hours: int = Field(8, ge=1, le=168)` makes an out-of-range validity a 422,
not a 168-year certificate.

### 4.5 Log parsing

Both log parsers use anchored regexes with named groups and discard
non-matching lines. Values extracted from logs are stored as data, never
executed. The ZT parser additionally filters `COMMAND=`, `sudo:` and `CRON[`
lines to avoid recording its own activity.

---

## 5. Privilege and the data plane

The policy engines are the most dangerous code in the platform: they write system
configuration and restart daemons.

### 5.1 What they need

| Operation | Privilege |
|---|---|
| Write `/etc/swanctl/swanctl.conf` | File ownership, or root |
| `swanctl --load-all` | `sudo` |
| Write `/opt/openssh-pqc/etc/sshd_config` | `sudo tee` |
| `sshd -t` / `pkill` / restart `sshd` | `sudo` |
| Read `/var/run/charon.vici` | Socket group membership |
| Read journald | `systemd-journal` group |

### 5.2 Scoping it

Never run the backend as root. Use a dedicated service account with narrow
`sudoers` entries ([SETUP.md §9](SETUP.md#9-privilege-configuration)).

Each entry is a full root-equivalent primitive if its argument can be influenced.
The `sudo tee /opt/openssh-pqc/etc/sshd_config` rule is only safe because the
path is a fixed constant in the code — a version that took the path from a
request would be a root-write-anywhere vulnerability. **Keep those paths as
module-level constants.**

### 5.3 Dev mode is a silent no-op

Without the daemon present, both engines write to `/tmp/quansec/` and return
`dev_mode: true`. This is deliberate — it makes the platform demonstrable — but
it means **a policy apply can succeed without changing anything.**

Any automation calling `/policies/apply` must check `dev_mode` in the response
and treat `true` as a failure to enforce.

### 5.4 Validate before restart

The SSH engine runs `sshd -t` and aborts on failure *before* touching the running
daemon, so a malformed config produces an HTTP 500 rather than a dead listener.

The IPsec engine does **not** validate before `swanctl --load-all`, and it treats
a missing "successfully loaded" string as a warning rather than an error. A bad
config is logged and the endpoint still returns `status: applied`. Adding a
`swanctl --load-all --dry-run`-equivalent check would bring it to parity.

---

## 6. Transport

### 6.1 HTTP

The application serves plain HTTP. **Bearer tokens over plain HTTP are readable
by anyone on the path.** Put it behind TLS-terminating nginx or Caddy before any
non-loopback use.

### 6.2 CORS

```python
allow_origins=["http://localhost:3000", "https://localhost:443"]
allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
```

Origins are explicitly listed rather than wildcarded, which is correct. Update
them for a real deployment; do not replace them with `["*"]`, which
`allow_credentials=True` makes especially dangerous.

### 6.3 WebSocket

`/api/ws/live` performs **no authentication**. Anyone who can reach the port can
subscribe.

What leaks: tunnel names, endpoint IPs, negotiated algorithms, PQC status,
lifecycle transitions. No credentials, no keys, no traffic content — but a
reconnaissance-grade map of your crypto posture, including the moment a tunnel
goes classical.

Fix: accept a token as a query parameter or first frame and validate before
subscribing.

```python
@router.websocket("/api/ws/live")
async def websocket_live(websocket: WebSocket, token: str = Query(...)):
    try:
        decode_token(token)
    except HTTPException:
        await websocket.close(code=1008)
        return
    await websocket.accept()
```

There is also a cleanup bug: if the initial Redis connection raises, the
`finally` block references `pubsub` and `redis` before assignment, and
`connected_clients.remove(websocket)` raises `ValueError` if the socket was
already removed.

### 6.4 `/metrics`

Unauthenticated by design — Prometheus scrapers do not carry bearer tokens.
Exposes counts and coverage percentages only; no identities, hosts or keys.

Restrict it at the network layer:

```nginx
location /metrics {
    allow 10.0.0.0/8;
    deny all;
    proxy_pass http://127.0.0.1:8000;
}
```

---

## 7. Audit

`audit_events` records privileged actions with actor, action, resource, detail and
severity: logins, user creation, policy applies, fail-mode changes, certificate
issuance, API key creation and revocation, attack simulations.

Exported to SIEM via `/api/siem/events` in CEF, syslog or JSON.

Three gaps:

1. **The SIEM export does not include audit events.** The query selects
   `created_at`; the column is `occurred_at`. It fails silently at DEBUG level and
   the export returns only Zero Trust events. One-word fix in
   `protocols/siem/router.py`.
2. **`detail` is a `TEXT` column built with f-strings**, not `JSONB`. Not
   queryable as JSON, and a value containing a quote would produce malformed
   JSON. All current values are controlled identifiers.
3. **Reads are not audited.** Only mutations are recorded. Someone with a valid
   operator token can enumerate every tunnel, session and certificate without
   leaving a trace.

---

## 8. Threat model

### 8.1 Attacker: stolen operator token

**Can:** read the full crypto posture, run attack simulations, acknowledge alerts
(hiding a real downgrade), create API keys under that account.

**Cannot:** change policy, issue certificates, create users.

**Detection:** API key creation is audited. Alert acknowledgement is not.

**Mitigation:** short `JWT_EXPIRE_HOURS`; audit alert acknowledgement.

### 8.2 Attacker: stolen admin token

**Can:** downgrade every tunnel and session to classical crypto, issue themselves
SSH certificates for any principal, set fail-open, create admin users.

This is total compromise of the managed estate. Every action is audited, but the
attacker can create the certificates before anyone reads the log.

**Mitigation:** treat admin credentials like root; separate admin from operator
accounts; alert on `cert_issued` and `policy_apply` in the SIEM; require MFA
(not implemented).

### 8.3 Attacker: database read access

**Gets:** password hashes (PBKDF2, expensive to crack), API key hashes (256-bit
preimages, effectively uncrackable), the full audit trail, and the complete crypto
topology.

**Does not get:** any usable credential.

The hashing design holds up here — a database dump alone yields nothing directly
usable.

### 8.4 Attacker: host access as the backend user

**Gets:** `.env` (JWT secret, database password), the CA private key if it is
readable, and every `sudoers` primitive the account holds.

The `sudoers` entries are the escalation path. `sudo tee <fixed path>` plus
`sudo sshd -f <that path>` is arbitrary root code execution *if* the attacker can
also influence the file content — which they can, since they are the backend
user. **Host compromise of the backend account is effectively root on that host.**

**Mitigation:** run the backend on a host that does not also terminate tunnels;
keep the CA key on a separate signing host or in an HSM.

### 8.5 Attacker: on-path network

**Without TLS:** reads bearer tokens, reads and modifies API responses, subscribes
to the WebSocket.

**With TLS:** the WebSocket remains unauthenticated but is encrypted; `/metrics`
remains unauthenticated.

**Mitigation:** TLS everywhere; authenticate the WebSocket; firewall `/metrics`.

### 8.6 Not in scope

QUANSEC does not defend the *managed* protocols against attack — StrongSwan and
sshd do that. It observes and configures them. A compromise of QUANSEC leads to a
downgrade of those protocols, which is why it is a high-value target.

---

## 9. Known issues

Ordered by severity.

| # | Issue | Impact | Fix |
|---|---|---|---|
| 1 | Default `JWT_SECRET` is `change-this-in-production` | Anyone can forge an admin token | Set it in `.env`; `setup_backend.sh` generates one |
| 2 | IPsec PSKs committed to the repository | Tunnel impersonation | Rotate; move to X.509 |
| 3 | WebSocket unauthenticated | Crypto posture reconnaissance | Validate a token before subscribe |
| 4 | API key `scopes` not enforced | A `read` key has full owner privilege | Enforce in `get_current_user`, or create keys only under operator accounts |
| 5 | Portal scoping is login-time only | Not a tenancy boundary | Enforce per request, or document as UI-only |
| 6 | No TLS by default | Token interception | Terminate TLS at a reverse proxy |
| 7 | CA private key unencrypted on disk | Full SSH access to trusting servers | Passphrase + agent, or HSM |
| 8 | SIEM omits audit events (`created_at` vs `occurred_at`) | Incomplete SIEM record | One-word fix |
| 9 | Dev mode returns success without enforcing | Automation may believe a policy applied | Check `dev_mode` in callers |
| 10 | IPsec policy apply does not validate before reload | A bad config is applied and reported as success | Validate first, like the SSH engine |
| 11 | No password policy | Weak admin passwords | Enforce minimum length and complexity |
| 12 | `audit_events.detail` is f-string JSON in a `TEXT` column | Malformed JSON on a quote in a value | Use `JSONB` and `json.dumps` |
| 13 | Reads are not audited | Silent reconnaissance with a valid token | Log read access to sensitive endpoints |
| 14 | Cert serial allocation races | Duplicate serials break revocation by serial | Use a sequence |
| 15 | `StrictHostKeyChecking=no` in the ZT remote fetch | MITM on the audit channel | Pin the host key |
| 16 | WebSocket cleanup references possibly-unbound names | `NameError`/`ValueError` in the error path | Initialise before the `try` |

---

## 10. Hardening checklist

**Before any non-lab deployment:**

- [ ] `JWT_SECRET` set to 32+ random bytes in `.env`
- [ ] Admin password changed from every default; `ADMIN_PASSWORD` not left in shell history
- [ ] Database password changed from `quansec_secret` / `CHANGE_ME`
- [ ] IPsec PSKs rotated in **all three** config files
- [ ] `.env` is mode 600 and not committed
- [ ] TLS terminated in front of the API; HTTP redirected
- [ ] `allow_origins` updated to the real UI origin
- [ ] `/metrics` restricted by network ACL
- [ ] Backend runs as a dedicated non-root service account
- [ ] `sudoers` entries scoped to exact commands with fixed paths
- [ ] CA private key passphrase-protected or moved to an HSM
- [ ] API keys created under operator accounts, never admin
- [ ] WebSocket authentication implemented, or the port firewalled

**Operationally:**

- [ ] `audit_events` shipped to a SIEM and alerted on `policy_apply` and `cert_issued`
- [ ] `/health.collectors` monitored for length, not just `status`
- [ ] Certificate validity kept short (8 h default) — it is the revocation mechanism
- [ ] Retention policy applied to `ipsec_events`, `zt_audit`, `ssh_connections`
- [ ] `JWT_EXPIRE_HOURS` reduced from 24 if the threat model warrants it
- [ ] Dependencies patched — `pip list --outdated`, `npm audit`

---

*See also:* [SETUP.md §9](SETUP.md#9-privilege-configuration) · [OPERATIONS.md](OPERATIONS.md) · [API.md](API.md) · [DATA-MODEL.md](DATA-MODEL.md)
