# QUANSEC Authentication

Access tokens, refresh-token rotation, scopes, and how the TLS module is
protected.

> **Scope note.** JWT authentication is an *application-layer* control. It is
> not post-quantum, and carrying it over hybrid TLS does not make it so. See
> [What is and is not post-quantum](#what-is-and-is-not-post-quantum).

---

## 1. Model

Two token types, with deliberately different designs.

| | Access token | Refresh token |
|---|---|---|
| Format | JWT, HS384 | 32 random bytes, opaque |
| Lifetime | 15 min (`ACCESS_TOKEN_TTL_MINUTES`) | 7 days (`REFRESH_TOKEN_TTL_DAYS`) |
| Stored server-side | No | Yes — SHA-256 hash only |
| Revocable | **No** | Yes |
| Sent as | `Authorization: Bearer …` | HttpOnly cookie (browser) or JSON body (scripts) |
| Browser storage | In memory only | Cookie, unreadable by script |

Access tokens are stateless and **cannot be withdrawn before they expire**. That
is why they last 15 minutes and why revocation bites at the refresh layer. After
a `revoke-all`, an already-issued access token stays usable for up to 15 more
minutes; the API says so in its response rather than implying an instant
cut-off.

Refresh tokens are not JWTs. They need server-side state to be revocable at
all, and once state is required a self-describing signed token buys nothing.

---

## 2. Environment variables

All authentication settings come from the environment. **There are no defaults
for secrets** — `core/config.py` raises at import if `JWT_SECRET` is missing,
placeholder, or under 48 bytes, because a secret compiled into source is a
published key.

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | *(none — required)* | HS384 signing secret, ≥48 bytes (96 hex chars) |
| `JWT_ISSUER` | `quansec` | `iss` claim, verified on every request |
| `JWT_AUDIENCE` | `quansec-api` | `aud` claim, verified on every request |
| `ACCESS_TOKEN_TTL_MINUTES` | `15` | Access-token lifetime |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | Refresh-token lifetime |
| `AUTH_COOKIE_SECURE` | `true` | `false` **only** for local HTTP dev |
| `AUTH_COOKIE_SAMESITE` | `lax` | SameSite attribute |
| `REFRESH_COOKIE_NAME` | `quansec_refresh` | Refresh cookie name |
| `REFRESH_COOKIE_PATH` | `/api/auth` | Cookie path — never sent to protocol APIs |
| `CSRF_COOKIE_NAME` | `quansec_csrf` | Readable double-submit cookie |
| `CSRF_HEADER_NAME` | `X-CSRF-Token` | Header echoing that cookie |
| `LOGIN_RATE_LIMIT` | `10` | Attempts per window, per IP+email |
| `LOGIN_RATE_WINDOW_SECONDS` | `300` | Window length |
| `LOGIN_LOCKOUT_SECONDS` | `900` | Lockout after the limit is passed |
| `REFRESH_RATE_LIMIT` | `60` | Refreshes per window, per IP |
| `TRUSTED_PROXY` | `false` | Honour `X-Forwarded-For`. Enable **only** behind a proxy |
| `ADMIN_PASSWORD` | *(none)* | Read by `seed_admin.py` |

`JWT_ALGORITHM` is **not** an environment variable. It is pinned to HS384 in
code: an attacker who can influence the verification algorithm can strip the
signature entirely (`alg=none`) or force HMAC verification against a public key.

### Generating the secret

```bash
python3 -c "import secrets; print(secrets.token_hex(48))"
```

Put it in `quansec/.env` as `JWT_SECRET=…`. `.env` is git-ignored. Rotating the
secret invalidates every session; users log in again.

---

## 3. Setup

```bash
cd quansec

# 1. Dependencies (Argon2id support is new)
.venv/bin/pip install -r requirements.txt

# 2. Secret, if not already set
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(48))" >> .env

# 3. Migrations — applied automatically at startup, or manually:
python3 - <<'EOF'
import asyncio, asyncpg, os, pathlib
from dotenv import load_dotenv; load_dotenv()
async def main():
    conn = await asyncpg.connect(os.getenv("DATABASE_URL"))
    for path in sorted(pathlib.Path("migrations").glob("*.sql")):
        await conn.execute(path.read_text())
        print("applied", path.name)
    await conn.close()
asyncio.run(main())
EOF

# 4. Initial administrator
ADMIN_PASSWORD='<a strong password>' .venv/bin/python seed_admin.py

# 5. Run
.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Migration `008_auth_tokens.sql` creates `refresh_tokens` and `auth_throttle`,
and adds `ip_address` / `user_agent` to `audit_events`. It is idempotent.

**No table is created at runtime.** Schema changes are migrations.

---

## 4. Scope matrix

Scopes are derived from `users.role` and `users.portal` **on the server**.
Nothing a client sends contributes to them — `scopes_for()` in `core/scopes.py`
takes no request input at all.

### Vocabulary

| Scope | Grants |
|---|---|
| `tls:read` | TLS status, sessions, events, policy, readiness |
| `tls:admin` | Policy changes, service control, probes, downgrade tests, certificates |
| `ssh:read` | SSH status, connections, handshakes |
| `ssh:admin` | SSH policy and certificate issuance |
| `ipsec:read` | IPsec status, tunnels, events |
| `ipsec:admin` | IPsec policy and attack simulations |
| `system:admin` | Everything, including user management |

### Role → scope

| Role | Portal | Scopes granted |
|---|---|---|
| `admin` | any | `system:admin` (implies all) |
| `operator` | `main` | `tls:read`, `ssh:read`, `ipsec:read` |
| `operator` | `tls` | above **+ `tls:admin`** |
| `operator` | `ssh` | above **+ `ssh:admin`** |
| `operator` | `ipsec` | above **+ `ipsec:admin`** |
| *(unknown)* | any | **none** — fails closed |

Implication runs one way only: `tls:admin` satisfies a `tls:read` check;
`tls:read` **never** satisfies a `tls:admin` check.

An operator gets read access to all three modules because the cross-protocol
dashboard views need it, and because the pre-existing `require_user` dependency
already allowed exactly that. Narrowing it would revoke access SSH and IPsec
users have today.

### TLS endpoint protection

| Endpoint | Required |
|---|---|
| `GET /api/tls/status` | `tls:read` |
| `GET /api/tls/readiness` | `tls:read` |
| `GET /api/tls/sessions`, `/sessions/{id}` | `tls:read` |
| `GET /api/tls/events` | `tls:read` |
| `GET /api/tls/policy` | `tls:read` |
| `GET /api/tls/certificate` | `tls:read` |
| `GET /api/tls/signature-algorithms` | `tls:read` |
| `POST /api/tls/policy/apply` | **`tls:admin`** |
| `POST /api/tls/service/{start,stop,reload}` | **`tls:admin`** |
| `POST /api/tls/probe` | **`tls:admin`** |
| `POST /api/tls/tests/hybrid-downgrade` | **`tls:admin`** |
| `POST /api/tls/tests/tls12-downgrade` | **`tls:admin`** |
| `POST /api/tls/tests/cipher-downgrade` | **`tls:admin`** |
| `GET /api/tls/dataplane/echo` | **none** — see below |

`/dataplane/echo` is the one unauthenticated TLS route. It is reachable only
through the NGINX endpoint on `127.0.0.1:8443` and is what the positive
enforcement probe connects to. An `openssl s_client` handshake has no bearer
token to present, so requiring one would make the enforcement test impossible.
It returns only what NGINX observed about the caller's own connection.

---

## 5. Login and refresh flow

### Browser

```
POST /api/auth/login?use_cookie=true
  → 200 { access_token, expires_in, scopes, csrf_token, refresh_token: null }
  → Set-Cookie: quansec_refresh=…; HttpOnly; Secure; SameSite=Lax; Path=/api/auth
  → Set-Cookie: quansec_csrf=…;    Secure; SameSite=Lax; Path=/api/auth
```

The refresh token is **absent from the body** — a response body is readable by
JavaScript, which would defeat `HttpOnly`.

When the access token expires, the client calls:

```
POST /api/auth/refresh
  Cookie: quansec_refresh=…
  X-CSRF-Token: <value of the quansec_csrf cookie>
  → 200 { access_token, … } + a rotated refresh cookie
```

### Script / CLI

```bash
# use_cookie=false returns the refresh token in the body
curl -X POST 'http://127.0.0.1:8000/api/auth/login?use_cookie=false' \
     -d 'username=admin@quansec.io&password=…'

curl -X POST http://127.0.0.1:8000/api/auth/refresh \
     -H 'Content-Type: application/json' \
     -d '{"refresh_token":"…"}'
```

Body-token clients are exempt from CSRF: they are not relying on an ambient
browser credential, so there is nothing to forge.

### Endpoints

| Route | Auth required | Notes |
|---|---|---|
| `POST /api/auth/login` | none | Throttled on IP+email |
| `POST /api/auth/login-scoped?portal=` | none | Portal-restricted |
| `POST /api/auth/refresh` | refresh token | Rotates; CSRF on the cookie path |
| `POST /api/auth/logout` | refresh token | **No access token needed** |
| `POST /api/auth/revoke-all` | access token | All sessions, all devices |
| `GET /api/auth/me` | access token | Identity + scopes |
| `GET /api/auth/sessions` | access token | Live sessions, no token material |
| `GET /api/auth/scopes` | access token | The matrix above |

`logout` deliberately does not require an access token: a user whose access
token already expired must still be able to log out, or the refresh token stays
live for its full 7 days.

---

## 6. Token rotation and theft detection

Every login opens a **family**. Each refresh rotates the current token and links
the successor to its parent:

```
login → t1 → t2 → t3        (t1, t2 rotated; t3 current)
```

A rotated token is **single-use**. If `t2` is presented again after `t3` exists,
the only explanations are theft or a cloned client — and the response is to
**revoke the entire family**, including the `t3` the legitimate user holds.

Both parties are logged out. That is intended: from the server they are
indistinguishable, and the safe reading is that the chain is compromised. The
real user logs in again; the thief cannot. The event is recorded as
`auth.refresh.reuse_detected` at **critical** severity — the one event in this
module that means an active attacker rather than a mistyped password.

Reuse in one family does not affect a user's other families, so a compromise in
one session does not sign them out everywhere.

**Client note:** never issue two refreshes concurrently. The second would
present an already-rotated token and trip the detector. `QuansecClient.refresh()`
de-duplicates in-flight refreshes for this reason.

---

## 7. Storage and hashing

- Refresh tokens: **SHA-256 hash only**. The raw value exists in the response
  and the client, never in the database or a log. Plain SHA-256 rather than
  Argon2 because a 256-bit random value has no dictionary to slow down.
- Passwords: **Argon2id** (19 MiB, t=2, p=1 — OWASP), via the existing
  `core.auth` password utility.
- **Legacy hashes still work.** Existing accounts are `pbkdf2_sha256`; passlib
  keeps `pbkdf2_sha256` and `bcrypt` as deprecated-but-verifiable schemes, and
  each hash is rewritten to Argon2id on its owner's next successful login — the
  one moment the plaintext is available. Dropping them would have locked every
  current user out permanently.

---

## 8. Audit events

Recorded to `audit_events` with `resource = 'auth'`. **No token material is ever
written** — sessions are identified by `jti`, `token_id` and `family_id`, and a
recursive scrubber redacts anything key-like that reaches the detail payload.

| Action | Severity |
|---|---|
| `auth.login.success` | info |
| `auth.login.failure` | warning |
| `auth.login.throttled` | warning |
| `auth.token.refresh` | info |
| `auth.logout` | info |
| `auth.session.revoke_all` | warning |
| `auth.token.expired` | info |
| `auth.token.invalid` | warning |
| `auth.scope.denied` | warning |
| `auth.csrf.failure` | warning |
| **`auth.refresh.reuse_detected`** | **critical** |

---

## 9. Rejected tokens

`core/tokens.py` rejects, and audits:

- `alg=none` and any algorithm other than HS384 (pinned allow-list)
- Wrong signing key
- Invalid `iss` or `aud`
- Expired tokens
- Malformed / non-JWT input
- Missing any of `sub, role, scopes, portal, iat, exp, iss, aud, jti`
- Wrong token type (`typ != "access"`)

The client always receives the same generic message. Distinguishing "expired"
from "bad signature" tells an attacker which half of a forgery worked; the
specific reason goes to the audit log.

---

## 10. Frontend migration

**Before:** the access token was written to `localStorage["quansec_token"]` and
read directly by 12 pages.

**After:**

- The access token lives **in memory** on the `quansec` client singleton.
- The refresh token is an **HttpOnly cookie** — unreadable by script.
- `QuansecClient.restore()` silently exchanges the refresh cookie for a new
  access token on page load, so a reload does not log the user out.
- Requests retry once after a silent refresh on 401, making the 15-minute
  expiry invisible.
- Pages now import `authHeaders()` from `src/lib/auth-fetch.ts` instead of
  defining their own storage-reading helper.
- Any legacy `quansec_token` value found in `localStorage` is **purged** —
  leaving it would preserve the exposure this change closes.

Rationale: `localStorage` is readable by any script on the origin, so one XSS
bug yields a credential that survives reloads. An in-memory token dies with the
tab; an HttpOnly cookie cannot be read even while a payload is executing.

---

## 11. Local development

```bash
# Backend
cd quansec
AUTH_COOKIE_SECURE=false .venv/bin/uvicorn main:app --port 8000

# Frontend
cd quansec-ui && npm run dev        # http://localhost:3000
```

`AUTH_COOKIE_SECURE=false` is required over plain HTTP: browsers silently drop
a `Secure` cookie on `http://localhost`, and login would appear to succeed while
every refresh failed. **Set it back to `true` anywhere reachable over a
network.**

### Tests

```bash
cd quansec
.venv/bin/python -m pytest tests/test_auth_tokens.py tests/test_auth_api.py -q
```

`test_auth_tokens.py` covers the primitives (scope mapping, JWT verification,
rotation, reuse detection, password hashing). `test_auth_api.py` drives the real
HTTP routes with authentication fully enabled.

---

## What is and is not post-quantum

These are independent and must be reported separately. A claim about one is not
a claim about another.

| Layer | Mechanism | Post-quantum? |
|---|---|---|
| **Transport** | X25519MLKEM768 hybrid TLS 1.3 | **Yes** — hybrid PQ key establishment |
| **Application authentication** | JWT, HS384 | **No** — a classical MAC |
| **Certificate authentication** | RSA / ECDSA X.509 | **No** — classical signatures |

A JWT carried over hybrid TLS is **not** post-quantum authentication. The
transport protects the token in flight; the token itself is a symmetric-MAC
credential verified by this backend, and its security properties are unchanged
by how it travelled.

Likewise, X25519MLKEM768 makes the *key exchange* hybrid post-quantum while an
RSA or ECDSA certificate leaves *authentication* classical. The platform reports
this as:

> **Hybrid post-quantum TLS with classical X.509 authentication**

ML-DSA certificate authentication is under investigation and is **not** claimed
until OpenSSL lists the algorithm, a certificate is generated, NGINX loads it, a
client completes the handshake, and invalid signatures are rejected.
