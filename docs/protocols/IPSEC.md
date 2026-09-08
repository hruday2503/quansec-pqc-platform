# IPsec module

Post-quantum IKEv2 with ML-KEM-1024, monitored through StrongSwan's VICI socket.

**Status:** live · **KEM:** ML-KEM-1024 (pure) · **NIST level:** 5 · **CNSA 2.0 deadline:** 2033

- [1. What this module does](#1-what-this-module-does)
- [2. Files](#2-files)
- [3. Cryptographic design](#3-cryptographic-design)
- [4. The ML-KEM StrongSwan plugin](#4-the-ml-kem-strongswan-plugin)
- [5. The VICI client](#5-the-vici-client)
- [6. PQC classification](#6-pqc-classification)
- [7. The collector](#7-the-collector)
- [8. The lifecycle event listener](#8-the-lifecycle-event-listener)
- [9. The policy engine](#9-the-policy-engine)
- [10. The attack lab](#10-the-attack-lab)
- [11. API reference](#11-api-reference)
- [12. Data model](#12-data-model)
- [13. Operating notes](#13-operating-notes)

---

## 1. What this module does

```
StrongSwan charon ──VICI poll (5 s)──► collector ──► ipsec_tunnels ──► REST ──► portal
        │                                                                          ▲
        └──VICI event subscription──► event listener ──► ipsec_events ──► Redis ──► WS
                                                                    quansec:live
policy engine ──writes /etc/swanctl/swanctl.conf──► swanctl --load-all ──► charon
```

Five responsibilities:

1. **Discover** every IKE_SA and CHILD_SA and record the negotiated proposal.
2. **Classify** each tunnel as PQC or classical from the *negotiated* algorithms.
3. **Stream** lifecycle transitions to the dashboard in near-real time.
4. **Enforce** a chosen policy by rewriting the StrongSwan config and reloading it.
5. **Prove** the difference by running attacks against whichever policy is live.

---

## 2. Files

| File | Lines | Responsibility |
|---|---|---|
| `vici_client.py` | 137 | VICI socket wrapper, byte decoding, SA normalisation, PQC detection |
| `collector.py` | 216 | 5-second poll loop, upsert, stale detection, Redis publish |
| `events.py` | 166 | VICI event subscription via a thread bridge, event classification |
| `router.py` | 254 | Tunnels, stats, events, handshakes, manual seed, manual refresh |
| `policy.py` | 159 | Three policies, swanctl config generation, daemon reload, comparison |
| `attacks.py` | 378 | Downgrade, Shor, harvest-now-decrypt-later, Pollard's rho, ML-KEM resistance |
| `websocket.py` | 71 | `/api/ws/live` — Redis subscribe → WebSocket fan-out |
| `models.py` | 53 | `TunnelOut`, `TunnelCreate`, `IPsecStats`, `IPsecEvent` |

---

## 3. Cryptographic design

### 3.1 The proposal

```
proposals     = aes256-sha256-mlkem1024      # IKE  (control channel)
esp_proposals = aes256-sha256                # ESP  (data channel)
```

| Component | Algorithm | Quantum-safe? | Why |
|---|---|---|---|
| Key exchange | **ML-KEM-1024** | ✅ | The only broken part of classical IPsec. FIPS 203, NIST Level 5, CNSA 2.0. |
| Encryption | AES-256-CBC | ✅ | Grover halves it to 128-bit effective — still adequate |
| Integrity / PRF | HMAC-SHA2-256 | ✅ | Grover halves preimage resistance to 128-bit — adequate |
| Authentication | PSK (lab) / X.509 (production) | ⚠️ classical | See below |

### 3.2 Why only the key exchange changes

Shor's algorithm solves the hidden subgroup problem over abelian groups in
polynomial time, which is exactly what ECDH and DH security reduce to. It has no
bearing on AES or SHA-2.

Grover's algorithm gives a quadratic speedup on unstructured search, reducing an
n-bit symmetric key to n/2-bit effective strength. AES-256 → 128-bit effective is
fine; that is why AES-256 and SHA-384 are retained unchanged throughout.

**The key exchange is the only genuinely broken component.** Replacing it is the
entire migration.

### 3.3 Authentication is still classical — and why that is acceptable *for now*

PSK authentication is used in the lab; X.509 with classical signatures in the
production template. Neither is post-quantum.

This is a defensible ordering, not an oversight:

- **Key establishment is retroactively vulnerable.** Traffic recorded today is
  decryptable the day a quantum computer exists. This is the harvest-now-decrypt-later
  problem and it is happening now.
- **Authentication is only vulnerable in real time.** Forging a signature is
  useful only during a live handshake. An adversary with a future quantum computer
  cannot retroactively impersonate a peer in a session that already completed.

So key exchange is migrated first. ML-DSA (FIPS 204) for authentication is the
correct next step and CNSA 2.0 requires both by 2033.

### 3.4 Pure ML-KEM, not hybrid

The IPsec module negotiates ML-KEM-1024 **alone**, not `ecp384+mlkem1024`.

Rationale: a controlled two-peer deployment where both ends run the same build
has no interoperability population to protect; a single proposal with no
classical option is trivially downgrade-proof; and it proves the plugin
negotiates standalone rather than riding behind an ECDH exchange doing the real
work.

The hybrid form is available. `quansec/strongswan/swanctl.conf` contains
`proposals = aes256gcm128-prfsha384-ecp384+mlkem1024`, which is RFC 9370
additional key exchange — ECDH first, ML-KEM as an additional round. Use it when
peer interoperability matters more than a clean end-state demonstration.

---

## 4. The ML-KEM StrongSwan plugin

Source: `quansec/compiled-backup/ml_kem_source/`

### 4.1 Registration

```c
#define ML_KEM_768  1050
#define ML_KEM_1024 1051

static plugin_feature_t features[] = {
    PLUGIN_REGISTER(KE, ml_kem_ke_create),
        PLUGIN_PROVIDE(KE, ML_KEM_768),
        PLUGIN_PROVIDE(KE, ML_KEM_1024),
};
```

`1050` and `1051` sit in IANA's **private use** range for IKEv2 transform IDs.
That is why both peers need:

```
charon { accept_private_algs = yes }
```

Without it charon refuses to negotiate a transform ID it has no registration for.
Both peers agree on the numbers because they run the same plugin — which also
means this deployment will not interoperate with a third-party ML-KEM
implementation using different (or standardised) IDs.

### 4.2 KEM mapped onto Diffie-Hellman

ML-KEM is a *key encapsulation mechanism*, not a Diffie-Hellman group, but
StrongSwan's `key_exchange_t` interface is DH-shaped. The adapter:

| StrongSwan call | Initiator | Responder |
|---|---|---|
| `get_public_key()` | `OQS_KEM_keypair()` → return the ML-KEM public key | return the stored ciphertext (masquerading as a public key) |
| `set_public_key(v)` | `OQS_KEM_decaps(v, sk)` → shared secret | `OQS_KEM_encaps(v)` → ciphertext + shared secret |
| `get_shared_secret()` | the decapsulated secret | the encapsulated secret |

Both sides finish with the same shared secret, and the IKE state machine never
learns it was talking to a KEM. Length checks in `set_public_key` reject a value
whose size does not match the expected public key or ciphertext, which prevents
the obvious confusion attack.

All cryptography is liboqs; the plugin is ~200 lines of adapter and memory
management.

### 4.3 Build artefacts

`compiled-backup/` also ships pre-built `libstrongswan-ml-kem.so` and a matching
`libstrongswan.so.0.0.0`. These are ABI-tied to the StrongSwan version they were
compiled against and will fail to load on a different build. Prefer compiling
from source ([SETUP.md §4.3](../SETUP.md#43-build-strongswan-with-the-plugin)).

---

## 5. The VICI client

`vici_client.py` wraps the `vici` Python library with three concerns.

### 5.1 Connection

```python
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(self.socket_path)          # /var/run/charon.vici
self._session = vici.Session(sock)
```

A fresh connection per poll cycle. A failure returns `False`, the collector logs
a warning and skips the cycle — charon restarts do not require a backend restart.

### 5.2 Byte decoding

VICI returns bytes for every key and value, recursively. `_decode()` walks dicts,
lists and scalars converting to `str` with `errors="replace"`. Without it every
downstream comparison would need `b"..."` literals.

### 5.3 SA normalisation

`normalise_sa(raw)` flattens StrongSwan's nested structure into flat tunnel dicts:

```
IKE_SA "pqc-tunnel"
  ├─ encr-alg, encr-keysize, integ-alg, prf-alg, dh-group  → ike_proposal
  ├─ local-host, local-id, remote-host, remote-id, state, version, established
  └─ child-sas
       └─ "net"  → esp_proposal, bytes-in/out, packets-in/out
```

- **With CHILD_SAs** → one row per child, named `"ike_name/child_name"`, carrying
  the parent's IKE proposal plus its own ESP proposal and counters. This is
  correct because a CHILD_SA is what actually carries traffic.
- **Without CHILD_SAs** → one row for the IKE_SA alone with zeroed counters — an
  established IKE_SA whose child has not come up yet is real state worth showing.

`established` arrives as *seconds since establishment*, converted to an absolute
`TIMESTAMPTZ` so it survives being stored and compared across hosts.

---

## 6. PQC classification

Two functions, both operating on the negotiated proposal string.

### 6.1 Is it PQC?

```python
PQC_KEYWORDS = {"kyber", "mlkem", "ml_kem", "ml-kem",
                "ntru", "bike", "hqc", "frodo", "newhope"}

def _is_pqc(proposal):
    normalized = proposal.lower().replace("_", "").replace("-", "")
    return any(k.replace("_","").replace("-","") in normalized for k in PQC_KEYWORDS)
```

Normalising away separators means `ML_KEM_1024`, `mlkem1024`, `ML-KEM-1024` and
`MlKem1024` all classify identically. StrongSwan's own naming varies between the
VICI output (`ML_KEM_1024`) and the proposal syntax (`mlkem1024`), so this is not
theoretical.

The keyword set covers algorithms beyond ML-KEM — NTRU, BIKE, HQC, FrodoKEM,
NewHope — so a peer running a different PQC implementation still classifies as
quantum-safe even though this deployment does not offer those.

### 6.2 Which KEM?

`_extract_pqc_kem()` returns a normalised display label by matching most-specific
first: `mlkem1024` → `ML-KEM-1024`, `mlkem768` → `ML-KEM-768`, `kyber1024` →
`Kyber1024`, and so on. Anything unrecognised but matching a PQC keyword returns
the raw token, so a novel algorithm shows up under its own name rather than as
`null`.

Order matters: `mlkem1024` must be checked before `mlkem` would match, which is
why the checks are explicit rather than a loop over the keyword set.

### 6.3 A tunnel is PQC if *either* channel is

```python
"pqc_enabled": _is_pqc(ike_proposal) or _is_pqc(esp_proposal)
```

In practice the KEM is in the IKE proposal — ESP uses symmetric algorithms
derived from the IKE-established key. The `or` covers configurations that put a
per-child key exchange in the ESP proposal (PFS rekeying).

---

## 7. The collector

`collector.py` — the `ipsec-collector` background task.

### 7.1 The cycle

```python
async def collect_once(pool, redis):
    client = ViciClient(settings.VICI_SOCKET)
    if not client.connect():
        logger.warning("StrongSwan VICI socket not available — skipping this cycle")
        return
    try:
        tunnels = [t for raw in client.list_sas() for t in normalise_sa(raw)]
        async with pool.acquire() as conn:
            await upsert_tunnels(conn, tunnels)
            await mark_stale_tunnels_down(conn, {t["name"] for t in tunnels})
        if redis:
            await publish_summary(redis, tunnels)
    except Exception as e:
        logger.error(f"IPsec collect_once error: {e}", exc_info=True)
    finally:
        client.close()
```

### 7.2 The upsert

```sql
INSERT INTO ipsec_tunnels (name, local_host, …, last_seen)
VALUES ($1, …, NOW())
ON CONFLICT (name) DO UPDATE SET
    state          = EXCLUDED.state,
    ike_proposal   = EXCLUDED.ike_proposal,
    …
    established_at = COALESCE(EXCLUDED.established_at, ipsec_tunnels.established_at),
    last_seen      = NOW()
```

Two details worth noting:

- **`COALESCE` on `established_at`** preserves the original establishment time if
  a later poll reports `NULL` — the tunnel did not re-establish just because one
  poll could not compute the timestamp.
- **`created_at` is never updated**, so it remains the time QUANSEC first saw the
  tunnel.

The whole batch runs in one transaction, so a dashboard read never sees a
half-updated poll.

### 7.3 Stale detection

VICI reports only *active* SAs, so a torn-down tunnel simply stops appearing.

```sql
SELECT name FROM ipsec_tunnels
WHERE state != 'DOWN' AND last_seen < NOW() - INTERVAL '30 seconds'
```

Rows matching this and absent from the current cycle are set to `DOWN` and get a
`DOWN` event with `{"reason": "not seen in last poll cycle"}`.

The 30-second grace period is six poll intervals — enough to ride out a couple of
missed cycles from a transient VICI hiccup without flapping a tunnel's state.

### 7.4 Live publish

```json
{"protocol":"ipsec","total":1,"up":1,"down":0,
 "pqc_count":1,"pqc_pct":100.0,"timestamp":"2026-07-29T…Z"}
```

Published to `quansec:live` every cycle. If Redis is unavailable the collector
logs once and continues — no data is lost, only push latency.

---

## 8. The lifecycle event listener

`events.py` — the `ipsec-events` background task.

### 8.1 The thread bridge

VICI's `session.listen()` is a blocking generator. Calling it on the event loop
would freeze the entire application permanently.

```
asyncio loop                          worker thread
    │                                      │
    ├── run_in_executor(_listen_blocking) ─┤
    │                                      │  for label, msg in session.listen([...]):
    │      ◄── run_coroutine_threadsafe ───┤      queue.put((label, decoded))
    │                                      │
    └── while True: await queue.get()      │
            classify → store → publish
```

`asyncio.run_coroutine_threadsafe` is the only thread-safe way to schedule work
onto a running loop from another thread. The listener reconnects after 5 seconds
if the socket drops.

### 8.2 Subscribed events

`ike-updown`, `child-updown`, `ike-rekey`, `child-rekey`.

| Classified as | Condition |
|---|---|
| `ESTABLISHED` | `up == "yes"` and IKE state is `ESTABLISHED` |
| `IKE_SA_INIT` | `up == "yes"`, other state |
| `DOWN` | `up != "yes"` |
| `CHILD_UP` / `CHILD_DOWN` | child event, by `up` |

Each stored event carries a `detail` JSONB payload:

```json
{"stage":"ESTABLISHED","local_host":"192.168.1.6","remote_host":"192.168.1.7",
 "encr_alg":"AES_CBC","integ_alg":"HMAC_SHA2_256_128",
 "key_exchange":"ML_KEM_1024","pqc":true}
```

The `pqc` flag here is computed independently of the collector's classification
(`"ml_kem" in dh.lower() or "kyber" in dh.lower()`), giving a second opinion on
the same fact.

`GET /api/ipsec/handshakes` annotates each event with a `stage_order` integer
(`IKE_SA_INIT` 1 → `IKE_AUTH` 2 → `ESTABLISHED` 3 → `CHILD_UP` 4 → rekeys 5 →
downs 6–7) so the UI can render the handshake as an ordered timeline.

---

## 9. The policy engine

`policy.py` — `/api/ipsec/policies`

### 9.1 Available policies

| Name | IKE proposal | KEM | Quantum-safe |
|---|---|---|---|
| `classical` | `aes256-sha256-ecp384` | ECDH P-384 | ❌ |
| `pqc-level3` | `aes256-sha256-mlkem768` | ML-KEM-768 | ✅ NIST L3 |
| `pqc-level5` | `aes256-sha256-mlkem1024` | ML-KEM-1024 | ✅ NIST L5 |

Each carries an `algorithms` block (key exchange, encryption, integrity,
`nist_standard`, `security_level`) and, for `classical`, a `threat` string:
*"Shor's algorithm breaks ECDH in hours"*.

The `classical` policy exists so the attack lab has something to break. Applying
it deliberately downgrades a live tunnel — which is the demonstration.

### 9.2 Applying

```
POST /api/ipsec/policies/apply   {"policy_name": "pqc-level5"}   [admin]
```

1. Look up the policy; 400 on unknown name.
2. `_read_current_addrs()` parses `local_addrs` / `remote_addrs` out of the
   existing `/etc/swanctl/swanctl.conf`, so applying a policy never changes the
   tunnel's endpoints. Falls back to `192.168.1.6` / `192.168.1.7` if unreadable.
3. Render `SWANCTL_TEMPLATE` with the proposals and addresses substituted.
4. **Dev mode** (no `/etc/swanctl`): write `/tmp/quansec/swanctl/swanctl.conf`,
   log a warning, return `dev_mode: true`.
   **Production**: write the real file, then `sudo swanctl --load-all`.
5. Insert an `audit_events` row (`policy_apply`, severity `warning`).

Response:

```json
{"status":"applied","policy":"pqc-level5","ike_proposal":"aes256-sha256-mlkem1024",
 "pqc_enabled":true,"dev_mode":false,
 "message":"Reload successful. Re-initiate tunnel to use new policy."}
```

**Existing SAs keep their old proposal.** `swanctl --load-all` updates
configuration; it does not renegotiate live SAs. The new policy takes effect on
the next rekey or a manual `swanctl --initiate`. The response message says this
explicitly, and it is the single most common source of "I applied the policy and
nothing changed".

The PSK in `SWANCTL_TEMPLATE` is `${IPSEC_PSK}`, which is written literally into
the config file — it is not expanded by Python. StrongSwan does not perform
environment expansion either, so a generated config needs the secret substituted
before the tunnel will authenticate. Treat the generated file's `secrets` block
as a template to complete, not as ready to load.

### 9.3 Comparison

`GET /api/ipsec/policies/compare` returns a table the UI renders directly:

| Field | Classical | PQC | Why it changed |
|---|---|---|---|
| Key exchange | ECDH (ECP-384) | ML-KEM-1024 | Shor breaks ECDH on a quantum computer in hours |
| Quantum safe | false | true | CNSA 2.0 requires PQC by 2030 (TLS/SSH) and 2033 (IPsec) |
| Security level | Classical ~192-bit | PQC Level 5 (256-bit) | ML-KEM-1024 provides 256-bit post-quantum security |
| Encryption | AES-256-CBC | AES-256-CBC | AES-256 remains quantum-safe |
| NIST standard | None (pre-PQC) | FIPS 203 | NIST finalised ML-KEM on 13 August 2024 |

Plus `cnsa_deadline: "2033 (IPsec)"` and a live `days_remaining` countdown to
2033-01-01.

---

## 10. The attack lab

`attacks.py` — `/api/ipsec/attacks/*`

Every attack reads the **current** tunnel state first (`_get_current_tunnel_info()`
via VICI, falling back to parsing `swanctl.conf`) and branches on whether PQC is
active. Switch the policy to `classical` and re-run, and every verdict flips.
That is the demonstration.

### 10.1 What is real and what is illustrative

Stated plainly, because the distinction matters:

| Attack | Real computation | Illustrative narrative |
|---|---|---|
| `factoring` | **Yes** — generates a real 64-bit semiprime, factors it with Pollard's rho, recovers `d` from `e=65537` and φ(n), reports wall-clock time | Extrapolation to 512/2048-bit |
| `shors` | Partly — runs Pollard's rho on 15, 21, 35 as a factoring demo | The quantum break-time figures are literature estimates, not measurements |
| `downgrade` | Reads the live negotiated proposal | The MITM is described, not performed |
| `harvest` | Reads the live proposal; byte count is randomised | The future-decryption scenario is reasoning |
| `kyber-resist` | Runs a 10,000-iteration loop | The loop does not perform lattice reduction; the 2²⁵⁶ figure is arithmetic |

The genuinely persuasive one is **`factoring`**: it breaks a real key in front of
you, in milliseconds, using an algorithm from 1975. That is the argument — not
that quantum computers are coming, but that "hard maths problem" has a shelf life.

### 10.2 The endpoints

**`POST /attacks/downgrade`** — MITM strips PQC from IKE_SA_INIT.
PQC active → `BLOCKED` ("StrongSwan rejected NO_PROPOSAL_CHOSEN"). Classical →
`VULNERABLE`. This directly demonstrates fail-closed: a single-proposal config
has nothing to downgrade *to*.

**`POST /attacks/shors`** — PQC → `RESISTANT`, with the explanation that ML-KEM
rests on Module-LWE and Shor's algorithm does not apply to lattice problems.
Classical → `VULNERABLE`, "~8 hours on 4,000 qubits (ECDH-384)".

**`POST /attacks/harvest`** — the most operationally important one. PQC →
`PROTECTED`, `future_decrypt: "IMPOSSIBLE"`. Classical → `VULNERABLE`,
`future_decrypt: "POSSIBLE"`, with the note that *traffic already captured cannot
be protected retroactively*. That last point is the reason migration deadlines
are not negotiable.

**`POST /attacks/factoring`** — real Pollard's rho:

```python
x = y = random.randint(2, n-1); c = random.randint(1, n-1); d = 1
while d == 1:
    x = (x*x + c) % n
    y = (y*y + c) % n; y = (y*y + c) % n     # y moves twice as fast
    d = math.gcd(abs(x - y), n)               # Floyd cycle detection
```

Returns `n`, `p`, `q`, the recovered private exponent `d`, and the elapsed time.

**`POST /attacks/kyber-resist`** — reports ML-KEM-1024's parameters
(n=256, k=4, q=3329, lattice dimension 1024, NIST level 5) and the break-time
arithmetic: 2²⁵⁶ operations at 10¹⁵ ops/s ≈ 2.69 × 10⁵²⁴ years, roughly 10⁵¹⁴
times the age of the universe.

**`GET /attacks/results`** — every past simulation from `audit_events` where
`action = 'attack_simulation'`.

All attack endpoints are `require_user`, not `require_admin`: they read state and
write an audit row, but never touch a live tunnel.

---

## 11. API reference

All endpoints require authentication. `/api/ipsec/*` (the main router) declares
`require_user` at the router level; policy `apply` requires admin.

### Tunnels and stats

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/ipsec/tunnels` | `?state=ESTABLISHED&pqc=true&limit=50&offset=0` |
| `GET` | `/api/ipsec/tunnels/{id}` | 404 if absent |
| `POST` | `/api/ipsec/tunnels` | Seed a tunnel before StrongSwan establishes it; state `CONNECTING` |
| `GET` | `/api/ipsec/stats` | Aggregate — one query |
| `POST` | `/api/ipsec/refresh` | Run a poll cycle now |

```jsonc
// GET /api/ipsec/stats
{
  "total_tunnels": 1, "established": 1, "down": 0,
  "pqc_enabled": 1, "pqc_coverage": 100.0,
  "total_bytes_in": 8432, "total_bytes_out": 8432,
  "last_updated": "2026-07-29T14:23:11.482Z"
}
```

```jsonc
// GET /api/ipsec/tunnels  →  one element
{
  "id": 1, "name": "pqc-tunnel/net",
  "local_host": "192.168.1.6", "local_id": "vm-a",
  "remote_host": "192.168.1.7", "remote_id": "vm-b",
  "state": "INSTALLED", "ike_version": 2,
  "ike_proposal": "AES_CBC-256-HMAC_SHA2_256_128-PRF_HMAC_SHA2_256-ML_KEM_1024",
  "esp_proposal": "AES_CBC-256-HMAC_SHA2_256_128",
  "pqc_kem": "ML-KEM-1024", "pqc_enabled": true,
  "bytes_in": 8432, "bytes_out": 8432, "packets_in": 84, "packets_out": 84,
  "established_at": "2026-07-29T14:01:03Z", "last_seen": "2026-07-29T14:23:11Z",
  "created_at": "2026-07-29T13:58:44Z"
}
```

### Events

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/ipsec/events` | `?tunnel_name=&event_type=&limit=100` |
| `GET` | `/api/ipsec/handshakes` | Same data plus `stage_order` for timeline rendering |

### Policies and attacks

| Method | Path | Auth |
|---|---|---|
| `GET` | `/api/ipsec/policies` | user |
| `POST` | `/api/ipsec/policies/apply` | **admin** |
| `GET` | `/api/ipsec/policies/compare` | user |
| `POST` | `/api/ipsec/attacks/{downgrade,shors,harvest,factoring,kyber-resist}` | user |
| `GET` | `/api/ipsec/attacks/results` | user |

### WebSocket

`ws://host:8000/api/ws/live` — subscribes to `quansec:live`. Sends a `connected`
frame on accept, then forwards every published message. Carries both IPsec and
SSH traffic; filter on `protocol`. Currently unauthenticated — see
[SECURITY.md](../SECURITY.md).

---

## 12. Data model

### `ipsec_tunnels` — current state, one row per SA

`name` is `UNIQUE` and is the upsert conflict target. For a tunnel with children
it is `"ike_name/child_name"`.

Indexes: `state`, `pqc_enabled`, `last_seen DESC` — matching the three filters
the router actually uses.

### `ipsec_events` — append-only history

`detail` is `JSONB`, so payload shape can differ per event type without a schema
change. Indexed on `tunnel_name`, `event_type`, `occurred_at DESC`.

Written by two sources: the event listener (real-time lifecycle) and the
collector (synthetic `DOWN` on stale detection).

No retention policy. This table grows without bound on a busy tunnel that rekeys
frequently — add a retention job before long-running production use.

Full schema: [DATA-MODEL.md](../DATA-MODEL.md).

---

## 13. Operating notes

| Situation | What to check |
|---|---|
| No tunnels appear | `sudo swanctl --list-sas` — if empty, the tunnel is genuinely down. `start_action = trap` means it only comes up on traffic; send a ping. |
| `VICI socket not available` every 5 s | charon down, or the socket is unreadable by the backend user. [SETUP.md §4.6](../SETUP.md#46-vici-socket-permissions). |
| Tunnel up, `pqc_enabled: false` | Read `swanctl --list-sas`. If it shows `ECP_384`, the peer really did negotiate classical — the platform is reporting correctly and you have a downgrade to investigate. |
| `NO_PROPOSAL_CHOSEN` | ml-kem plugin not loaded, or `accept_private_algs` missing on one peer. `swanctl --stats \| grep ml-kem`. |
| Policy applied, tunnel unchanged | Expected. Config reload does not renegotiate live SAs. Wait for rekey or `swanctl --initiate --child net`. |
| Policy apply → `dev_mode: true` | `/etc/swanctl` does not exist. Install StrongSwan, or accept dev mode for a demo. |
| Policy apply → 500 "Cannot write" | Backend lacks write permission on `swanctl.conf`. [SETUP.md §9](../SETUP.md#9-privilege-configuration). |
| Tunnels flapping to DOWN | Poll cycles are being missed for >30 s. Check for VICI timeouts or backend CPU starvation. |
| `ipsec_events` growing large | Expected on a frequently-rekeying tunnel; no retention policy exists. Add one. |

---

*See also:* [SSH.md](SSH.md) · [TLS.md](TLS.md) · [SETUP.md](../SETUP.md) · [API.md](../API.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)
