# Vendored: `tls13_module`

This package is a **vendored copy** of the TLS 1.3 client and certificate tooling from
an upstream repository. It is not a submodule and not a pip dependency — the files here
are the authoritative copy used by QUANSEQ and are patched for this platform.

> ## Scope change: this is no longer the data plane
>
> QUANSEQ's TLS data plane is **NGINX 1.27.5 linked against OpenSSL 3.5.7**
> (`protocols/tls/service.py`), configured fail-closed on `X25519MLKEM768`.
>
> The vendored TLS **server** (`server.py`) was deleted, because Python's `ssl`
> module cannot restrict TLS 1.3 negotiation to a named hybrid group:
> `SSLContext.set_ecdh_curve()` resolves names through the elliptic-curve name
> database and rejects `X25519MLKEM768`, and the string-based
> `SSL_CTX_set1_groups_list` that OpenSSL's own CLI uses is not exposed. A server
> built on it could never enforce hybrid key exchange.
>
> What remains — `client.py`, `cert_manager.py`, `utils.py`, `config.py`,
> `exceptions.py` — is the reusable validation and client logic that
> `protocols/tls/probe.py` and `protocols/tls/certs.py` build on.

## Provenance

| | |
|---|---|
| Upstream | `https://github.com/V-Preetha/TLS-SMOAD-HSC.git` |
| Upstream package | `tls13_module/` |
| Commit pinned | `2b361a9` ("Add session token authentication and HKDF session key derivation") |
| Vendored on | 2026-07-30 |
| Upstream version string | `2.0.0` |

## Files taken

| File | Patched |
|---|---|
| `config.py` | yes — extra QUANSEQ fields |
| `exceptions.py` | no |
| `utils.py` | yes — patches 1, 2, 3 |
| ~~`server.py`~~ | **removed** — see the scope note above |
| `client.py` | yes — patches 1, 6 |
| `cert_manager.py` | yes — patch 7 |
| `__init__.py` | yes — trimmed exports |

## Files deliberately NOT taken

| Path | Reason |
|---|---|
| `phase2_server.py`, `phase2_client.py` | `phase2_server.py:47` hardcodes `"tls_native_hybrid": True` as handshake "evidence". QUANSEQ must never emit a hybrid claim that was not externally verified, so these compatibility wrappers are excluded outright. |
| `session_tokens.py`, `hybrid_session_keys.py` | HMAC session tokens and HKDF key derivation are not on the TLS transport path. QUANSEQ already has JWT + API-key auth in `core/auth.py`. Excluding them also removes the only `cryptography` dependency, leaving this package stdlib-only. |
| `legacy/` | Archived manual X25519 + ML-KEM prototype. Not imported by live code. |
| `certs/`, `liboqs/`, `docs/*.pcapng`, `legacy/reports/` | Certificates, key material, vendored C sources and packet captures. Never enter this repository. |
| `examples/` | Demonstration endpoints, including a `POST /certs/regenerate` route. Certificate generation in QUANSEQ is CLI-only (`scripts/generate_tls_certs.py`). |
| `check_pqc.py`, `generate_certs.ps1`, `setup.py`, `requirements*.txt` | Platform-specific tooling and packaging not needed in-tree. |

## Patches applied

Each patch is marked in the source with a `# QUANSEQ PATCH n:` comment.

1. **Structured, redactable logging.** Upstream printed ANSI-coloured, Unicode-decorated
   lines straight to stdout via `print()`. That crashes on non-UTF-8 consoles (upstream
   finding F-07) and cannot be routed or filtered. Replaced with the stdlib `logging`
   module under `quanseq.tls.transport`, ASCII-only. Message payloads are logged only
   when `TLSConfig.log_payloads` is true (default false) — upstream logged every payload
   in cleartext (F-06).

2. **Honest `negotiated_group` reporting.** Upstream set `negotiated_group` to a literal
   `None` in `get_session_info`, which reads as "no group was negotiated" rather than
   "Python cannot tell us". Added `negotiated_group_source` so callers can distinguish
   the two, and `hybrid_group_configured` to record the group that was *requested* —
   never an assertion that it was used.

3. **Renamed and widened the runtime gate.** `_require_hybrid_tls_runtime` →
   `_require_hybrid_capable_runtime`. The old name implied it enforced hybrid TLS; it
   only compared `ssl.OPENSSL_VERSION` against 3.5.5 (upstream finding F-01). It now also
   checks that the configured group actually appears in `openssl list -tls-groups`, and
   its docstring states explicitly that this gates the *runtime* and does not, and cannot,
   enforce what gets negotiated.

4. ~~**Bounded handshakes off the accept loop.**~~ Applied to `server.py`, which has
   since been removed. NGINX handles accept-loop concurrency now.

5. ~~**Joinable shutdown.**~~ Same — superseded by NGINX process lifecycle in
   `protocols/tls/service.py`, which waits for the listening socket to be released.

6. **Payload redaction**, gated on `log_payloads`. Still applies to `client.py`.

7. **Linux-only guidance, and a directory-creation fix.** Removed Windows/`winget`
   install strings and the `generate_certs.ps1` references, which are dead advice on
   this platform. Also added `_ensure_dir()` to each generator: upstream created the
   output directory only in `generate_all()`, so calling `generate_ca()` or
   `generate_server_cert()` directly failed with an opaque openssl error. Private keys
   are now written mode 600 at creation.

8. **Socket errors translated at `send_raw`.** Upstream let `ssl.SSLError` escape from
   the send/receive path. This matters more than it looks: in TLS 1.3 the client
   finishes its side of the handshake before the server has validated the client
   certificate, so an **mTLS rejection arrives as an alert on the first read**, not
   from `wrap_socket()`. A caller that wrapped only `connect()` in a `try` would see a
   raw `ssl.SSLError` from `send()` and mishandle a plain authentication failure.
   Socket-level errors now surface as `TLSHandshakeError` / `TLSConnectionError` /
   `CertVerificationError` like every other failure in the module.

9. ~~**Bind failures propagate out of `start_background()`.**~~ Applied to `server.py`,
   which has since been removed.
