import os
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CERT_DIR = os.path.expanduser("~/quanseq-certs")

# Isolated TLS runtime built by scripts/build-pqc-tls-runtime.sh.
#
# Outside the repository by default because this checkout's path contains spaces,
# and neither OpenSSL's nor NGINX's build system quotes paths in the Makefiles and
# linker flags it generates — a spaced build root fails at link time. The runtime
# is still project-scoped and isolated: nothing else uses it, it touches no system
# prefix, and removing the directory undoes the build entirely.
_DEFAULT_RUNTIME_DIR = os.path.expanduser("~/.quanseq/pqc-tls")


def _flag(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


# Minimum signing-secret length. HS384's HMAC block is 128 bytes and the output
# is 48; a secret shorter than the digest is the weakest link in the token, so
# 48 bytes is the floor. Expressed in hex characters because that is how the
# secret is generated and pasted.
_MIN_SECRET_BYTES = 48
_MIN_SECRET_HEX_CHARS = _MIN_SECRET_BYTES * 2

# Values that have appeared as defaults or in documentation. Any of these means
# the operator has not generated a real secret, whatever its length.
_PLACEHOLDER_SECRETS = {
    "change-this-in-production",
    "change_me",
    "changeme",
    "secret",
    "quanseq",
    "CHANGE_ME_32_RANDOM_BYTES_HEX",
    "CHANGE_ME_48_RANDOM_BYTES_HEX",
}


class ConfigurationError(RuntimeError):
    """Raised at import when a security-critical setting is missing or unusable."""


def _require_secret(name: str) -> str:
    """
    Read a signing secret from the environment, or refuse to start.

    Deliberately has no default and no "development mode" escape hatch. A
    fallback secret is indistinguishable from a published one, and a
    development-only bypass is exactly the thing that reaches production.

    Raised at import time on purpose: a process that cannot verify tokens
    correctly should never begin serving requests.
    """
    value = (os.getenv(name) or "").strip()

    if not value:
        raise ConfigurationError(
            f"{name} is not set.\n\n"
            f"  Generate one:  python3 -c \"import secrets; print(secrets.token_hex({_MIN_SECRET_BYTES}))\"\n"
            f"  Then add it to quanseq/.env as:  {name}=<the value>\n\n"
            "  .env is git-ignored. There is no default: a secret compiled into\n"
            "  the source would let anyone holding this repository forge an\n"
            "  administrator token."
        )

    if value in _PLACEHOLDER_SECRETS:
        raise ConfigurationError(
            f"{name} is still the placeholder value {value!r}.\n"
            f"  Generate a real one:  python3 -c \"import secrets; print(secrets.token_hex({_MIN_SECRET_BYTES}))\""
        )

    # Hex is what the documented generator emits, so measure entropy in bytes
    # when it looks like hex and in characters otherwise. A 96-character hex
    # string is 48 bytes; a 96-character passphrase is not, but it is long
    # enough either way.
    is_hex = len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)
    effective_bytes = len(value) // 2 if is_hex else len(value)

    if effective_bytes < _MIN_SECRET_BYTES:
        raise ConfigurationError(
            f"{name} provides about {effective_bytes} bytes of key material; "
            f"HS384 requires at least {_MIN_SECRET_BYTES}.\n"
            f"  Generate a replacement:  python3 -c \"import secrets; print(secrets.token_hex({_MIN_SECRET_BYTES}))\"\n"
            f"  ({_MIN_SECRET_HEX_CHARS} hex characters. Rotating the secret invalidates "
            "existing sessions; users log in again.)"
        )

    return value


def _cert_path(name: str, filename: str, cert_dir: str) -> str:
    return os.getenv(name, os.path.join(cert_dir, filename))


def _runtime_path(name: str, relative: str, runtime_dir: str) -> str:
    return os.getenv(name, os.path.join(runtime_dir, relative))


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://quanseq_user:CHANGE_ME@localhost:5432/quanseq")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # ── Authentication ───────────────────────────────────────────────────────
    # The signing secret has NO default. A fallback string in source is a
    # published key: anyone holding this file could mint an admin token against
    # any deployment that had not overridden it. _require_secret() raises at
    # import instead, so a missing or placeholder secret stops the process with
    # instructions rather than starting an app that trusts forged tokens.
    #
    # Generate with:  python3 -c "import secrets; print(secrets.token_hex(48))"
    JWT_SECRET: str = _require_secret("JWT_SECRET")

    # HS384 with a >=48-byte secret. Symmetric is the right family for a single
    # backend that both mints and verifies its own tokens; RS/ES only pays off
    # once a separate service must verify without being able to sign.
    #
    # The value is pinned rather than read from the environment: an attacker who
    # can influence the *verification* algorithm can strip a signature entirely
    # (alg=none) or force HMAC verification against a public key. See
    # core/tokens.py, which passes this as the sole permitted algorithm.
    JWT_ALGORITHM: str = "HS384"
    JWT_ISSUER: str = os.getenv("JWT_ISSUER", "quanseq")
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "quanseq-api")

    # Short enough that a leaked access token expires before it is useful, long
    # enough to avoid a refresh on every page. Revocation happens at the refresh
    # layer, so this window is the true blast radius of a stolen access token.
    ACCESS_TOKEN_TTL_MINUTES: int = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "15"))
    REFRESH_TOKEN_TTL_DAYS: int = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "7"))

    # Retained only so a pre-existing .env does not fail to parse. Nothing reads
    # it; ACCESS_TOKEN_TTL_MINUTES replaced it.
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

    # ── Refresh cookie ───────────────────────────────────────────────────────
    # Path is restricted to /api/auth so the refresh token is not attached to
    # ordinary API calls: a XSS payload that can read responses still never sees
    # it, and no protocol endpoint can leak it in a log or an echo.
    REFRESH_COOKIE_NAME: str = os.getenv("REFRESH_COOKIE_NAME", "quanseq_refresh")
    REFRESH_COOKIE_PATH: str = os.getenv("REFRESH_COOKIE_PATH", "/api/auth")
    REFRESH_COOKIE_DOMAIN: str = os.getenv("REFRESH_COOKIE_DOMAIN", "") or None
    # Secure defaults on. Over plain HTTP on localhost the browser will drop a
    # Secure cookie, so local development sets AUTH_COOKIE_SECURE=false — which
    # is also why it is an explicit switch and not inferred from the request.
    REFRESH_COOKIE_SECURE: bool = _flag("AUTH_COOKIE_SECURE", "true")
    # Lax, not Strict: Strict withholds the cookie on any cross-site navigation,
    # so following a link into the dashboard would land on a logged-out page
    # even with a valid session. Lax still blocks cross-site POST, which is the
    # CSRF vector that matters here, and the double-submit token below covers
    # the rest.
    REFRESH_COOKIE_SAMESITE: str = os.getenv("AUTH_COOKIE_SAMESITE", "lax")
    CSRF_COOKIE_NAME: str = os.getenv("CSRF_COOKIE_NAME", "quanseq_csrf")
    CSRF_HEADER_NAME: str = os.getenv("CSRF_HEADER_NAME", "X-CSRF-Token")

    # ── Login throttling ─────────────────────────────────────────────────────
    LOGIN_RATE_LIMIT: int = int(os.getenv("LOGIN_RATE_LIMIT", "10"))
    LOGIN_RATE_WINDOW_SECONDS: int = int(os.getenv("LOGIN_RATE_WINDOW_SECONDS", "300"))
    LOGIN_LOCKOUT_SECONDS: int = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))
    REFRESH_RATE_LIMIT: int = int(os.getenv("REFRESH_RATE_LIMIT", "60"))
    REFRESH_RATE_WINDOW_SECONDS: int = int(os.getenv("REFRESH_RATE_WINDOW_SECONDS", "300"))

    # Trust X-Forwarded-For for the client IP. OFF by default: any client can
    # send that header, so trusting it without a proxy in front lets an attacker
    # forge the address in the audit log and sidestep per-IP throttling by
    # rotating a header value. Enable only when a reverse proxy sets it.
    TRUSTED_PROXY: bool = _flag("TRUSTED_PROXY", "false")

    # IPsec
    VICI_SOCKET: str = os.getenv("VICI_SOCKET", "/var/run/charon.vici")
    IPSEC_POLL_INTERVAL: int = int(os.getenv("IPSEC_POLL_INTERVAL", "5"))

    # ── TLS data plane: NGINX + OpenSSL 3.5.7 ────────────────────────────────
    # The TLS data plane is NGINX linked against OpenSSL 3.5.7, running as its
    # own process and configured fail-closed on X25519MLKEM768. QUANSEQ is the
    # control plane: it renders the config, manages the process, reads the logs
    # and runs enforcement probes. See protocols/tls/settings.py for validation.
    TLS_ENABLED: bool = _flag("QUANSEQ_TLS_ENABLED", "true")
    TLS_HOST: str = os.getenv("QUANSEQ_TLS_HOST", "127.0.0.1")
    TLS_PORT: int = int(os.getenv("QUANSEQ_TLS_PORT", "8443"))
    TLS_SERVER_HOSTNAME: str = os.getenv("QUANSEQ_TLS_SERVER_HOSTNAME", "localhost")

    # Isolated runtime built by scripts/build-pqc-tls-runtime.sh. Nothing here
    # comes from the system OpenSSL 3.0.13 or the system NGINX 1.24.0.
    TLS_RUNTIME_DIR: str = os.getenv("QUANSEQ_TLS_RUNTIME_DIR", _DEFAULT_RUNTIME_DIR)
    TLS_NGINX_BIN: str = _runtime_path("QUANSEQ_TLS_NGINX_BIN", "nginx/sbin/nginx", TLS_RUNTIME_DIR)
    TLS_OPENSSL_BIN: str = _runtime_path("QUANSEQ_TLS_OPENSSL_BIN", "openssl/bin/openssl", TLS_RUNTIME_DIR)
    TLS_NGINX_CONF: str = _runtime_path("QUANSEQ_TLS_NGINX_CONF", "conf/nginx.conf", TLS_RUNTIME_DIR)
    TLS_ACCESS_LOG: str = _runtime_path("QUANSEQ_TLS_ACCESS_LOG", "logs/access.json.log", TLS_RUNTIME_DIR)
    TLS_ERROR_LOG: str = _runtime_path("QUANSEQ_TLS_ERROR_LOG", "logs/error.log", TLS_RUNTIME_DIR)
    TLS_PID_FILE: str = _runtime_path("QUANSEQ_TLS_PID_FILE", "run/nginx.pid", TLS_RUNTIME_DIR)
    TLS_EVIDENCE_DIR: str = _runtime_path("QUANSEQ_TLS_EVIDENCE_DIR", "evidence", TLS_RUNTIME_DIR)

    # Certificates. Development PKI generated by scripts/generate_tls_certs.py,
    # kept outside the repository with keys mode 600.
    TLS_CERT_DIR: str = os.getenv("QUANSEQ_TLS_CERT_DIR", _DEFAULT_CERT_DIR)
    TLS_CA_CERT: str = _cert_path("QUANSEQ_TLS_CA_CERT", "ca.crt", TLS_CERT_DIR)
    TLS_SERVER_CERT: str = _cert_path("QUANSEQ_TLS_SERVER_CERT", "server.crt", TLS_CERT_DIR)
    TLS_SERVER_KEY: str = _cert_path("QUANSEQ_TLS_SERVER_KEY", "server.key", TLS_CERT_DIR)
    TLS_CLIENT_CERT: str = _cert_path("QUANSEQ_TLS_CLIENT_CERT", "client.crt", TLS_CERT_DIR)
    TLS_CLIENT_KEY: str = _cert_path("QUANSEQ_TLS_CLIENT_KEY", "client.key", TLS_CERT_DIR)

    # ── Enforced TLS policy ──────────────────────────────────────────────────
    # These become NGINX directives. There is deliberately NO classical fallback
    # group: a client that cannot do X25519MLKEM768 is refused at the handshake.
    TLS_PROTOCOLS: str = os.getenv("QUANSEQ_TLS_PROTOCOLS", "TLSv1.3")
    TLS_GROUPS: str = os.getenv("QUANSEQ_TLS_GROUPS", "X25519MLKEM768")
    TLS_CIPHERSUITES: str = os.getenv("QUANSEQ_TLS_CIPHERSUITES", "TLS_AES_256_GCM_SHA384")
    TLS_HYBRID_GROUP: str = os.getenv("QUANSEQ_TLS_HYBRID_GROUP", "X25519MLKEM768")
    TLS_MTLS: bool = _flag("QUANSEQ_TLS_MTLS", "false")
    TLS_EARLY_DATA: bool = _flag("QUANSEQ_TLS_EARLY_DATA", "false")

    # The FastAPI upstream NGINX proxies to.
    TLS_UPSTREAM: str = os.getenv("QUANSEQ_TLS_UPSTREAM", "127.0.0.1:8000")

    # ── Portal listener ──────────────────────────────────────────────────────
    # A SECOND listener, serving the dashboard to a browser.
    #
    # It exists because the strict-hybrid listener on TLS_PORT cannot serve a
    # browser: no mainstream browser negotiates X25519MLKEM768 against a
    # ciphersuite list of exactly TLS_AES_256_GCM_SHA384. Rather than weaken
    # the enforcement listener to make the UI reachable — which would destroy
    # the property the probes exist to verify — the portal gets its own
    # listener with browser-compatible groups.
    #
    # Both listeners are logged, to SEPARATE files, so a session observed on
    # the portal is never counted as evidence of hybrid enforcement.
    TLS_PORTAL_ENABLED: bool = _flag("QUANSEQ_TLS_PORTAL_ENABLED", "true")
    TLS_PORTAL_PORT: int = int(os.getenv("QUANSEQ_TLS_PORTAL_PORT", "8444"))
    TLS_PORTAL_GROUPS: str = os.getenv(
        "QUANSEQ_TLS_PORTAL_GROUPS", "X25519MLKEM768:x25519:secp256r1"
    )
    TLS_PORTAL_CIPHERSUITES: str = os.getenv(
        "QUANSEQ_TLS_PORTAL_CIPHERSUITES",
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
    )
    # Where Next.js is listening, for the portal listener to proxy to.
    TLS_UI_UPSTREAM: str = os.getenv("QUANSEQ_TLS_UI_UPSTREAM", "127.0.0.1:3000")
    TLS_PORTAL_ACCESS_LOG: str = _runtime_path(
        "QUANSEQ_TLS_PORTAL_ACCESS_LOG", "logs/access-portal.json.log", TLS_RUNTIME_DIR
    )

    TLS_TIMEOUT: int = int(os.getenv("QUANSEQ_TLS_TIMEOUT", "10"))
    TLS_POLL_INTERVAL: int = int(os.getenv("QUANSEQ_TLS_POLL_INTERVAL", "10"))
    TLS_LOG_PAYLOADS: bool = _flag("QUANSEQ_TLS_LOG_PAYLOADS", "false")

    # Reserved for a future collector that tails nginx TLS access logs to observe
    # third-party traffic. Nothing reads this today.
    NGINX_ACCESS_LOG: str = os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")

    # SSH
    SSH_AUTH_LOG: str = os.getenv("SSH_AUTH_LOG", "/var/log/auth.log")
    SSHD_CONFIG: str = os.getenv("SSHD_CONFIG", "/etc/ssh/sshd_config")
    SSHD_CONFIG_BINARY: str = os.getenv("SSHD_CONFIG_BINARY", "/usr/sbin/sshd")
    SSH_POLL_INTERVAL: int = int(os.getenv("SSH_POLL_INTERVAL", "5"))

    # VPN
    WG_INTERFACE: str = os.getenv("WG_INTERFACE", "wg0")
    VPN_POLL_INTERVAL: int = int(os.getenv("VPN_POLL_INTERVAL", "5"))

settings = Settings()
