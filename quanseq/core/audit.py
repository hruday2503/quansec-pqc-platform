"""
core/audit.py — authentication and authorization audit trail.

Writes to `audit_events` (migration 001, extended with network context in 008),
so authentication events land in the same stream the SIEM module already reads.

**No token material is ever recorded.** Not access tokens, not refresh tokens,
not their hashes, not passwords. Sessions are identified by `jti` and by the
`token_id`/`family_id` UUIDs from `refresh_tokens` — opaque identifiers that
support an investigation without being usable to authenticate. `_scrub()` is a
last-resort filter over the detail payload for anything that slips through.

Auditing must never break a request: a failed audit write is logged and
swallowed. Losing an audit row is bad; refusing a valid login because the audit
table is full is worse.
"""

import json
import logging
from typing import Any, Dict, Optional

import asyncpg
from fastapi import Request

logger = logging.getLogger("quanseq.auth.audit")

# ── Event names ──────────────────────────────────────────────────────────────
LOGIN_SUCCESS = "auth.login.success"
LOGIN_FAILURE = "auth.login.failure"
LOGIN_THROTTLED = "auth.login.throttled"
TOKEN_REFRESH = "auth.token.refresh"
LOGOUT = "auth.logout"
REVOKE_SESSION = "auth.session.revoke"
REVOKE_ALL = "auth.session.revoke_all"
TOKEN_EXPIRED = "auth.token.expired"
TOKEN_INVALID = "auth.token.invalid"
SCOPE_DENIED = "auth.scope.denied"
REFRESH_REUSE = "auth.refresh.reuse_detected"
CSRF_FAILURE = "auth.csrf.failure"

# Severity per event. Reuse detection is critical: it is the one event that
# means an active attacker, not a mistyped password.
_SEVERITY: Dict[str, str] = {
    LOGIN_SUCCESS: "info",
    LOGIN_FAILURE: "warning",
    LOGIN_THROTTLED: "warning",
    TOKEN_REFRESH: "info",
    LOGOUT: "info",
    REVOKE_SESSION: "info",
    REVOKE_ALL: "warning",
    TOKEN_EXPIRED: "info",
    TOKEN_INVALID: "warning",
    SCOPE_DENIED: "warning",
    REFRESH_REUSE: "critical",
    CSRF_FAILURE: "warning",
}

# Keys whose values are redacted before the detail payload is stored, whatever
# they contain. Defence in depth — call sites are not supposed to pass these.
_SENSITIVE_KEYS = frozenset({
    "password", "token", "raw_token", "refresh_token", "access_token",
    "token_hash", "secret", "authorization", "cookie", "csrf", "key",
    "password_hash", "client_secret",
})


async def record(
    conn: asyncpg.Connection,
    action: str,
    *,
    user_id: Optional[int] = None,
    detail: Optional[Dict[str, Any]] = None,
    severity: Optional[str] = None,
    request: Optional[Request] = None,
    resource: str = "auth",
) -> None:
    """
    Append one audit event.

    Swallows its own errors on purpose: see the module docstring. The failure is
    logged at ERROR so a broken audit path is visible in the process log.
    """
    payload = _scrub(detail or {})
    ip, user_agent = _client_context(request)

    try:
        await conn.execute(
            """INSERT INTO audit_events
                   (user_id, action, resource, detail, severity, ip_address, user_agent)
               VALUES ($1, $2, $3, $4, $5, $6::inet, $7)""",
            user_id, action, resource, json.dumps(payload, default=str),
            severity or _SEVERITY.get(action, "info"), ip, user_agent,
        )
    except Exception as exc:                     # noqa: BLE001
        logger.error("Could not write audit event %s: %s", action, exc)


def _scrub(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact anything that looks like credential material, recursively.

    Matches on substring so `refresh_token_value` and `X-CSRF-Token` are caught
    as readily as `token`.
    """
    clean: Dict[str, Any] = {}
    for key, value in detail.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in _SENSITIVE_KEYS):
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = _scrub(value)
        else:
            clean[key] = value
    return clean


def _client_context(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    """
    Client IP and User-Agent.

    X-Forwarded-For is honoured only when TRUSTED_PROXY is set: any client can
    send that header, so trusting it unconditionally lets an attacker forge the
    source address in the audit log and evade per-IP throttling.
    """
    if request is None:
        return None, None

    from core.config import settings

    ip: Optional[str] = None
    if getattr(settings, "TRUSTED_PROXY", False):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
    if not ip and request.client:
        ip = request.client.host

    user_agent = (request.headers.get("user-agent") or "")[:400] or None
    return _valid_ip(ip), user_agent


def _valid_ip(value: Optional[str]) -> Optional[str]:
    """
    Return `value` only if it parses as an IP address, else None.

    `request.client.host` is not guaranteed to be an address: Starlette's
    TestClient reports the literal "testclient", and a Unix-socket or otherwise
    unusual transport can report a non-address too. `ip_address` and
    `audit_events.ip_address` are INET columns, so passing one of those straight
    through makes PostgreSQL reject the INSERT — which, on the login path, would
    turn an unparseable peer address into a failed login.

    An unknown address is recorded as NULL. Losing one audit field is the
    correct trade against refusing the request.
    """
    if not value:
        return None
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def client_ip(request: Optional[Request]) -> Optional[str]:
    """Public helper — the rate limiter keys on the same value the audit logs."""
    return _client_context(request)[0]
