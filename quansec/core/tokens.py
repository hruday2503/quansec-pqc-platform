"""
core/tokens.py — access-token minting and verification, and refresh-token
generation, rotation and theft detection.

Two token types with deliberately different designs:

  Access token   A signed JWT. Stateless, 15 minutes, carries the scopes the
                 API authorizes against. Cannot be revoked before it expires —
                 which is exactly why it is short-lived.

  Refresh token  256 bits from `secrets.token_urlsafe`. Opaque, 7 days, stored
                 as a SHA-256 hash, single-use, and revocable. Not a JWT: it
                 needs server-side state to be revocable at all, and once state
                 is required a signed self-describing token buys nothing.

The verification rules in `decode_access_token` are the security boundary of
the whole API. Each one is written out below with the attack it stops.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence

import asyncpg
from jose import JWTError, jwt

from core.config import settings
from core.scopes import expand

logger = logging.getLogger("quansec.auth.tokens")

# Number of random bytes behind a refresh token. token_urlsafe(32) yields 32
# bytes of entropy in a 43-character string — comfortably past the 32-byte floor
# and small enough to sit in a cookie.
REFRESH_TOKEN_BYTES = 32

# Claims that must be present and non-empty. A token missing any of these is
# rejected outright rather than defaulted: a token with no `scopes` claim must
# not become a token with no scopes that still authenticates, and a token with
# no `sub` must never resolve to a user.
REQUIRED_CLAIMS = ("sub", "role", "scopes", "portal", "iat", "exp", "iss", "aud", "jti")


class TokenError(Exception):
    """
    Verification failed. Carries a machine-readable `reason` for the audit log.

    The reason is deliberately NOT sent to the client — see auth_router, which
    returns one generic message for every failure. Telling a caller whether a
    token was expired, forged, or simply for the wrong audience helps an
    attacker far more than it helps a legitimate user.
    """

    def __init__(self, reason: str, message: str = "Invalid or expired token"):
        super().__init__(message)
        self.reason = reason
        self.message = message


# ── Access tokens ────────────────────────────────────────────────────────────

def create_access_token(
    *,
    user_id: int,
    email: str,
    role: str,
    portal: str,
    scopes: Sequence[str],
    expires_in_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Mint a signed access token.

    `scopes` must come from `core.scopes.scopes_for()`. This function does not
    validate the caller's authority to request them — it is the caller's job not
    to pass anything a client supplied, and the only call site (login/refresh)
    derives them from the database row.

    Returns the token plus its metadata, so the caller can audit the `jti`
    without decoding what it just signed.
    """
    now = datetime.now(timezone.utc)
    ttl = expires_in_minutes if expires_in_minutes is not None else settings.ACCESS_TOKEN_TTL_MINUTES
    expires_at = now + timedelta(minutes=ttl)
    jti = str(uuid.uuid4())

    claims = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "portal": portal,
        "scopes": sorted(expand(scopes)),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": jti,
        "typ": "access",
    }

    token = jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {
        "token": token,
        "jti": jti,
        "expires_at": expires_at,
        "expires_in": int(ttl * 60),
        "scopes": claims["scopes"],
    }


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Verify an access token and return its claims. Raises TokenError otherwise.

    The checks, and what each one stops:

    * **Algorithm allow-list.** `algorithms=[HS384]` is a single pinned value
      read from code, never from the token or the environment. This is what
      makes `{"alg":"none"}` fail — python-jose will not verify a token whose
      header algorithm is outside the list, so an unsigned token is rejected
      before its claims are read. It equally stops the RS256->HS256 confusion
      attack, where a token is re-signed with a public key as an HMAC secret.

    * **Issuer and audience.** Verified by the library against the configured
      values. Without these a token minted by a different QUANSEC deployment,
      or a token intended for another service that happens to share the secret,
      would authenticate here.

    * **Expiry.** Enforced by the library. `iat` is not checked against the
      future: clock skew between the signer and verifier is the same process
      here, but a rejection on skew would present as a random auth failure.

    * **Required claims.** Checked explicitly after decoding, because a token
      that verifies cryptographically can still be structurally wrong — for
      instance one minted by an older build with no `scopes`.

    * **Token type.** `typ` must be `access`. Prevents any other signed artifact
      the platform might later mint from being replayed as an access token.
    """
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET,
            # A list of exactly one. Never widen this, and never source it from
            # a request or an environment variable.
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "require_exp": True,
                "require_iat": True,
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("expired_token") from exc
    except jwt.JWTClaimsError as exc:
        # Raised for a bad audience or issuer. The message distinguishes them
        # for the audit log; the client is told neither.
        detail = str(exc).lower()
        if "audience" in detail:
            raise TokenError("invalid_audience") from exc
        if "issuer" in detail:
            raise TokenError("invalid_issuer") from exc
        raise TokenError("invalid_claims") from exc
    except JWTError as exc:
        # Bad signature, unsupported/absent algorithm, or structurally
        # malformed input all land here.
        raise TokenError("malformed_token") from exc

    missing = [claim for claim in REQUIRED_CLAIMS if claims.get(claim) in (None, "", [])]
    if missing:
        raise TokenError(f"missing_claims:{','.join(missing)}")

    if claims.get("typ") != "access":
        raise TokenError("wrong_token_type")

    try:
        int(claims["sub"])
    except (TypeError, ValueError) as exc:
        raise TokenError("invalid_subject") from exc

    if not isinstance(claims.get("scopes"), list):
        raise TokenError("invalid_scopes")

    return claims


# ── Refresh tokens ───────────────────────────────────────────────────────────

def generate_refresh_token() -> str:
    """A new refresh token: 32 bytes from the OS CSPRNG, URL-safe."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(raw: str) -> str:
    """
    SHA-256 of a refresh token, hex.

    Plain SHA-256 rather than Argon2/bcrypt is deliberate. Those exist to make
    guessing a *low-entropy* secret expensive. A refresh token is 256 random
    bits; there is no dictionary to slow down, and a per-request KDF would only
    add latency to the refresh path. What matters is that the raw value is never
    written to the database or a log, which this guarantees.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def issue_refresh_token(
    conn: asyncpg.Connection,
    *,
    user_id: int,
    family_id: Optional[str] = None,
    parent_id: Optional[int] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_label: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create and store a refresh token. Returns the raw token and its row.

    A new `family_id` starts a fresh login; passing an existing one continues
    that family through a rotation. The raw token is returned to the caller and
    then exists only in the response — never in the database, never in a log.
    """
    raw = generate_refresh_token()
    token_hash = hash_refresh_token(raw)
    family = family_id or str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)

    row = await conn.fetchrow(
        """INSERT INTO refresh_tokens (
               family_id, user_id, token_hash, parent_id, expires_at,
               user_agent, ip_address, device_label
           ) VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8)
           RETURNING id, token_id, family_id, user_id, issued_at, expires_at""",
        family, user_id, token_hash, parent_id, expires_at,
        _truncate(user_agent, 400), ip_address, _truncate(device_label, 100),
    )

    return {
        "raw_token": raw,
        "id": row["id"],
        "token_id": str(row["token_id"]),
        "family_id": str(row["family_id"]),
        "user_id": row["user_id"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
    }


class RefreshOutcome:
    """Why a refresh attempt ended the way it did."""

    OK = "ok"
    UNKNOWN = "unknown_token"        # no such hash — forged, or already pruned
    EXPIRED = "expired"
    REVOKED = "revoked"              # logout or revoke-all
    REUSED = "reuse_detected"        # rotated token presented again: theft


async def rotate_refresh_token(
    conn: asyncpg.Connection,
    raw_token: str,
    *,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validate a refresh token and rotate it. The core of theft detection.

    On success the presented token is marked `rotated`, a successor is issued in
    the same family, and the two are linked. The old token is dead from this
    moment — that is what makes reuse detectable at all.

    On reuse — a token that has already been rotated being presented again — the
    **entire family is revoked**, including the successor currently in
    legitimate use. Both the thief and the real user are logged out, which is
    the intended outcome: the two are indistinguishable from here, and the safe
    reading is that the chain is compromised. The real user logs in again; the
    thief cannot.

    Returns {"outcome": ..., ...}. Never raises for an invalid token — the
    caller decides the HTTP response and the audit entry.
    """
    token_hash = hash_refresh_token(raw_token)

    row = await conn.fetchrow(
        """SELECT r.id, r.token_id, r.family_id, r.user_id, r.expires_at,
                  r.revoked_at, r.revoked_reason, r.replaced_by,
                  u.email, u.role, u.portal
           FROM refresh_tokens r
           JOIN users u ON u.id = r.user_id
           WHERE r.token_hash = $1""",
        token_hash,
    )

    if row is None:
        return {"outcome": RefreshOutcome.UNKNOWN}

    now = datetime.now(timezone.utc)
    context = {
        "token_id": str(row["token_id"]),
        "family_id": str(row["family_id"]),
        "user_id": row["user_id"],
        "email": row["email"],
        "role": row["role"],
        "portal": row["portal"],
    }

    # Reuse is checked FIRST, before revocation and expiry. A stolen token that
    # has been rotated is usually also already revoked (the family died with an
    # earlier detection), and reporting that as a plain "revoked" would hide the
    # attack in the audit log behind an ordinary logout.
    if row["replaced_by"] is not None:
        revoked = await revoke_family(
            conn, str(row["family_id"]), reason="reuse_detected"
        )
        logger.warning(
            "Refresh-token reuse detected for user %s (family %s) - "
            "revoked %d token(s) in the family",
            row["user_id"], row["family_id"], revoked,
        )
        return {**context, "outcome": RefreshOutcome.REUSED, "revoked_count": revoked}

    if row["revoked_at"] is not None:
        return {**context, "outcome": RefreshOutcome.REVOKED,
                "reason": row["revoked_reason"]}

    if row["expires_at"] <= now:
        return {**context, "outcome": RefreshOutcome.EXPIRED}

    # Valid. Issue the successor inside the same family, then close the old one.
    successor = await issue_refresh_token(
        conn,
        user_id=row["user_id"],
        family_id=str(row["family_id"]),
        parent_id=row["id"],
        user_agent=user_agent,
        ip_address=ip_address,
    )

    await conn.execute(
        """UPDATE refresh_tokens
           SET replaced_by = $1, revoked_at = NOW(), revoked_reason = 'rotated',
               last_used_at = NOW()
           WHERE id = $2""",
        successor["id"], row["id"],
    )

    return {
        **context,
        "outcome": RefreshOutcome.OK,
        "previous_token_id": str(row["token_id"]),
        "refresh": successor,
    }


async def revoke_token(conn: asyncpg.Connection, raw_token: str, *,
                       reason: str = "logout") -> Optional[Dict[str, Any]]:
    """
    Revoke a single refresh token — one session, as used by logout.

    Returns the revoked row, or None if the token was unknown or already dead.
    Idempotent: logging out twice is not an error.
    """
    row = await conn.fetchrow(
        """UPDATE refresh_tokens
           SET revoked_at = NOW(), revoked_reason = $2, last_used_at = NOW()
           WHERE token_hash = $1 AND revoked_at IS NULL
           RETURNING id, token_id, family_id, user_id""",
        hash_refresh_token(raw_token), reason,
    )
    return dict(row) if row else None


async def revoke_family(conn: asyncpg.Connection, family_id: str, *,
                        reason: str = "revoke_all") -> int:
    """Revoke every live token in one family. Returns how many were revoked."""
    result = await conn.execute(
        """UPDATE refresh_tokens
           SET revoked_at = NOW(), revoked_reason = $2
           WHERE family_id = $1::uuid AND revoked_at IS NULL""",
        family_id, reason,
    )
    return _rowcount(result)


async def revoke_all_for_user(conn: asyncpg.Connection, user_id: int, *,
                              reason: str = "revoke_all") -> int:
    """
    Revoke every live refresh token for a user — all sessions, all devices.

    Access tokens already issued stay valid until they expire; that window is
    ACCESS_TOKEN_TTL_MINUTES and is the documented cost of stateless access
    tokens. Callers who need an immediate cut-off must also change the password.
    """
    result = await conn.execute(
        """UPDATE refresh_tokens
           SET revoked_at = NOW(), revoked_reason = $2
           WHERE user_id = $1 AND revoked_at IS NULL""",
        user_id, reason,
    )
    return _rowcount(result)


async def purge_expired(conn: asyncpg.Connection, *, older_than_days: int = 30) -> int:
    """
    Delete long-dead tokens.

    Expired rows are kept for a grace period rather than removed on expiry: a
    reuse attempt against a recently expired token is a signal worth seeing, and
    deleting the row immediately would report it as `unknown_token` instead.
    """
    result = await conn.execute(
        """DELETE FROM refresh_tokens
           WHERE expires_at < NOW() - ($1 || ' days')::interval""",
        str(older_than_days),
    )
    return _rowcount(result)


async def list_sessions(conn: asyncpg.Connection, user_id: int) -> List[Dict[str, Any]]:
    """Live sessions for a user. Never exposes a hash or a raw token."""
    rows = await conn.fetch(
        """SELECT token_id, family_id, issued_at, expires_at, last_used_at,
                  user_agent, host(ip_address) AS ip_address, device_label
           FROM refresh_tokens
           WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
           ORDER BY issued_at DESC""",
        user_id,
    )
    return [dict(row) for row in rows]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _rowcount(result: str) -> int:
    """asyncpg returns tags like 'UPDATE 3'."""
    try:
        return int(result.rsplit(" ", 1)[1])
    except (AttributeError, IndexError, ValueError):
        return 0


def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    text = value.strip()
    return text[:limit] if text else None
