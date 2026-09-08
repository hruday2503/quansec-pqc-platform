"""
core/auth.py — password hashing, request authentication and scope enforcement.

Three ways a request can authenticate, all resolving to the same principal dict:

  Access token   A short-lived HS384 JWT carrying explicit scopes. The normal
                 path for the dashboard. Verified in core/tokens.py.
  API key        `qsk_live_...`, for server-to-server callers. Long-lived, and
                 its scopes come from the owning user's role at request time —
                 never from the key row — so revoking a role revokes the key's
                 reach immediately.

BACKWARD COMPATIBILITY
----------------------
`require_user` and `require_admin` keep their exact previous behaviour and
signatures. Roughly fifteen SSH, IPsec, scoring and metrics routes depend on
them, and changing what they mean would silently alter access control across
modules this work is not supposed to touch. Scope enforcement is added
alongside, through `require_scope(...)`, and applied to TLS.

`require_admin` therefore still tests `role == "admin"`. It is equivalent to
`require_scope(SYSTEM_ADMIN)` under the current role mapping, but it is left as
a role test so that changing the mapping later cannot quietly widen the
existing SSH and IPsec admin routes.
"""

import hashlib
import logging
from typing import Any, Dict, Optional

import asyncpg
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from core import audit
from core.database import get_db
from core.scopes import expand, has_any, scopes_for
from core.tokens import TokenError, decode_access_token

logger = logging.getLogger("quanseq.auth")

# ── Password hashing ─────────────────────────────────────────────────────────
#
# Argon2id is the default for new and re-hashed passwords: it is memory-hard, so
# a GPU or ASIC attacker gains far less against it than against PBKDF2.
#
# pbkdf2_sha256 and bcrypt stay in the scheme list because existing accounts are
# hashed with pbkdf2_sha256 (the seeded admin among them). Dropping them would
# lock every current user out with no way back — the plaintext needed to migrate
# a hash only exists during a login. `deprecated="auto"` marks them for upgrade,
# and authenticate_user() rewrites each hash to Argon2id the next time its owner
# logs in successfully.
pwd_context = CryptContext(
    schemes=["argon2", "pbkdf2_sha256", "bcrypt"],
    deprecated="auto",
    # OWASP Password Storage Cheat Sheet, Argon2id: 19 MiB, t=2, p=1.
    argon2__memory_cost=19456,
    argon2__time_cost=2,
    argon2__parallelism=1,
)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a password against any supported hash format.

    Returns False rather than raising on a malformed or unknown hash: a
    corrupted row must fail the login, not 500 the endpoint.
    """
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:                            # noqa: BLE001
        return False


def needs_rehash(hashed: str) -> bool:
    """Whether a stored hash uses a deprecated scheme or outdated parameters."""
    try:
        return pwd_context.needs_update(hashed)
    except Exception:                            # noqa: BLE001
        return False


async def authenticate_user(conn: asyncpg.Connection, email: str,
                            password: str) -> Optional[Dict[str, Any]]:
    """
    Verify credentials and return the user row, or None.

    Transparently upgrades a legacy pbkdf2/bcrypt hash to Argon2id on success —
    the only moment the plaintext is available to do so. The upgrade is
    best-effort: a failed write must not fail an otherwise valid login.

    A dummy hash is verified when the account does not exist so that the
    response time does not reveal whether an email is registered. Without it,
    "no such user" returns measurably faster than "wrong password", which is a
    reliable account-enumeration oracle regardless of the error message.
    """
    row = await conn.fetchrow(
        "SELECT id, email, role, portal, password_hash, created_at "
        "FROM users WHERE lower(email) = lower($1)",
        email,
    )

    if row is None:
        _dummy_verify(password)
        return None

    if not verify_password(password, row["password_hash"]):
        return None

    if needs_rehash(row["password_hash"]):
        try:
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                hash_password(password), row["id"],
            )
            logger.info("Upgraded password hash to Argon2id for user %s", row["id"])
        except Exception as exc:                 # noqa: BLE001
            logger.warning("Could not upgrade password hash for user %s: %s",
                           row["id"], exc)

    user = dict(row)
    user.pop("password_hash", None)
    return user


# A real Argon2id hash of a fixed string, computed once at import. Verifying
# against it costs the same as a genuine check.
_DUMMY_HASH = pwd_context.hash("quanseq-timing-equalizer")


def _dummy_verify(password: str) -> None:
    try:
        pwd_context.verify(password, _DUMMY_HASH)
    except Exception:                            # noqa: BLE001
        pass


# ── Request authentication ───────────────────────────────────────────────────

# auto_error=False so a missing Authorization header reaches our own handler and
# is audited, instead of FastAPI returning a bare 401 we never see.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    conn: asyncpg.Connection = Depends(get_db),
) -> Dict[str, Any]:
    """
    Resolve the caller. Raises 401 if the credential is absent or unusable.

    The returned dict keeps `id`, `email`, `role` and `created_at` so existing
    routes that index into it keep working, and adds `scopes`, `portal` and
    `auth_method`.
    """
    if not token:
        raise _UNAUTHENTICATED

    if token.startswith("qsk_live_"):
        return await _principal_from_api_key(request, token, conn)

    try:
        claims = decode_access_token(token)
    except TokenError as exc:
        action = (audit.TOKEN_EXPIRED if exc.reason == "expired_token"
                  else audit.TOKEN_INVALID)
        await audit.record(
            conn, action,
            detail={"reason": exc.reason, "path": request.url.path},
            request=request,
        )
        # One generic message for every failure. Distinguishing "expired" from
        # "bad signature" for the caller tells an attacker which half of a
        # forgery attempt worked.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return await _principal_from_claims(request, claims, conn)


async def _principal_from_claims(request: Request, claims: Dict[str, Any],
                                 conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Build the principal from verified claims, re-reading the user row.

    The database read is not redundant. A token stays valid for its full 15
    minutes, so without it a deleted user, or one demoted from admin to
    operator, would keep their old authority until the token expired. Scopes are
    recomputed from the *current* role and portal for the same reason — the
    claim in the token records what was true at issue time, and the row records
    what is true now.
    """
    user_id = int(claims["sub"])
    row = await conn.fetchrow(
        "SELECT id, email, role, portal, created_at FROM users WHERE id = $1",
        user_id,
    )
    if row is None:
        await audit.record(
            conn, audit.TOKEN_INVALID,
            detail={"reason": "user_deleted", "sub": user_id,
                    "path": request.url.path},
            request=request,
        )
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    current = scopes_for(row["role"], row["portal"])
    # Intersect with the token's own scopes: a token may hold fewer scopes than
    # the role allows (a future narrowed-scope token), and it must never gain
    # authority it was not issued with just because the role is broad.
    granted = sorted(expand(claims.get("scopes", [])) & expand(current))

    return {
        "id": row["id"],
        "email": row["email"],
        "role": row["role"],
        "portal": row["portal"],
        "created_at": row["created_at"],
        "scopes": granted,
        "jti": claims.get("jti"),
        "auth_method": "access_token",
    }


async def _principal_from_api_key(request: Request, token: str,
                                  conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Resolve an API key to a principal.

    The key's effective scopes are the INTERSECTION of what the key was issued
    with and what its owner's role grants today (migration 009 put the real
    scope vocabulary on `api_keys.scopes`).

    Intersecting on every request, rather than trusting the stored list, is what
    makes a role change take effect immediately: demoting a user from admin to
    operator narrows every key they ever issued, instead of leaving standing
    admin grants scattered across long-lived keys. The key can only ever lose
    authority this way, never gain it.
    """
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    row = await conn.fetchrow(
        """SELECT u.id, u.email, u.role, u.portal, u.created_at,
                  k.id AS key_id, k.scopes AS key_scopes, k.expires_at
           FROM api_keys k JOIN users u ON u.id = k.user_id
           WHERE k.key_hash = $1 AND k.revoked_at IS NULL""",
        key_hash,
    )
    if row is None:
        await audit.record(
            conn, audit.TOKEN_INVALID,
            detail={"reason": "invalid_api_key", "path": request.url.path},
            request=request,
        )
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    if row["expires_at"] is not None:
        from datetime import datetime, timezone
        if row["expires_at"] <= datetime.now(timezone.utc):
            await audit.record(
                conn, audit.TOKEN_EXPIRED,
                user_id=row["id"],
                detail={"reason": "expired_api_key", "key_id": row["key_id"],
                        "path": request.url.path},
                request=request,
            )
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    owner_scopes = expand(scopes_for(row["role"], row["portal"]))
    key_scopes = expand(list(row["key_scopes"] or []))
    granted = sorted(key_scopes & owner_scopes)

    await conn.execute(
        "UPDATE api_keys SET last_used = NOW() WHERE key_hash = $1", key_hash
    )

    return {
        "id": row["id"],
        "email": row["email"],
        "role": row["role"],
        "portal": row["portal"],
        "created_at": row["created_at"],
        "scopes": granted,
        "api_key_id": row["key_id"],
        "auth_method": "api_key",
    }


# ── Dependencies ─────────────────────────────────────────────────────────────

async def require_user(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Any authenticated user. Unchanged from the pre-migration behaviour.

    Still used by the SSH, IPsec, scoring, metrics, SIEM and alerts routers.
    """
    return user


async def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Admin only. Unchanged: still a role test, for the reason in the module
    docstring.
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


def require_scope(*required: str):
    """
    Build a dependency requiring any one of `required`.

        @router.post("/policy", dependencies=[Depends(require_scope(TLS_ADMIN))])

    A denial is audited with the scopes held and the scopes needed, which is
    what makes "user could not do X" answerable later without reproducing it.
    `system:admin` satisfies every check through the implication table, so it
    never has to be listed.
    """
    if not required:
        raise ValueError("require_scope() needs at least one scope")

    async def dependency(
        request: Request,
        user: Dict[str, Any] = Depends(get_current_user),
        conn: asyncpg.Connection = Depends(get_db),
    ) -> Dict[str, Any]:
        if has_any(user.get("scopes"), required):
            return user

        await audit.record(
            conn, audit.SCOPE_DENIED,
            user_id=user.get("id"),
            detail={
                "required_scopes": list(required),
                "held_scopes": user.get("scopes", []),
                "path": request.url.path,
                "method": request.method,
                "auth_method": user.get("auth_method"),
            },
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of: {', '.join(required)}",
        )

    return dependency


def require_all_scopes(*required: str):
    """Every listed scope, for the rare route that needs a conjunction."""
    if not required:
        raise ValueError("require_all_scopes() needs at least one scope")

    async def dependency(
        request: Request,
        user: Dict[str, Any] = Depends(get_current_user),
        conn: asyncpg.Connection = Depends(get_db),
    ) -> Dict[str, Any]:
        held = expand(user.get("scopes", []))
        missing = [scope for scope in required if scope not in held]
        if not missing:
            return user

        await audit.record(
            conn, audit.SCOPE_DENIED,
            user_id=user.get("id"),
            detail={"required_scopes": list(required), "missing": missing,
                    "held_scopes": sorted(held), "path": request.url.path},
            request=request,
        )
        raise HTTPException(status_code=403,
                            detail=f"Requires all of: {', '.join(required)}")

    return dependency


def has_scope(user: Dict[str, Any], *scopes: str) -> bool:
    """Non-raising check, for handlers that vary their response by authority."""
    return has_any(user.get("scopes"), scopes)


# ── Compatibility shims ──────────────────────────────────────────────────────

def decode_token(token: str) -> Dict[str, Any]:
    """
    Deprecated. `protocols/auth_api_keys.py` imports this name.

    Kept so that module keeps working; new code should call
    `core.tokens.decode_access_token`, which raises TokenError rather than
    HTTPException and so can be audited by the caller.
    """
    try:
        return decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_access_token(user_id: int, email: str, role: str) -> str:
    """
    Deprecated three-positional-argument form, preserved for any caller not yet
    migrated. Derives scopes from the role with no portal, and returns only the
    encoded string.

    New code should call `core.tokens.create_access_token`, which takes the
    portal and returns the metadata needed to audit the `jti`.
    """
    from core.tokens import create_access_token as _create

    return _create(
        user_id=user_id, email=email, role=role, portal="main",
        scopes=scopes_for(role, None),
    )["token"]
