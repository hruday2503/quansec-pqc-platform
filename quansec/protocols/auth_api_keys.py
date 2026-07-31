"""
protocols/auth_api_keys.py — long-lived API keys for machine integrations.

Distinct from the JWT session tokens in core/tokens.py:

  Access token   15 minutes, for a human logged into the dashboard.
  API key        no expiry by default, revocable, for a server or script that
                 cannot perform an interactive login.

  POST   /api/keys           issue a key (raw value returned once)
  GET    /api/keys           list your keys, masked
  DELETE /api/keys/{id}      revoke a key
  GET    /api/keys/scopes    which scopes you may grant

SCOPES
------
A key carries scopes from core/scopes.py, so it can be narrowed to exactly what
an integration needs — `tls:read` for a monitoring scraper that should never be
able to apply a policy.

**A key can never exceed its owner.** Requested scopes are intersected with the
owner's role scopes at creation, and intersected again on every request in
core/auth.py. So an operator cannot mint a `system:admin` key, and demoting a
user immediately shrinks every key they created rather than leaving a
standing grant behind.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from core import audit
from core.auth import require_user
from core.database import get_db
from core.scopes import ALL_SCOPES, describe, expand, scopes_for

router = APIRouter(prefix="/api/keys", tags=["API Keys"])

# Keys are shown to the user as a prefix plus a suffix; the middle is never
# recoverable. 32 bytes of entropy, same generator as refresh tokens.
KEY_BYTES = 32
KEY_PREFIX = "qsk_live_"


def _generate_key() -> tuple[str, str, str]:
    """Returns (full_key, masked_display, sha256_hash)."""
    raw = secrets.token_urlsafe(KEY_BYTES)
    full_key = f"{KEY_PREFIX}{raw}"
    masked = f"{full_key[:14]}...{full_key[-4:]}"
    return full_key, masked, hashlib.sha256(full_key.encode()).hexdigest()


def hash_key(raw_key: str) -> str:
    """SHA-256 of a key. The raw value is never stored — see core/tokens.py."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: List[str] = Field(
        default_factory=list,
        description="Scopes to grant. Intersected with your own — a key can "
                    "never exceed its creator. Empty means read-only.",
    )
    protocol: Optional[str] = Field(
        default=None,
        description="Which portal issued this key: tls | ssh | ipsec | main. "
                    "Presentation only; enforcement is by scope.",
    )
    expires_in_days: Optional[int] = Field(
        default=None, ge=1, le=3650,
        description="Optional expiry. Omit for a key that does not expire.",
    )


class ApiKeyOut(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: List[str]
    protocol: Optional[str] = None
    last_used: Optional[datetime] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    revoked: bool
    expired: bool = False


@router.get("/scopes")
async def grantable_scopes(user: Dict[str, Any] = Depends(require_user)):
    """
    Which scopes the caller may put on a key.

    Exactly their own, never more. The UI uses this to build the checkbox list,
    so a user is not offered a scope the server would strip anyway.
    """
    own = user.get("scopes", [])
    return {
        "grantable": own,
        "descriptions": {scope: describe(scope) for scope in own},
        "note": (
            "A key can never exceed the authority of the user who created it. "
            "Scopes are re-intersected with your role on every request, so "
            "losing a role immediately narrows every key you issued."
        ),
    }


@router.post("", status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Issue an API key. The raw value is returned ONCE and is not recoverable.

    Requesting a scope the caller does not hold is rejected outright rather than
    silently dropped: a caller that asked for `tls:admin` and received a
    read-only key would discover the difference at the worst moment.
    """
    if payload.protocol and payload.protocol not in ("tls", "ssh", "ipsec", "main"):
        raise HTTPException(status_code=400,
                            detail="protocol must be tls, ssh, ipsec or main")

    own_scopes = expand(user.get("scopes", []))
    requested = payload.scopes or []

    unknown = [s for s in requested if s not in ALL_SCOPES]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scope(s): {unknown}. Valid: {sorted(ALL_SCOPES)}",
        )

    over_reach = [s for s in requested if s not in own_scopes]
    if over_reach:
        await audit.record(
            conn, audit.SCOPE_DENIED,
            user_id=user["id"],
            detail={"requested_scopes": requested, "held_scopes": sorted(own_scopes),
                    "over_reach": over_reach, "path": "/api/keys"},
            request=request,
        )
        raise HTTPException(
            status_code=403,
            detail=f"You cannot grant scope(s) you do not hold: {over_reach}",
        )

    # No scopes requested → read-only within what the caller actually has.
    granted = sorted(expand(requested) & own_scopes) if requested else sorted(
        s for s in own_scopes if s.endswith(":read")
    )
    if not granted:
        raise HTTPException(
            status_code=400,
            detail="No grantable scopes. Your account holds none of the "
                   "requested permissions.",
        )

    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days else None
    )

    full_key, masked, key_hash = _generate_key()
    row = await conn.fetchrow(
        """INSERT INTO api_keys (user_id, name, key_prefix, key_hash, scopes,
                                 protocol, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, name, key_prefix, scopes, protocol, created_at, expires_at""",
        user["id"], payload.name, masked, key_hash, granted,
        payload.protocol, expires_at,
    )

    await audit.record(
        conn, "auth.api_key.create",
        user_id=user["id"],
        detail={"key_id": row["id"], "name": payload.name, "scopes": granted,
                "protocol": payload.protocol,
                "expires_at": expires_at.isoformat() if expires_at else None},
        severity="warning",
        request=request,
    )

    return {
        "id": row["id"],
        "name": row["name"],
        # The only time this value exists outside the caller's process.
        "api_key": full_key,
        "key_prefix": row["key_prefix"],
        "scopes": row["scopes"],
        "protocol": row["protocol"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "warning": "This is the only time the full key is shown. Store it now — "
                   "only its SHA-256 hash is kept, so it cannot be recovered.",
    }


@router.get("", response_model=List[ApiKeyOut])
async def list_api_keys(
    protocol: Optional[str] = Query(None, description="Filter by issuing portal"),
    include_revoked: bool = Query(True),
    user: Dict[str, Any] = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Your API keys, masked. The hash is never returned."""
    clauses = ["user_id = $1"]
    params: List[Any] = [user["id"]]

    if protocol:
        params.append(protocol)
        clauses.append(f"protocol = ${len(params)}")
    if not include_revoked:
        clauses.append("revoked_at IS NULL")

    rows = await conn.fetch(
        f"""SELECT id, name, key_prefix, scopes, protocol, last_used,
                   created_at, expires_at, revoked_at
            FROM api_keys
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at DESC""",
        *params,
    )

    now = datetime.now(timezone.utc)
    return [
        {
            "id": r["id"], "name": r["name"], "key_prefix": r["key_prefix"],
            "scopes": list(r["scopes"] or []), "protocol": r["protocol"],
            "last_used": r["last_used"], "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "revoked": r["revoked_at"] is not None,
            "expired": bool(r["expires_at"] and r["expires_at"] <= now),
        }
        for r in rows
    ]


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    request: Request,
    user: Dict[str, Any] = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Revoke a key. Takes effect immediately — core/auth.py rejects any key whose
    `revoked_at` is set.

    Scoped to the caller's own keys, so `key_id` cannot be used to revoke
    someone else's integration.
    """
    result = await conn.execute(
        """UPDATE api_keys SET revoked_at = NOW()
           WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL""",
        key_id, user["id"],
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404,
                            detail="Key not found or already revoked")

    await audit.record(
        conn, "auth.api_key.revoke",
        user_id=user["id"], detail={"key_id": key_id},
        severity="warning", request=request,
    )
    return {"status": "revoked", "key_id": key_id}
