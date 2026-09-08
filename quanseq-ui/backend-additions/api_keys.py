"""
protocols/auth/api_keys.py — long-lived API key management for customer
integration, separate from short-lived JWT session tokens.

JWT (24h) is for humans logging into the dashboard.
API keys (no expiry, revocable) are for servers/applications integrating
QUANSEQ into their own infrastructure.

  POST   /api/keys           generate a new API key
  GET    /api/keys           list your API keys (masked)
  DELETE /api/keys/{id}      revoke a key
"""

import hashlib
import secrets
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import get_db
from core.auth import require_user, get_current_user, decode_token
from fastapi.security import OAuth2PasswordBearer
from fastapi import Header

router = APIRouter(prefix="/api/keys", tags=["API Keys"])

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    name        TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    scopes      TEXT[] NOT NULL DEFAULT ARRAY['read'],
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
"""


def _generate_key() -> tuple[str, str, str]:
    """Returns (full_key, prefix_for_display, hash_for_storage)."""
    raw = secrets.token_urlsafe(32)
    full_key = f"qsk_live_{raw}"
    prefix = full_key[:14] + "..." + full_key[-4:]
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def ensure_table(conn: asyncpg.Connection):
    await conn.execute(CREATE_TABLE)


class ApiKeyCreate(BaseModel):
    name: str
    scopes: list[str] = ["read"]


class ApiKeyOut(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: list[str]
    last_used: datetime | None
    created_at: datetime
    revoked: bool


@router.post("", status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    user: dict = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Generate a new API key. The raw key is shown ONCE — store it now."""
    await ensure_table(conn)
    full_key, prefix, key_hash = _generate_key()

    row = await conn.fetchrow(
        """INSERT INTO api_keys (user_id, name, key_prefix, key_hash, scopes)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, name, key_prefix, scopes, created_at""",
        user["id"], payload.name, prefix, key_hash, payload.scopes,
    )

    await conn.execute(
        "INSERT INTO audit_events (user_id, action, resource, detail, severity) VALUES ($1,$2,$3,$4,$5)",
        user["id"], "api_key_created", "auth",
        f'{{"name": "{payload.name}"}}', "warning",
    )

    return {
        "id": row["id"],
        "name": row["name"],
        "api_key": full_key,
        "key_prefix": row["key_prefix"],
        "scopes": row["scopes"],
        "created_at": row["created_at"],
        "warning": "This is the only time the full key is shown. Store it securely.",
    }


@router.get("", response_model=list[ApiKeyOut])
async def list_api_keys(
    user: dict = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    await ensure_table(conn)
    rows = await conn.fetch(
        """SELECT id, name, key_prefix, scopes, last_used, created_at, revoked_at
           FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC""",
        user["id"],
    )
    return [
        {
            "id": r["id"], "name": r["name"], "key_prefix": r["key_prefix"],
            "scopes": r["scopes"], "last_used": r["last_used"],
            "created_at": r["created_at"], "revoked": r["revoked_at"] is not None,
        }
        for r in rows
    ]


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    await ensure_table(conn)
    result = await conn.execute(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        key_id, user["id"],
    )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Key not found or already revoked")

    await conn.execute(
        "INSERT INTO audit_events (user_id, action, resource, detail, severity) VALUES ($1,$2,$3,$4,$5)",
        user["id"], "api_key_revoked", "auth", f'{{"key_id": {key_id}}}', "warning",
    )
    return {"status": "revoked", "key_id": key_id}
