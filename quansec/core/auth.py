"""
core/auth.py — JWT authentication and role-based access control.

Roles:
  admin    — full control, can manage users
  operator — can read all data and trigger actions, cannot manage users

Usage in routers:
    from core.auth import require_user, require_admin

    @router.get("/something", dependencies=[Depends(require_user)])
    async def something(): ...

    @router.post("/admin-only", dependencies=[Depends(require_admin)])
    async def admin_thing(): ...

Or to access the current user:
    @router.get("/me")
    async def me(user: dict = Depends(require_user)):
        return user
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings
from core.database import get_db

# ── Password hashing ──────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


# ── JWT ─────────────────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_access_token(user_id: int, email: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload = {
        "sub":   str(user_id),
        "email": email,
        "role":  role,
        "exp":   expire,
        "iat":   datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Dependencies ──────────────────────────────────────────────────────────────
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    conn: asyncpg.Connection = Depends(get_db),
) -> dict:
    # API key path — long-lived keys for server-to-server integration
    if token.startswith("qsk_live_"):
        import hashlib
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        row = await conn.fetchrow(
            """SELECT u.id, u.email, u.role, u.created_at
               FROM api_keys k JOIN users u ON u.id = k.user_id
               WHERE k.key_hash = $1 AND k.revoked_at IS NULL""",
            key_hash,
        )
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")
        await conn.execute(
            "UPDATE api_keys SET last_used = NOW() WHERE key_hash = $1", key_hash
        )
        return dict(row)

    # JWT path — short-lived session tokens for dashboard logins
    payload = decode_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    row = await conn.fetchrow(
        "SELECT id, email, role, created_at FROM users WHERE id = $1", int(user_id)
    )
    if not row:
        raise HTTPException(status_code=401, detail="User no longer exists")

    return dict(row)


async def require_user(user: dict = Depends(get_current_user)) -> dict:
    """Any authenticated user (admin or operator)."""
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Admin only."""
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user
