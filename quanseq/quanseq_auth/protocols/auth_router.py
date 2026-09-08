"""
protocols/auth/router.py — authentication endpoints.

  POST /api/auth/login      OAuth2 form login → returns JWT
  POST /api/auth/register   admin-only: create a new user
  GET  /api/auth/me         current user info
  GET  /api/auth/users      admin-only: list all users
"""

from datetime import datetime
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr

from core.database import get_db
from core.auth import (
    hash_password, verify_password, create_access_token,
    require_user, require_admin,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])


# ── Models ────────────────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str

class UserOut(BaseModel):
    id: int
    email: str
    role: str
    created_at: datetime

class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str = "operator"   # admin | operator


# ── Login ─────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    OAuth2 password login. Username field = email.
    Returns a JWT bearer token.
    """
    row = await conn.fetchrow(
        "SELECT id, email, role, password_hash FROM users WHERE email = $1",
        form.username,
    )
    if not row or not verify_password(form.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    token = create_access_token(row["id"], row["email"], row["role"])

    # Audit
    await conn.execute(
        "INSERT INTO audit_events (user_id, action, resource, severity) VALUES ($1, $2, $3, $4)",
        row["id"], "login", "auth", "info",
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": row["role"],
        "email": row["email"],
    }


# ── Register (admin only) ──────────────────────────────────────────────────────
@router.post("/register", response_model=UserOut, status_code=201)
async def register(
    payload: RegisterRequest,
    admin: dict = Depends(require_admin),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Create a new user. Admin only."""
    if payload.role not in ("admin", "operator"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'operator'")

    existing = await conn.fetchval("SELECT id FROM users WHERE email = $1", payload.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    row = await conn.fetchrow(
        """
        INSERT INTO users (email, password_hash, role)
        VALUES ($1, $2, $3)
        RETURNING id, email, role, created_at
        """,
        payload.email, hash_password(payload.password), payload.role,
    )

    await conn.execute(
        "INSERT INTO audit_events (user_id, action, resource, detail, severity) VALUES ($1, $2, $3, $4, $5)",
        admin["id"], "create_user", "auth",
        f'{{"new_user": "{payload.email}", "role": "{payload.role}"}}', "warning",
    )

    return dict(row)


# ── Me ────────────────────────────────────────────────────────────────────────
@router.get("/me", response_model=UserOut)
async def me(user: dict = Depends(require_user)):
    """Return the currently authenticated user."""
    return user


# ── List users (admin only) ─────────────────────────────────────────────────────
@router.get("/users", response_model=list[UserOut])
async def list_users(
    admin: dict = Depends(require_admin),
    conn: asyncpg.Connection = Depends(get_db),
):
    rows = await conn.fetch("SELECT id, email, role, created_at FROM users ORDER BY id")
    return [dict(r) for r in rows]
