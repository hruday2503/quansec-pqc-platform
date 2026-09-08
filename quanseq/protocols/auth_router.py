"""
protocols/auth_router.py — authentication endpoints.

  POST /api/auth/login         credentials -> access token + refresh cookie
  POST /api/auth/login-scoped  as above, restricted to one portal
  POST /api/auth/refresh       rotate the refresh token, mint a new access token
  POST /api/auth/logout        revoke this session
  POST /api/auth/revoke-all    revoke every session for the caller
  GET  /api/auth/me            current principal, role, portal and scopes
  GET  /api/auth/sessions      live sessions for the caller
  POST /api/auth/register      admin-only: create a user
  GET  /api/auth/users         admin-only: list users

TWO CLIENT SHAPES
-----------------
Browsers get the refresh token in a Secure/HttpOnly/SameSite cookie scoped to
/api/auth, and it is **not** in the JSON body — a response body is reachable
from JavaScript, which would undo the point of HttpOnly.

Non-browser clients (scripts, tests, the CLI) pass `?use_cookie=false` and
receive the refresh token in the body, because they have no cookie jar. They are
then exempt from CSRF, having no ambient credential to forge.

ERROR RESPONSES ARE UNIFORM
---------------------------
Every credential failure returns the same 401 and the same message. "No such
user" and "wrong password" must be indistinguishable, or the endpoint becomes an
account-enumeration oracle. The specific reason goes to the audit log instead.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from core import audit, csrf, ratelimit
from core.auth import authenticate_user, hash_password, require_admin, require_user
from core.config import settings
from core.database import get_db
from core.scopes import describe, scopes_for
from core.tokens import (
    RefreshOutcome,
    create_access_token,
    issue_refresh_token,
    list_sessions,
    revoke_all_for_user,
    revoke_token,
    rotate_refresh_token,
)

logger = logging.getLogger("quanseq.auth.router")
router = APIRouter(prefix="/api/auth", tags=["Auth"])

# One message for every credential failure. See the module docstring.
_GENERIC_AUTH_ERROR = "Incorrect email or password"
_GENERIC_REFRESH_ERROR = "Invalid or expired session. Please log in again."


# ── Models ───────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    """
    Login and refresh response.

    `refresh_token` is populated only for non-cookie clients. For a browser it
    stays None and the value is in the HttpOnly cookie instead.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds")
    role: str
    email: str
    portal: str
    scopes: List[str]
    refresh_token: Optional[str] = None
    csrf_token: Optional[str] = None


class RefreshRequest(BaseModel):
    """Body for POST /refresh. Omit entirely when using the cookie."""

    refresh_token: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    created_at: datetime
    portal: Optional[str] = None


class MeResponse(BaseModel):
    id: int
    email: str
    role: str
    portal: Optional[str] = None
    created_at: Optional[datetime] = None
    scopes: List[str]
    scope_descriptions: Dict[str, str]
    auth_method: str


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=12,
                          description="Minimum 12 characters, hashed with Argon2id")
    role: str = "operator"
    portal: str = "main"


class RevocationResponse(BaseModel):
    revoked: int
    detail: str


# ── Cookie helpers ───────────────────────────────────────────────────────────

def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    """
    Store the refresh token in the browser.

    httponly    script cannot read it, so an XSS payload cannot steal the
                long-lived credential even though it can call the API.
    secure      not sent over plaintext HTTP (disable only for local dev).
    samesite    blocks the cross-site form POST.
    path        /api/auth — never attached to protocol API calls at all.
    max_age     matches the server-side expiry, so a dead cookie is not kept.
    """
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
        max_age=settings.REFRESH_TOKEN_TTL_DAYS * 24 * 3600,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
    )
    csrf.clear_csrf_cookie(response)


async def _issue_session(
    conn: asyncpg.Connection,
    request: Request,
    response: Response,
    user: Dict[str, Any],
    *,
    use_cookie: bool,
) -> TokenResponse:
    """
    Mint an access token and open a refresh-token family.

    Scopes come from `scopes_for(role, portal)` reading the database row. No
    part of the request contributes to them.
    """
    scopes = scopes_for(user["role"], user.get("portal"))
    access = create_access_token(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        portal=user.get("portal") or "main",
        scopes=scopes,
    )

    refresh = await issue_refresh_token(
        conn,
        user_id=user["id"],
        user_agent=request.headers.get("user-agent"),
        ip_address=audit.client_ip(request),
    )

    csrf_token: Optional[str] = None
    if use_cookie:
        _set_refresh_cookie(response, refresh["raw_token"])
        csrf_token = csrf.generate_csrf_token()
        csrf.set_csrf_cookie(response, csrf_token)

    await audit.record(
        conn, audit.LOGIN_SUCCESS,
        user_id=user["id"],
        detail={
            "email": user["email"],
            "role": user["role"],
            "portal": user.get("portal"),
            "scopes": scopes,
            "jti": access["jti"],
            "token_id": refresh["token_id"],
            "family_id": refresh["family_id"],
            "delivery": "cookie" if use_cookie else "body",
        },
        request=request,
    )

    return TokenResponse(
        access_token=access["token"],
        expires_in=access["expires_in"],
        role=user["role"],
        email=user["email"],
        portal=user.get("portal") or "main",
        scopes=scopes,
        # Withheld for cookie clients on purpose — see the class docstring.
        refresh_token=None if use_cookie else refresh["raw_token"],
        csrf_token=csrf_token,
    )


# ── Login ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    use_cookie: bool = Query(True, description="False returns the refresh token "
                                               "in the body, for non-browser clients"),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Log in with email and password. The OAuth2 `username` field is the email.

    Throttled on IP + email. Every failure returns the same message.
    """
    ip = audit.client_ip(request)
    limit = await ratelimit.login_limit(conn, ip=ip, email=form.username)
    if limit.limited:
        await audit.record(
            conn, audit.LOGIN_THROTTLED,
            detail={"email": form.username, "retry_after": limit.retry_after,
                    "backend": limit.backend},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(limit.retry_after)},
        )

    user = await authenticate_user(conn, form.username, form.password)
    if user is None:
        await audit.record(
            conn, audit.LOGIN_FAILURE,
            detail={"email": form.username, "reason": "invalid_credentials"},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_AUTH_ERROR)

    await ratelimit.reset(conn, scope="login",
                          identifier=f"{ip or '-'}:{form.username.strip().lower()}")
    return await _issue_session(conn, request, response, user, use_cookie=use_cookie)


@router.post("/login-scoped", response_model=TokenResponse)
async def login_scoped(
    request: Request,
    response: Response,
    portal: str,
    form: OAuth2PasswordRequestForm = Depends(),
    use_cookie: bool = Query(True),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Portal-scoped login, used by the per-protocol login pages.

    A portal mismatch returns the same 401 as bad credentials. Saying "this
    account exists but is not registered for the TLS portal" would confirm the
    account exists, which is exactly what the uniform error prevents.
    """
    ip = audit.client_ip(request)
    limit = await ratelimit.login_limit(conn, ip=ip, email=form.username)
    if limit.limited:
        await audit.record(
            conn, audit.LOGIN_THROTTLED,
            detail={"email": form.username, "portal": portal,
                    "retry_after": limit.retry_after},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(limit.retry_after)},
        )

    user = await authenticate_user(conn, form.username, form.password)
    if user is None:
        await audit.record(
            conn, audit.LOGIN_FAILURE,
            detail={"email": form.username, "portal": portal,
                    "reason": "invalid_credentials"},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_AUTH_ERROR)

    # Admins reach every portal; 'main' is the cross-protocol portal.
    user_portal = (user.get("portal") or "main").strip().lower()
    allowed = (user["role"] == "admin" or user_portal == "main"
               or user_portal == portal.strip().lower())
    if not allowed:
        await audit.record(
            conn, audit.LOGIN_FAILURE,
            user_id=user["id"],
            detail={"email": user["email"], "requested_portal": portal,
                    "user_portal": user_portal, "reason": "portal_mismatch"},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_AUTH_ERROR)

    await ratelimit.reset(conn, scope="login",
                          identifier=f"{ip or '-'}:{form.username.strip().lower()}")
    return await _issue_session(conn, request, response, user, use_cookie=use_cookie)


# ── Refresh ──────────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Rotate the refresh token and mint a new access token.

    The presented token is consumed: after this call it is dead, and presenting
    it again is treated as theft and kills the whole family. That is the point
    of rotation — a stolen token is only useful until the real client next
    refreshes, and the collision is then detectable.

    Every failure path clears the cookie. Leaving a dead cookie in place would
    make the client retry forever against a token that can never work.
    """
    ip = audit.client_ip(request)
    limit = await ratelimit.refresh_limit(conn, ip=ip)
    if limit.limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many refresh attempts. Try again later.",
            headers={"Retry-After": str(limit.retry_after)},
        )

    body_token = body.refresh_token if body else None
    from_cookie = csrf.is_cookie_authenticated(request, body_token)

    if from_cookie:
        try:
            csrf.verify_csrf(request)
        except HTTPException:
            await audit.record(
                conn, audit.CSRF_FAILURE,
                detail={"path": request.url.path, "reason": "csrf_mismatch"},
                request=request,
            )
            raise

    raw_token = body_token or request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_REFRESH_ERROR)

    result = await rotate_refresh_token(
        conn, raw_token,
        user_agent=request.headers.get("user-agent"),
        ip_address=ip,
    )
    outcome = result["outcome"]

    if outcome == RefreshOutcome.REUSED:
        # The single most serious event this module can emit. The family is
        # already revoked by rotate_refresh_token(); this records why.
        await audit.record(
            conn, audit.REFRESH_REUSE,
            user_id=result.get("user_id"),
            detail={
                "family_id": result.get("family_id"),
                "token_id": result.get("token_id"),
                "revoked_count": result.get("revoked_count"),
                "note": "Rotated refresh token presented again - "
                        "entire family revoked as suspected theft",
            },
            severity="critical",
            request=request,
        )
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_REFRESH_ERROR)

    if outcome != RefreshOutcome.OK:
        await audit.record(
            conn,
            audit.TOKEN_EXPIRED if outcome == RefreshOutcome.EXPIRED else audit.TOKEN_INVALID,
            user_id=result.get("user_id"),
            detail={"reason": outcome, "token_id": result.get("token_id"),
                    "path": request.url.path},
            request=request,
        )
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_GENERIC_REFRESH_ERROR)

    # Scopes are recomputed from the user's current role and portal, so a
    # demotion takes effect at the next refresh rather than at the next login.
    scopes = scopes_for(result["role"], result.get("portal"))
    access = create_access_token(
        user_id=result["user_id"],
        email=result["email"],
        role=result["role"],
        portal=result.get("portal") or "main",
        scopes=scopes,
    )

    successor = result["refresh"]
    csrf_token: Optional[str] = None
    if from_cookie:
        _set_refresh_cookie(response, successor["raw_token"])
        csrf_token = csrf.generate_csrf_token()
        csrf.set_csrf_cookie(response, csrf_token)

    await audit.record(
        conn, audit.TOKEN_REFRESH,
        user_id=result["user_id"],
        detail={
            "jti": access["jti"],
            "previous_token_id": result["previous_token_id"],
            "new_token_id": successor["token_id"],
            "family_id": successor["family_id"],
            "delivery": "cookie" if from_cookie else "body",
        },
        request=request,
    )

    return TokenResponse(
        access_token=access["token"],
        expires_in=access["expires_in"],
        role=result["role"],
        email=result["email"],
        portal=result.get("portal") or "main",
        scopes=scopes,
        refresh_token=None if from_cookie else successor["raw_token"],
        csrf_token=csrf_token,
    )


# ── Logout ───────────────────────────────────────────────────────────────────

@router.post("/logout", response_model=RevocationResponse)
async def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Revoke this session's refresh token and clear the cookies.

    Intentionally does not require an access token: a user whose access token
    has already expired must still be able to log out, and refusing that would
    leave the refresh token live for its full 7 days.

    Always reports success. Whether the token existed is not something an
    unauthenticated caller should learn, and logging out twice is not an error.
    """
    body_token = body.refresh_token if body else None
    from_cookie = csrf.is_cookie_authenticated(request, body_token)

    if from_cookie:
        try:
            csrf.verify_csrf(request)
        except HTTPException:
            await audit.record(
                conn, audit.CSRF_FAILURE,
                detail={"path": request.url.path, "reason": "csrf_mismatch"},
                request=request,
            )
            raise

    raw_token = body_token or request.cookies.get(settings.REFRESH_COOKIE_NAME)
    revoked = 0
    if raw_token:
        row = await revoke_token(conn, raw_token, reason="logout")
        if row:
            revoked = 1
            await audit.record(
                conn, audit.LOGOUT,
                user_id=row["user_id"],
                detail={"token_id": str(row["token_id"]),
                        "family_id": str(row["family_id"])},
                request=request,
            )

    _clear_refresh_cookie(response)
    return RevocationResponse(revoked=revoked, detail="Logged out")


@router.post("/revoke-all", response_model=RevocationResponse)
async def revoke_all(
    request: Request,
    response: Response,
    user: Dict[str, Any] = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Revoke every refresh token for the caller — all sessions, all devices.

    Requires a valid access token, unlike logout: this affects sessions beyond
    the current one, so the caller must prove who they are.

    Access tokens already issued remain valid until they expire (at most
    ACCESS_TOKEN_TTL_MINUTES). That is inherent to stateless access tokens and
    is why the window is 15 minutes.
    """
    revoked = await revoke_all_for_user(conn, user["id"], reason="revoke_all")

    await audit.record(
        conn, audit.REVOKE_ALL,
        user_id=user["id"],
        detail={"revoked_count": revoked, "email": user["email"],
                "note": f"Access tokens remain valid for up to "
                        f"{settings.ACCESS_TOKEN_TTL_MINUTES} minutes"},
        request=request,
    )

    _clear_refresh_cookie(response)
    return RevocationResponse(
        revoked=revoked,
        detail=f"Revoked {revoked} session(s). Existing access tokens expire "
               f"within {settings.ACCESS_TOKEN_TTL_MINUTES} minutes.",
    )


# ── Introspection ────────────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
async def me(user: Dict[str, Any] = Depends(require_user)):
    """
    The current principal, with the scopes it actually holds.

    Scopes are what the frontend uses to decide which controls to render. That
    is presentation only — every endpoint re-checks server-side, so hiding a
    button is never the thing that stops an action.
    """
    scopes = user.get("scopes", [])
    return MeResponse(
        id=user["id"],
        email=user["email"],
        role=user["role"],
        portal=user.get("portal"),
        created_at=user.get("created_at"),
        scopes=scopes,
        scope_descriptions={scope: describe(scope) for scope in scopes},
        auth_method=user.get("auth_method", "access_token"),
    )


@router.get("/sessions")
async def sessions(
    user: Dict[str, Any] = Depends(require_user),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Live sessions for the caller. Never exposes a token or a hash."""
    return await list_sessions(conn, user["id"])


# ── User management ──────────────────────────────────────────────────────────

@router.post("/register", response_model=UserOut, status_code=201)
async def register(
    payload: RegisterRequest,
    request: Request,
    admin: Dict[str, Any] = Depends(require_admin),
    conn: asyncpg.Connection = Depends(get_db),
):
    """Create a user. Admin only. The password is hashed with Argon2id."""
    if payload.role not in ("admin", "operator"):
        raise HTTPException(status_code=400,
                            detail="Role must be 'admin' or 'operator'")
    if payload.portal not in ("main", "tls", "ssh", "ipsec"):
        raise HTTPException(status_code=400,
                            detail="Portal must be one of: main, tls, ssh, ipsec")

    existing = await conn.fetchval(
        "SELECT id FROM users WHERE lower(email) = lower($1)", payload.email
    )
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    row = await conn.fetchrow(
        """INSERT INTO users (email, password_hash, role, portal)
           VALUES ($1, $2, $3, $4)
           RETURNING id, email, role, portal, created_at""",
        payload.email, hash_password(payload.password), payload.role, payload.portal,
    )

    await audit.record(
        conn, "auth.user.create",
        user_id=admin["id"],
        detail={"new_user": payload.email, "role": payload.role,
                "portal": payload.portal,
                "granted_scopes": scopes_for(payload.role, payload.portal)},
        severity="warning",
        request=request,
    )
    return dict(row)


@router.get("/users", response_model=List[UserOut])
async def list_users(
    admin: Dict[str, Any] = Depends(require_admin),
    conn: asyncpg.Connection = Depends(get_db),
):
    rows = await conn.fetch(
        "SELECT id, email, role, portal, created_at FROM users ORDER BY id"
    )
    return [dict(row) for row in rows]


@router.get("/scopes")
async def scope_matrix(user: Dict[str, Any] = Depends(require_user)):
    """
    The scope vocabulary and the role mapping, for the docs and the UI.

    Read-only reference data. Exposing it to any authenticated user is safe:
    knowing that `tls:admin` exists does not help anyone obtain it.
    """
    from core.scopes import ALL_SCOPES

    return {
        "scopes": {scope: describe(scope) for scope in sorted(ALL_SCOPES)},
        "role_mapping": {
            "admin": scopes_for("admin", None),
            "operator (portal=main)": scopes_for("operator", "main"),
            "operator (portal=tls)": scopes_for("operator", "tls"),
            "operator (portal=ssh)": scopes_for("operator", "ssh"),
            "operator (portal=ipsec)": scopes_for("operator", "ipsec"),
        },
        "your_scopes": user.get("scopes", []),
    }
