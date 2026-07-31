"""
core/csrf.py — double-submit CSRF protection for the cookie-authenticated
routes.

WHY THIS IS NEEDED AT ALL
-------------------------
The refresh token lives in an HttpOnly cookie, which the browser attaches
automatically. That is what stops JavaScript from reading it — and also what
makes `POST /api/auth/refresh` forgeable: a page on another origin can submit a
form to it and the browser will send the cookie along. The response would be a
fresh access token, which the attacker cannot read cross-origin, but logout and
revoke-all are equally forgeable and their *effect* is the attack.

THE MECHANISM
-------------
At login the server sets two cookies:

    quansec_refresh   HttpOnly  — the token itself, unreadable by script
    quansec_csrf      readable  — a random value, deliberately NOT HttpOnly

The client reads the second and echoes it in the `X-CSRF-Token` header. The
server requires the two to match. A cross-origin attacker can cause the cookies
to be *sent* but cannot *read* the CSRF cookie to construct the header — the
same-origin policy stops that — and so cannot forge the request.

SameSite=Lax already blocks the plain cross-site form POST. This is the second
layer, for same-site subdomain attacks and for browsers where the SameSite
default cannot be relied on.
"""

import hmac
import logging
import secrets
from typing import Optional

from fastapi import HTTPException, Request, Response, status

from core.config import settings

logger = logging.getLogger("quansec.auth.csrf")

CSRF_TOKEN_BYTES = 32


def generate_csrf_token() -> str:
    """A new CSRF token: 32 bytes from the OS CSPRNG."""
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def set_csrf_cookie(response: Response, token: str) -> None:
    """
    Set the CSRF cookie.

    `httponly=False` is required, not an oversight: the client has to read this
    value to put it in the header. It is safe to expose precisely because
    knowing it is useless without also being able to send it from the user's
    browser, which is what the same-origin policy prevents.
    """
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
        max_age=settings.REFRESH_TOKEN_TTL_DAYS * 24 * 3600,
    )


def clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
    )


def verify_csrf(request: Request) -> None:
    """
    Enforce the double-submit match. Raises 403 on failure.

    Only applies to cookie-authenticated requests: a caller that presents the
    refresh token in the JSON body is not relying on ambient browser
    credentials, so there is nothing for an attacker to forge and no CSRF
    exposure. `is_cookie_authenticated()` makes that determination.

    The comparison is `hmac.compare_digest` — a plain `==` on a secret leaks its
    prefix through timing.
    """
    cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
    header_token = request.headers.get(settings.CSRF_HEADER_NAME)

    if not cookie_token or not header_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Missing CSRF token. Read the {settings.CSRF_COOKIE_NAME} cookie "
                f"and send it in the {settings.CSRF_HEADER_NAME} header."
            ),
        )

    if not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch",
        )


def is_cookie_authenticated(request: Request, body_token: Optional[str]) -> bool:
    """
    Whether this request relies on the cookie rather than an explicit token.

    A body-supplied token wins: a non-browser client that sends one explicitly
    is not exposed to CSRF and should not be made to carry a header it has no
    way to obtain.
    """
    if body_token:
        return False
    return settings.REFRESH_COOKIE_NAME in request.cookies
