"""
core/ratelimit.py — fixed-window throttling for the authentication endpoints.

Brute-force and credential-stuffing defence for `/api/auth/login` and
`/api/auth/refresh`. Redis is the primary counter (`get_redis_optional`, already
used by the collectors); PostgreSQL's `auth_throttle` table is the fallback.

**The fallback is the point.** A limiter that silently stops limiting when its
cache is unreachable is worse than no limiter, because nobody notices. If Redis
is down the counter degrades to a slower database write rather than to
unlimited attempts.

Login is limited on **IP + email** rather than IP alone: limiting by IP only
lets one attacker behind a shared NAT lock out an entire office, while limiting
by email only lets an attacker lock any account they can name. Combining them
throttles the actual attack — many guesses at one account from one source —
without giving anyone an account-lockout weapon.
"""

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional

import asyncpg

from core.config import settings
from core.redis_client import get_redis_optional

logger = logging.getLogger("quansec.auth.ratelimit")

_KEY_PREFIX = "quansec:auth:throttle:"


@dataclass
class RateLimitResult:
    """Outcome of one throttle check."""

    allowed: bool
    remaining: int
    retry_after: int = 0
    backend: str = "redis"

    @property
    def limited(self) -> bool:
        return not self.allowed


def _bucket_key(*parts: Optional[str]) -> str:
    """
    Hash the identifying parts into an opaque bucket key.

    Hashed so neither Redis nor `auth_throttle` becomes a browsable list of
    which addresses tried which accounts — the throttle store is not a place to
    accumulate a login-attempt history in the clear.
    """
    material = "|".join(part or "-" for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


async def check(
    conn: Optional[asyncpg.Connection],
    *,
    scope: str,
    identifier: str,
    limit: int,
    window_seconds: int,
    lockout_seconds: int = 0,
) -> RateLimitResult:
    """
    Count one attempt against a fixed window.

    Args:
        scope: logical bucket, e.g. "login" or "refresh".
        identifier: what is being limited — already-combined IP and/or email.
        limit: attempts permitted per window.
        window_seconds: window length.
        lockout_seconds: once the limit is passed, how long to keep refusing.
            Zero means the window simply has to drain.

    A failure in the limiter itself allows the request. Availability wins here:
    the endpoints behind it still verify credentials, so a broken counter means
    "unthrottled", not "unauthenticated".
    """
    key = _bucket_key(scope, identifier)

    redis = await get_redis_optional()
    if redis is not None:
        try:
            return await _check_redis(redis, key, limit, window_seconds, lockout_seconds)
        except Exception as exc:                 # noqa: BLE001
            logger.warning("Redis throttle failed (%s) - falling back to PostgreSQL", exc)

    if conn is not None:
        try:
            return await _check_postgres(conn, key, limit, window_seconds, lockout_seconds)
        except Exception as exc:                 # noqa: BLE001
            logger.error("PostgreSQL throttle failed: %s - allowing request", exc)

    return RateLimitResult(allowed=True, remaining=limit, backend="none")


async def _check_redis(redis, key: str, limit: int, window_seconds: int,
                       lockout_seconds: int) -> RateLimitResult:
    """INCR with a TTL — a fixed window, atomic without a Lua script."""
    lock_key = f"{_KEY_PREFIX}lock:{key}"
    locked_ttl = await redis.ttl(lock_key)
    if locked_ttl and locked_ttl > 0:
        return RateLimitResult(False, 0, retry_after=locked_ttl, backend="redis")

    counter_key = f"{_KEY_PREFIX}{key}"
    pipe = redis.pipeline()
    pipe.incr(counter_key)
    pipe.ttl(counter_key)
    count, ttl = await pipe.execute()

    # A brand-new key has no TTL; set it so the window can actually expire.
    if ttl is None or ttl < 0:
        await redis.expire(counter_key, window_seconds)
        ttl = window_seconds

    if count > limit:
        if lockout_seconds:
            await redis.setex(lock_key, lockout_seconds, "1")
            return RateLimitResult(False, 0, retry_after=lockout_seconds, backend="redis")
        return RateLimitResult(False, 0, retry_after=int(ttl), backend="redis")

    return RateLimitResult(True, max(0, limit - int(count)), backend="redis")


async def _check_postgres(conn: asyncpg.Connection, key: str, limit: int,
                          window_seconds: int, lockout_seconds: int) -> RateLimitResult:
    """
    Durable fallback.

    One statement: the upsert resets the window when `first_at` has aged past
    it, and increments otherwise. Doing it in SQL keeps the read-modify-write
    atomic under concurrent logins.
    """
    row = await conn.fetchrow(
        """INSERT INTO auth_throttle (bucket_key, attempts, first_at, last_at)
           VALUES ($1, 1, NOW(), NOW())
           ON CONFLICT (bucket_key) DO UPDATE SET
               attempts = CASE
                   WHEN auth_throttle.first_at < NOW() - ($2 || ' seconds')::interval
                   THEN 1
                   ELSE auth_throttle.attempts + 1
               END,
               first_at = CASE
                   WHEN auth_throttle.first_at < NOW() - ($2 || ' seconds')::interval
                   THEN NOW()
                   ELSE auth_throttle.first_at
               END,
               last_at = NOW()
           RETURNING attempts, blocked_until,
                     EXTRACT(EPOCH FROM (blocked_until - NOW()))::int AS block_remaining""",
        key, str(window_seconds),
    )

    remaining_block = row["block_remaining"] or 0
    if row["blocked_until"] is not None and remaining_block > 0:
        return RateLimitResult(False, 0, retry_after=int(remaining_block), backend="postgres")

    if row["attempts"] > limit:
        if lockout_seconds:
            await conn.execute(
                """UPDATE auth_throttle
                   SET blocked_until = NOW() + ($2 || ' seconds')::interval
                   WHERE bucket_key = $1""",
                key, str(lockout_seconds),
            )
            return RateLimitResult(False, 0, retry_after=lockout_seconds, backend="postgres")
        return RateLimitResult(False, 0, retry_after=window_seconds, backend="postgres")

    return RateLimitResult(True, max(0, limit - row["attempts"]), backend="postgres")


async def reset(conn: Optional[asyncpg.Connection], *, scope: str,
                identifier: str) -> None:
    """
    Clear a bucket after a successful authentication.

    Without this a user who mistypes their password several times and then gets
    it right stays near the limit for the rest of the window — the limiter is
    meant to punish failure, not to keep punishing after success.
    """
    key = _bucket_key(scope, identifier)

    redis = await get_redis_optional()
    if redis is not None:
        try:
            await redis.delete(f"{_KEY_PREFIX}{key}", f"{_KEY_PREFIX}lock:{key}")
        except Exception:                        # noqa: BLE001
            pass

    if conn is not None:
        try:
            await conn.execute("DELETE FROM auth_throttle WHERE bucket_key = $1", key)
        except Exception:                        # noqa: BLE001
            pass


async def login_limit(conn: Optional[asyncpg.Connection], *, ip: Optional[str],
                      email: Optional[str]) -> RateLimitResult:
    """Throttle a login attempt on IP + email. See the module docstring."""
    return await check(
        conn,
        scope="login",
        identifier=f"{ip or '-'}:{(email or '').strip().lower()}",
        limit=settings.LOGIN_RATE_LIMIT,
        window_seconds=settings.LOGIN_RATE_WINDOW_SECONDS,
        lockout_seconds=settings.LOGIN_LOCKOUT_SECONDS,
    )


async def refresh_limit(conn: Optional[asyncpg.Connection],
                        *, ip: Optional[str]) -> RateLimitResult:
    """
    Throttle refresh attempts per IP.

    A more generous limit than login: a legitimate browser refreshes roughly
    every 15 minutes, but several tabs and a page reload can bunch attempts
    together, and throttling those would log the user out for no reason.
    """
    return await check(
        conn,
        scope="refresh",
        identifier=ip or "-",
        limit=settings.REFRESH_RATE_LIMIT,
        window_seconds=settings.REFRESH_RATE_WINDOW_SECONDS,
    )
