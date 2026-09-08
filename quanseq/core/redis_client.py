"""
core/redis_client.py — Async Redis client singleton for QUANSEQ.

Usage in routers:
    from core.redis_client import get_redis

    redis = await get_redis()
    await redis.set("my_key", "value", ex=300)
    val = await redis.get("my_key")

Keys in use:
    quanseq:ipsec:snapshot   — latest IPsec collector snapshot (TTL: 30s)
    quanseq:ssh:snapshot     — latest SSH collector snapshot  (TTL: 30s)
    quanseq:alerts:firing    — set of currently firing alert rule IDs
    quanseq:setup:verified   — setup verification marker
"""

import logging
from typing import Optional

import redis.asyncio as aioredis

from core.config import settings

logger = logging.getLogger("quanseq.redis")

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Return the global Redis connection, creating it if needed."""
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30,
            )
            # Verify connection
            await _redis_client.ping()
            logger.info(f"Redis connected: {settings.REDIS_URL}")
        except Exception as e:
            logger.warning(f"Redis unavailable ({e}) — caching disabled")
            _redis_client = None
            raise
    return _redis_client


async def close_redis():
    """Close the Redis connection on shutdown."""
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection closed")


async def get_redis_optional() -> Optional[aioredis.Redis]:
    """Return Redis client, or None if Redis is unavailable (graceful degradation)."""
    try:
        return await get_redis()
    except Exception:
        return None
