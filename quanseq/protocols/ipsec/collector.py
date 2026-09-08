"""
collector.py — background asyncio task that polls StrongSwan via VICI
and writes real tunnel state to PostgreSQL every IPSEC_POLL_INTERVAL seconds.

Architecture:
  asyncio loop
    └── collect_loop()          runs forever
          └── collect_once()   single poll cycle
                ├── ViciClient.list_sas()   → raw SA data from kernel
                ├── normalise_sa()          → clean Python dicts
                └── upsert_tunnels()        → write to PostgreSQL

The collector also publishes a summary to Redis so the WebSocket
endpoint can push live updates to the dashboard.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

from core.config import settings
from core.database import get_pool
from protocols.ipsec.vici_client import ViciClient, normalise_sa

logger = logging.getLogger("quanseq.ipsec.collector")


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #

UPSERT_TUNNEL = """
INSERT INTO ipsec_tunnels (
    name, local_host, local_id, remote_host, remote_id,
    state, ike_version, ike_proposal, esp_proposal,
    pqc_kem, pqc_enabled, bytes_in, bytes_out,
    packets_in, packets_out, established_at, last_seen
)
VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12, $13,
    $14, $15, $16, NOW()
)
ON CONFLICT (name) DO UPDATE SET
    state          = EXCLUDED.state,
    ike_proposal   = EXCLUDED.ike_proposal,
    esp_proposal   = EXCLUDED.esp_proposal,
    pqc_kem        = EXCLUDED.pqc_kem,
    pqc_enabled    = EXCLUDED.pqc_enabled,
    bytes_in       = EXCLUDED.bytes_in,
    bytes_out      = EXCLUDED.bytes_out,
    packets_in     = EXCLUDED.packets_in,
    packets_out    = EXCLUDED.packets_out,
    established_at = COALESCE(EXCLUDED.established_at, ipsec_tunnels.established_at),
    last_seen      = NOW()
"""

# We need a unique constraint on name — add it in migration if absent
ENSURE_UNIQUE = """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ipsec_tunnels_name_key'
    ) THEN
        ALTER TABLE ipsec_tunnels ADD CONSTRAINT ipsec_tunnels_name_key UNIQUE (name);
    END IF;
END $$;
"""

INSERT_EVENT = """
INSERT INTO ipsec_events (tunnel_name, event_type, detail)
VALUES ($1, $2, $3)
"""


async def upsert_tunnels(conn: asyncpg.Connection, tunnels: list[dict]):
    """Write list of normalised tunnel dicts to the database."""
    await conn.execute(ENSURE_UNIQUE)
    async with conn.transaction():
        for t in tunnels:
            await conn.execute(
                UPSERT_TUNNEL,
                t["name"],
                t["local_host"],
                t.get("local_id"),
                t["remote_host"],
                t.get("remote_id"),
                t["state"],
                t["ike_version"],
                t.get("ike_proposal"),
                t.get("esp_proposal"),
                t.get("pqc_kem"),
                t["pqc_enabled"],
                t["bytes_in"],
                t["bytes_out"],
                t["packets_in"],
                t["packets_out"],
                t.get("established_at"),
            )


async def mark_stale_tunnels_down(conn: asyncpg.Connection, seen_names: set[str]):
    """
    Tunnels that were in the DB but not returned by VICI this cycle
    have gone DOWN — mark them accordingly and log an event.
    """
    rows = await conn.fetch(
        "SELECT name FROM ipsec_tunnels WHERE state != 'DOWN' AND last_seen < NOW() - INTERVAL '30 seconds'"
    )
    for row in rows:
        if row["name"] not in seen_names:
            await conn.execute(
                "UPDATE ipsec_tunnels SET state = 'DOWN' WHERE name = $1",
                row["name"],
            )
            await conn.execute(
                INSERT_EVENT,
                row["name"],
                "DOWN",
                json.dumps({"reason": "not seen in last poll cycle"}),
            )
            logger.info(f"Tunnel {row['name']} marked DOWN (not seen in poll)")


# --------------------------------------------------------------------------- #
# Redis publish
# --------------------------------------------------------------------------- #

async def publish_summary(redis: aioredis.Redis, tunnels: list[dict]):
    """Push a lightweight summary to Redis for WebSocket consumers."""
    total      = len(tunnels)
    up         = sum(1 for t in tunnels if t["state"] == "ESTABLISHED")
    pqc_count  = sum(1 for t in tunnels if t["pqc_enabled"])
    pqc_pct    = round(pqc_count / total * 100, 1) if total else 0.0

    summary = {
        "protocol":   "ipsec",
        "total":      total,
        "up":         up,
        "down":       total - up,
        "pqc_count":  pqc_count,
        "pqc_pct":    pqc_pct,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }
    await redis.publish("quanseq:live", json.dumps(summary))


# --------------------------------------------------------------------------- #
# Core poll cycle
# --------------------------------------------------------------------------- #

async def collect_once(pool: asyncpg.Pool, redis: aioredis.Redis | None):
    """One complete poll → normalise → write cycle."""
    client = ViciClient(settings.VICI_SOCKET)

    if not client.connect():
        logger.warning("StrongSwan VICI socket not available — skipping this cycle")
        return

    try:
        raw_sas  = client.list_sas()
        tunnels  = []
        for raw in raw_sas:
            tunnels.extend(normalise_sa(raw))

        if not tunnels:
            logger.debug("VICI returned no active SAs")

        async with pool.acquire() as conn:
            await upsert_tunnels(conn, tunnels)
            seen = {t["name"] for t in tunnels}
            await mark_stale_tunnels_down(conn, seen)

        if redis:
            await publish_summary(redis, tunnels)

        logger.info(f"IPsec poll: {len(tunnels)} tunnels, "
                    f"{sum(1 for t in tunnels if t['pqc_enabled'])} PQC-enabled")

    except Exception as e:
        logger.error(f"IPsec collect_once error: {e}", exc_info=True)
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# Background loop
# --------------------------------------------------------------------------- #

async def collect_loop():
    """
    Runs forever as a FastAPI lifespan background task.
    Call this from main.py startup.
    """
    logger.info(f"IPsec collector starting — polling every {settings.IPSEC_POLL_INTERVAL}s")
    pool = await get_pool()

    try:
        redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    except Exception:
        logger.warning("Redis unavailable — will skip live publish")
        redis = None

    while True:
        try:
            await collect_once(pool, redis)
        except Exception as e:
            logger.error(f"IPsec collector loop error: {e}", exc_info=True)

        await asyncio.sleep(settings.IPSEC_POLL_INTERVAL)
