"""
router.py — FastAPI routes for real-time IPsec data.

All data here comes from PostgreSQL which the collector populates
from the live StrongSwan VICI socket.

Routes:
  GET  /api/ipsec/tunnels          list all tunnels
  GET  /api/ipsec/tunnels/{id}     single tunnel detail
  GET  /api/ipsec/stats            aggregate stats (coverage %, byte totals)
  GET  /api/ipsec/events           recent SA events
  POST /api/ipsec/tunnels          manually add a tunnel config (seed)
  POST /api/ipsec/refresh          trigger an immediate poll (admin only)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from core.database import get_db
from core.auth import require_user
from protocols.ipsec.models import TunnelOut, TunnelCreate, IPsecStats, IPsecEvent

logger = logging.getLogger("quansec.ipsec.router")
router = APIRouter(
    prefix="/api/ipsec",
    tags=["IPsec"],
    dependencies=[Depends(require_user)],
)


# ─── List tunnels ────────────────────────────────────────────────────────────

@router.get("/tunnels", response_model=list[TunnelOut])
async def list_tunnels(
    state:   Optional[str] = Query(None, description="Filter by state: ESTABLISHED, DOWN"),
    pqc:     Optional[bool] = Query(None, description="Filter by PQC status"),
    limit:   int = Query(50, ge=1, le=200),
    offset:  int = Query(0, ge=0),
    conn: asyncpg.Connection = Depends(get_db),
):
    where_clauses = []
    args = []
    i = 1

    if state:
        where_clauses.append(f"state = ${i}")
        args.append(state.upper())
        i += 1
    if pqc is not None:
        where_clauses.append(f"pqc_enabled = ${i}")
        args.append(pqc)
        i += 1

    where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    args += [limit, offset]

    rows = await conn.fetch(
        f"""
        SELECT * FROM ipsec_tunnels
        {where}
        ORDER BY last_seen DESC
        LIMIT ${i} OFFSET ${i+1}
        """,
        *args,
    )
    return [dict(r) for r in rows]


# ─── Single tunnel ────────────────────────────────────────────────────────────

@router.get("/tunnels/{tunnel_id}", response_model=TunnelOut)
async def get_tunnel(
    tunnel_id: int,
    conn: asyncpg.Connection = Depends(get_db),
):
    row = await conn.fetchrow("SELECT * FROM ipsec_tunnels WHERE id = $1", tunnel_id)
    if not row:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    return dict(row)


# ─── Stats ────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=IPsecStats)
async def get_stats(conn: asyncpg.Connection = Depends(get_db)):
    row = await conn.fetchrow("""
        SELECT
            COUNT(*)                                          AS total_tunnels,
            COUNT(*) FILTER (WHERE state IN ('ESTABLISHED','INSTALLED')) AS established,
            COUNT(*) FILTER (WHERE state = 'DOWN')           AS down,
            COUNT(*) FILTER (WHERE pqc_enabled = TRUE)       AS pqc_enabled,
            COALESCE(
                ROUND(
                    COUNT(*) FILTER (WHERE pqc_enabled = TRUE)::NUMERIC
                    / NULLIF(COUNT(*), 0) * 100, 1
                ), 0
            )                                                AS pqc_coverage,
            COALESCE(SUM(bytes_in),  0)                      AS total_bytes_in,
            COALESCE(SUM(bytes_out), 0)                      AS total_bytes_out,
            MAX(last_seen)                                    AS last_updated
        FROM ipsec_tunnels
    """)

    return {
        "total_tunnels":   row["total_tunnels"],
        "established":     row["established"],
        "down":            row["down"],
        "pqc_enabled":     row["pqc_enabled"],
        "pqc_coverage":    float(row["pqc_coverage"]),
        "total_bytes_in":  row["total_bytes_in"],
        "total_bytes_out": row["total_bytes_out"],
        "last_updated":    row["last_updated"] or datetime.now(timezone.utc),
    }


# ─── Events ───────────────────────────────────────────────────────────────────

@router.get("/events", response_model=list[IPsecEvent])
async def list_events(
    tunnel_name: Optional[str] = Query(None),
    event_type:  Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    conn: asyncpg.Connection = Depends(get_db),
):
    where_clauses = []
    args = []
    i = 1

    if tunnel_name:
        where_clauses.append(f"tunnel_name = ${i}")
        args.append(tunnel_name); i += 1
    if event_type:
        where_clauses.append(f"event_type = ${i}")
        args.append(event_type.upper()); i += 1

    where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    args.append(limit)

    rows = await conn.fetch(
        f"SELECT * FROM ipsec_events {where} ORDER BY occurred_at DESC LIMIT ${i}",
        *args,
    )
    result = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("detail"), str):
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
        result.append(d)
    return result


# ─── Manual seed ─────────────────────────────────────────────────────────────

@router.post("/tunnels", response_model=TunnelOut, status_code=201)
async def create_tunnel(
    payload: TunnelCreate,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Manually register a tunnel config before StrongSwan establishes it.
    The collector will update state once the real SA appears.
    """
    row = await conn.fetchrow(
        """
        INSERT INTO ipsec_tunnels
            (name, local_host, remote_host, ike_version, pqc_kem, pqc_enabled, state)
        VALUES ($1, $2, $3, $4, $5, $6, 'CONNECTING')
        RETURNING *
        """,
        payload.name,
        payload.local_host,
        payload.remote_host,
        payload.ike_version,
        payload.pqc_kem,
        payload.pqc_kem is not None,
    )
    return dict(row)


# ─── Manual refresh ───────────────────────────────────────────────────────────

@router.post("/refresh")
async def trigger_refresh(conn: asyncpg.Connection = Depends(get_db)):
    """
    Trigger an immediate VICI poll outside the normal schedule.
    Returns the count of tunnels found.
    """
    from core.database import get_pool
    from protocols.ipsec.collector import collect_once
    import redis.asyncio as aioredis
    from core.config import settings

    pool = await get_pool()
    try:
        redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    except Exception:
        redis = None

    await collect_once(pool, redis)

    count = await conn.fetchval("SELECT COUNT(*) FROM ipsec_tunnels")
    return {"status": "ok", "tunnels_in_db": count}


@router.get("/handshakes")
async def handshake_stages(
    tunnel_name: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    conn: asyncpg.Connection = Depends(get_db),
):
    where = ""
    args = []
    if tunnel_name:
        where = "WHERE tunnel_name = $1"
        args.append(tunnel_name)
        args.append(limit)
        limit_idx = "$2"
    else:
        args.append(limit)
        limit_idx = "$1"
    rows = await conn.fetch(
        f"""
        SELECT tunnel_name, event_type, detail, occurred_at
        FROM ipsec_events
        {where}
        ORDER BY occurred_at DESC
        LIMIT {limit_idx}
        """,
        *args,
    )
    stage_order = {
        "IKE_SA_INIT": 1, "IKE_AUTH": 2, "ESTABLISHED": 3,
        "CHILD_UP": 4, "IKE_REKEY": 5, "CHILD_REKEY": 5,
        "CHILD_DOWN": 6, "DOWN": 7,
    }
    result = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("detail"), str):
            try:
                d["detail"] = json.loads(d["detail"])
            except Exception:
                pass
        d["stage_order"] = stage_order.get(d["event_type"], 99)
        result.append(d)
    return result
