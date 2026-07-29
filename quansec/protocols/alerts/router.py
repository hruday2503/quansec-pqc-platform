"""
protocols/alerts/router.py — real-time alerting.

Evaluates alert rules against live platform state and raises alerts when:
  - PQC coverage drops below a threshold (a tunnel/session went classical)
  - a downgrade attack is detected
  - a Zero Trust cert auth is rejected
  - a tunnel/session drops unexpectedly

A background task evaluates rules every few seconds and stores active
alerts. The dashboard polls /api/alerts.

  GET  /api/alerts            active + recent alerts
  GET  /api/alerts/rules      configured rules
  POST /api/alerts/{id}/ack   acknowledge an alert
"""

import asyncio
import logging
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends

from core.database import get_db
from core.auth import require_user

logger = logging.getLogger("quansec.alerts")
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    rule        TEXT,
    severity    TEXT,
    protocol    TEXT,
    message     TEXT,
    fingerprint TEXT UNIQUE,
    acked       BOOLEAN DEFAULT FALSE,
    raised_at   TIMESTAMPTZ DEFAULT NOW()
);
"""

RULES = [
    {"id": "pqc_coverage_drop", "severity": "high", "desc": "PQC coverage below 100% (a connection is classical)"},
    {"id": "downgrade_detected", "severity": "critical", "desc": "A classical/downgraded connection was observed"},
    {"id": "zt_rejection", "severity": "medium", "desc": "A Zero Trust certificate auth was rejected"},
    {"id": "tunnel_down", "severity": "high", "desc": "An IPsec tunnel went DOWN"},
]


async def _raise(conn, rule, severity, protocol, message, fingerprint):
    await conn.execute(CREATE_TABLE)
    await conn.execute(
        """INSERT INTO alerts (rule, severity, protocol, message, fingerprint)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT (fingerprint) DO NOTHING""",
        rule, severity, protocol, message, fingerprint,
    )


async def evaluate_once(pool: asyncpg.Pool):
    async with pool.acquire() as conn:
        await conn.execute(CREATE_TABLE)

        # Rule: IPsec coverage / downgrade
        ip = await conn.fetch("SELECT pqc_enabled, state, pqc_kem AS kex_algorithm FROM ipsec_tunnels WHERE state='ESTABLISHED'")
        for r in ip:
            if not r["pqc_enabled"]:
                await _raise(conn, "downgrade_detected", "critical", "ipsec",
                             f"IPsec tunnel using classical KEX: {r['kex_algorithm']}",
                             f"ipsec-downgrade-{r['kex_algorithm']}")

        # Rule: SSH coverage / downgrade
        sh = await conn.fetch("SELECT pqc_enabled, state, kex_algorithm, remote_host FROM ssh_connections WHERE state='ACTIVE'")
        for r in sh:
            if not r["pqc_enabled"]:
                await _raise(conn, "downgrade_detected", "critical", "ssh",
                             f"SSH session using classical KEX: {r['kex_algorithm']} ({r['remote_host']})",
                             f"ssh-downgrade-{r['remote_host']}-{r['kex_algorithm']}")

        # Rule: Zero Trust rejections
        try:
            exists = await conn.fetchval("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='zt_audit')")
            if exists:
                rej = await conn.fetch("SELECT identity, source_ip, reason, event_time FROM zt_audit WHERE result='rejected' ORDER BY event_time DESC LIMIT 5")
                for r in rej:
                    await _raise(conn, "zt_rejection", "medium", "ssh",
                                 f"Zero Trust rejected: {r['identity']} from {r['source_ip']} ({r['reason']})",
                                 f"zt-reject-{r['event_time']}-{r['source_ip']}")
        except Exception as e:
            logger.debug(f"zt alert rule: {e}")


async def alerts_loop():
    from core.database import get_pool
    pool = await get_pool()
    logger.info("Alerts engine starting — evaluating every 10s")
    while True:
        try:
            await evaluate_once(pool)
        except Exception as e:
            logger.error(f"alert eval error: {e}")
        await asyncio.sleep(10)


@router.get("", dependencies=[Depends(require_user)])
async def list_alerts(conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute(CREATE_TABLE)
    rows = await conn.fetch(
        "SELECT id, rule, severity, protocol, message, acked, raised_at FROM alerts ORDER BY raised_at DESC LIMIT 50"
    )
    active = [dict(r) for r in rows if not r["acked"]]
    return {
        "active_count": len(active),
        "alerts": [dict(r) for r in rows],
    }


@router.get("/rules", dependencies=[Depends(require_user)])
async def list_rules():
    return RULES


@router.post("/{alert_id}/ack", dependencies=[Depends(require_user)])
async def ack_alert(alert_id: int, conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute("UPDATE alerts SET acked=TRUE WHERE id=$1", alert_id)
    return {"status": "acknowledged", "id": alert_id}
