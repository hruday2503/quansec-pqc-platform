"""
protocols/siem/router.py — SIEM export.

Exports QUANSEC security events (policy changes, attacks, Zero Trust
cert auths, tunnel/session lifecycle) in formats SIEMs ingest:
  - CEF (Common Event Format — ArcSight, Splunk, QRadar)
  - JSON (generic / Elastic)
  - syslog (RFC 5424)

  GET /api/siem/events?format=cef|json|syslog   export recent events
  GET /api/siem/cef                              shortcut, CEF stream
"""

import logging
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, Response

from core.database import get_db
from core.auth import require_user

logger = logging.getLogger("quansec.siem")
router = APIRouter(prefix="/api/siem", tags=["SIEM Export"])

CEF_HEADER = "CEF:0|QUANSEC|PQC-Platform|1.0"

# Map audit actions → CEF signature + severity
SEVERITY = {
    "ssh_attack": 6, "ipsec_attack": 6,
    "ssh_policy_apply": 5, "policy_apply": 5,
    "login": 3, "api_key_created": 4, "api_key_revoked": 6,
    "zt_reject": 8,
}


def _severity(action: str) -> int:
    for k, v in SEVERITY.items():
        if action.startswith(k):
            return v
    return 3


async def _gather_events(conn, limit=100):
    events = []
    # audit_events table
    try:
        rows = await conn.fetch(
            "SELECT action, resource, detail, severity, created_at FROM audit_events ORDER BY created_at DESC LIMIT $1",
            limit,
        )
        for r in rows:
            events.append({
                "time": r["created_at"], "action": r["action"], "resource": r["resource"],
                "detail": r["detail"], "severity": r["severity"], "source": "audit",
            })
    except Exception as e:
        logger.debug(f"audit gather: {e}")
    # Zero Trust events
    try:
        exists = await conn.fetchval("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='zt_audit')")
        if exists:
            rows = await conn.fetch(
                "SELECT event_time, identity, source_ip, result, reason FROM zt_audit ORDER BY event_time DESC LIMIT $1",
                limit,
            )
            for r in rows:
                events.append({
                    "time": r["event_time"],
                    "action": f"zt_{r['result']}",
                    "resource": "ssh-zero-trust",
                    "detail": f'identity={r["identity"]} src={r["source_ip"]} reason={r["reason"]}',
                    "severity": "warning" if r["result"] == "rejected" else "info",
                    "source": "zero-trust",
                })
    except Exception as e:
        logger.debug(f"zt gather: {e}")
    return events


def _to_cef(e) -> str:
    sig = e["action"]
    sev = _severity(e["action"])
    name = e["action"].replace("_", " ").title()
    ts = e["time"].isoformat() if e["time"] else ""
    ext = f"rt={ts} act={e['action']} outcome={e.get('resource','')} msg={e.get('detail','')}"
    return f"{CEF_HEADER}|{sig}|{name}|{sev}|{ext}"


def _to_syslog(e) -> str:
    # RFC 5424-ish
    ts = e["time"].isoformat() if e["time"] else datetime.now(timezone.utc).isoformat()
    pri = 14  # facility=1 (user), severity=6 (info)
    return f"<{pri}>1 {ts} quansec pqc-platform - - - {e['action']} {e.get('detail','')}"


@router.get("/events", dependencies=[Depends(require_user)])
async def siem_events(format: str = "json", conn: asyncpg.Connection = Depends(get_db)):
    events = await _gather_events(conn)

    if format == "cef":
        body = "\n".join(_to_cef(e) for e in events)
        return Response(content=body + "\n", media_type="text/plain")
    if format == "syslog":
        body = "\n".join(_to_syslog(e) for e in events)
        return Response(content=body + "\n", media_type="text/plain")
    # default json
    return {
        "export_format": "json",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "events": [
            {**e, "time": e["time"].isoformat() if e["time"] else None} for e in events
        ],
    }


@router.get("/cef", dependencies=[Depends(require_user)])
async def siem_cef(conn: asyncpg.Connection = Depends(get_db)):
    events = await _gather_events(conn)
    body = "\n".join(_to_cef(e) for e in events)
    return Response(content=body + "\n", media_type="text/plain")
