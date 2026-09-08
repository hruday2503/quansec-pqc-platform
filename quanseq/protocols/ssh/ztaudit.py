"""
protocols/ssh/ztaudit.py — Zero Trust audit collector + API.

Parses SSH certificate authentication events from the auth log and
exposes them as a Zero Trust audit trail:
  - who authenticated (certificate identity / Key ID)
  - which certificate serial
  - which CA signed it
  - source IP, timestamp, accepted/rejected
  - rejection reason (expired, revoked, wrong principal)

Endpoints:
  GET /api/ssh/zt/events     recent certificate auth events
  GET /api/ssh/zt/status     Zero Trust posture summary
  GET /api/ssh/zt/policy     current ZT enforcement (passwords off, CA, etc.)

The collector reads a log file. On the machine running the PQC sshd the
events are in /var/log/auth.log. When QUANSEQ runs on a different host,
point ZT_AUTH_LOG at a synced copy, or run the collector where the log is.
"""

import asyncio
import logging
import os
import re
import subprocess
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends

from core.database import get_db
from core.auth import require_user

logger = logging.getLogger("quanseq.ssh.ztaudit")
router = APIRouter(prefix="/api/ssh/zt", tags=["SSH Zero Trust"])

# Where to read cert-auth events from. Override via env.
ZT_AUTH_LOG = os.environ.get("QUANSEQ_ZT_LOG", "/var/log/auth.log")
# If set, pull the log from a remote host over the PQC ssh first.
ZT_REMOTE = os.environ.get("QUANSEQ_ZT_REMOTE", "")  # e.g. "hd6441@192.168.1.7"
ZT_REMOTE_KEY = os.environ.get("QUANSEQ_ZT_KEY", "")
ZT_REMOTE_CERT = os.environ.get("QUANSEQ_ZT_CERT", "")

POLL_INTERVAL = 8

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS zt_audit (
    id            SERIAL PRIMARY KEY,
    event_time    TIMESTAMPTZ,
    identity      TEXT,
    cert_serial   TEXT,
    ca_fingerprint TEXT,
    source_ip     TEXT,
    principal     TEXT,
    result        TEXT,          -- accepted | rejected
    reason        TEXT,          -- expired | revoked | ok | ...
    raw_hash      TEXT UNIQUE,   -- dedupe key
    recorded_at   TIMESTAMPTZ DEFAULT NOW()
);
"""

# Accepted cert:
#   Accepted publickey for hd6441 from 192.168.1.6 port X ssh2: ED25519-CERT ... ID hruday@quanseq (serial 1) CA ED25519 SHA256:...
# Failed cert:
#   Failed publickey for hd6441 from ... ID hruday@quanseq (serial 1) CA ED25519 SHA256:...
# Rejection reason (separate line):
#   error: Certificate invalid: expired
ACCEPT_RE = re.compile(
    r"(?P<result>Accepted|Failed) publickey for (?P<principal>\S+) from (?P<ip>\S+) port \d+ ssh2: \S+-CERT \S+ ID (?P<identity>\S+) \(serial (?P<serial>\d+)\) CA \S+ (?P<ca>SHA256:\S+)"
)
REASON_RE = re.compile(r"Certificate invalid: (?P<reason>.+)")


def _fetch_log_text() -> str:
    """Read the auth log, optionally from a remote host over PQC ssh."""
    if ZT_REMOTE and ZT_REMOTE_KEY:
        try:
            cmd = [
                "/opt/openssh-pqc/bin/ssh",
                "-i", ZT_REMOTE_KEY,
                "-o", f"CertificateFile={ZT_REMOTE_CERT}",
                "-o", "StrictHostKeyChecking=no",
                "-p", "2222",
                ZT_REMOTE,
                "sudo tail -n 400 /var/log/auth.log",
            ]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return out.stdout
        except Exception as e:
            logger.warning(f"ZT remote log fetch failed: {e}")
            return ""
    try:
        with open(ZT_AUTH_LOG) as f:
            return f.read()
    except Exception as e:
        logger.debug(f"ZT log read failed: {e}")
        return ""


import hashlib


async def collect_zt_once(pool: asyncpg.Pool):
    text = _fetch_log_text()
    if not text:
        return
    lines = text.splitlines()

    async with pool.acquire() as conn:
        await conn.execute(CREATE_TABLE)
        pending_reason = None
        for idx, line in enumerate(lines):
            # Skip audit noise: sudo command logs, cron, our own greps
            if 'COMMAND=' in line or 'sudo:' in line or 'CRON[' in line:
                continue
            rm = REASON_RE.search(line)
            if rm:
                pending_reason = rm.group("reason").strip()
                # Look ahead: is the next line a Failed/Accepted publickey with an ID?
                nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
                if not ACCEPT_RE.search(nxt):
                    # Standalone cert rejection (expired cert never reaches the Failed line).
                    ts = datetime.now(timezone.utc)
                    tsm = re.match(r"(\d{4}-\d{2}-\d{2}T[\d:.]+[+\d:]*)", line)
                    if tsm:
                        try: ts = datetime.fromisoformat(tsm.group(1))
                        except Exception: pass
                    # Find the source IP: this line has a PID like sshd-session[NNNN];
                    # the follow-up line with the same PID carries "<user> <IP> port".
                    src_ip = "unknown"
                    pidm = re.search(r"sshd-session\[(\d+)\]", line)
                    pid = pidm.group(1) if pidm else None
                    # scan the next few lines for the same PID + an IP
                    for look in range(idx, min(idx + 4, len(lines))):
                        ll = lines[look]
                        if pid and f"sshd-session[{pid}]" not in ll:
                            continue
                        ipm2 = re.search(r"(?:user \S+|from) (\d+\.\d+\.\d+\.\d+) port", ll)
                        if ipm2:
                            src_ip = ipm2.group(1)
                            break
                    if src_ip == "unknown":
                        ipm = re.search(r"from (\S+) port", line)
                        src_ip = ipm.group(1) if ipm else "unknown"
                    raw_hash = hashlib.sha256(f"{ts}certreject{pending_reason}{idx}".encode()).hexdigest()
                    await conn.execute(
                        """INSERT INTO zt_audit
                           (event_time, identity, cert_serial, ca_fingerprint, source_ip, principal, result, reason, raw_hash)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                           ON CONFLICT (raw_hash) DO NOTHING""",
                        ts, "invalid-certificate", "-", "-", src_ip, "-", "rejected", pending_reason, raw_hash,
                    )
                    pending_reason = None
                continue
            m = ACCEPT_RE.search(line)
            if not m:
                continue
            result = "accepted" if m.group("result") == "Accepted" else "rejected"
            reason = "ok" if result == "accepted" else (pending_reason or "denied")
            pending_reason = None

            # timestamp prefix (ISO or syslog)
            ts = None
            tsm = re.match(r"(\d{4}-\d{2}-\d{2}T[\d:.]+[+\d:]*)", line)
            if tsm:
                try:
                    ts = datetime.fromisoformat(tsm.group(1))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            raw_hash = hashlib.sha256(
                f"{ts}{m.group('identity')}{m.group('serial')}{m.group('ip')}{result}{reason}".encode()
            ).hexdigest()

            await conn.execute(
                """INSERT INTO zt_audit
                   (event_time, identity, cert_serial, ca_fingerprint, source_ip, principal, result, reason, raw_hash)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                   ON CONFLICT (raw_hash) DO NOTHING""",
                ts, m.group("identity"), m.group("serial"), m.group("ca"),
                m.group("ip"), m.group("principal"), result, reason, raw_hash,
            )


async def zt_collect_loop():
    from core.database import get_pool
    pool = await get_pool()
    logger.info("Zero Trust audit collector starting — polling every %ds", POLL_INTERVAL)
    while True:
        try:
            await collect_zt_once(pool)
        except Exception as e:
            logger.error(f"ZT collect error: {e}")
        await asyncio.sleep(POLL_INTERVAL)


@router.get("/events", dependencies=[Depends(require_user)])
async def zt_events(limit: int = 50, conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute(CREATE_TABLE)
    rows = await conn.fetch(
        """SELECT event_time, identity, cert_serial, ca_fingerprint, source_ip,
                  principal, result, reason
           FROM zt_audit ORDER BY event_time DESC LIMIT $1""",
        limit,
    )
    return [dict(r) for r in rows]


@router.get("/status", dependencies=[Depends(require_user)])
async def zt_status(conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute(CREATE_TABLE)
    rows = await conn.fetch("SELECT result, reason FROM zt_audit")
    total = len(rows)
    accepted = sum(1 for r in rows if r["result"] == "accepted")
    rejected = total - accepted
    expired = sum(1 for r in rows if r["reason"] == "expired")
    return {
        "total_auth_events": total,
        "accepted": accepted,
        "rejected": rejected,
        "rejected_expired": expired,
        "cert_only": True,
        "passwords_disabled": True,
    }


@router.get("/policy", dependencies=[Depends(require_user)])
async def zt_policy():
    """The Zero Trust enforcement posture."""
    return {
        "authentication": "certificate-only (CA-signed)",
        "passwords": "disabled",
        "network_trust": "none — identity required regardless of source network",
        "credential_lifetime": "short-lived (hours), auto-expiring",
        "least_privilege": "per-principal, per-command scoping",
        "revocation": "serial-based (KRL supported)",
        "transport": "hybrid post-quantum (mlkem768x25519-sha256)",
        "principles": [
            {"principle": "Never trust, always verify", "status": "enforced", "detail": "Every session requires a valid CA-signed certificate"},
            {"principle": "No implicit network trust", "status": "enforced", "detail": "Being on the LAN grants nothing; passwords disabled"},
            {"principle": "Least privilege", "status": "enforced", "detail": "Certificates scoped to specific principals"},
            {"principle": "Time-bound access", "status": "enforced", "detail": "Certificates expire automatically"},
            {"principle": "Full auditability", "status": "enforced", "detail": "Every cert auth logged with identity + serial"},
        ],
    }
