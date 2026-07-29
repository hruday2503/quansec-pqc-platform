"""
protocols/ssh/router.py — REST endpoints for the SSH PQC module.
Mirrors the IPsec router surface so the frontend reuses the same patterns.

  GET  /api/ssh/stats            coverage + counts
  GET  /api/ssh/connections      active/closed SSH sessions
  GET  /api/ssh/handshakes       recent KEX negotiations (from connections)
  GET  /api/ssh/policies/compare classical vs hybrid PQC comparison
  POST /api/ssh/attacks/{name}   run an SSH-specific attack simulation
"""

import logging
import subprocess
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from core.database import get_db
from core.auth import require_user

logger = logging.getLogger("quansec.ssh.router")
router = APIRouter(prefix="/api/ssh", tags=["SSH PQC"])


@router.get("/stats", dependencies=[Depends(require_user)])
async def ssh_stats(conn: asyncpg.Connection = Depends(get_db)):
    rows = await conn.fetch("SELECT pqc_enabled, state FROM ssh_connections")
    total = len(rows)
    active = sum(1 for r in rows if r["state"] == "ACTIVE")
    pqc = sum(1 for r in rows if r["pqc_enabled"] and r["state"] == "ACTIVE")
    coverage = round((pqc / active) * 100, 1) if active else 0.0
    byte_rows = await conn.fetch("SELECT bytes_sent, bytes_received FROM ssh_connections WHERE state='ACTIVE'")
    total_sent = sum(r["bytes_sent"] or 0 for r in byte_rows)
    total_recv = sum(r["bytes_received"] or 0 for r in byte_rows)
    return {
        "total_connections": total,
        "active": active,
        "closed": total - active,
        "pqc_enabled": pqc,
        "pqc_coverage": coverage,
        "total_bytes_sent": total_sent,
        "total_bytes_received": total_recv,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/connections", dependencies=[Depends(require_user)])
async def ssh_connections(conn: asyncpg.Connection = Depends(get_db)):
    rows = await conn.fetch(
        """SELECT id, session_key, local_host, remote_host, remote_user,
                  kex_algorithm, kem_label, pqc_enabled, state,
                  bytes_sent, bytes_received, established_at, last_seen
           FROM ssh_connections
           ORDER BY (state='ACTIVE') DESC, last_seen DESC"""
    )
    return [dict(r) for r in rows]


@router.get("/handshakes", dependencies=[Depends(require_user)])
async def ssh_handshakes(limit: int = 10, conn: asyncpg.Connection = Depends(get_db)):
    rows = await conn.fetch(
        """SELECT session_key, remote_host, kex_algorithm, kem_label,
                  pqc_enabled, established_at
           FROM ssh_connections ORDER BY established_at DESC LIMIT $1""",
        limit,
    )
    return [dict(r) for r in rows]


@router.get("/policies/compare", dependencies=[Depends(require_user)])
async def ssh_compare():
    return {
        "comparison": [
            {"field": "Key Exchange", "classical": "curve25519-sha256 (X25519)",
             "pqc": "mlkem768x25519-sha256 (X25519 + ML-KEM-768)",
             "why_changed": "X25519 alone is broken by Shor's algorithm; hybrid adds a quantum-safe KEM",
             "standard": "NIST FIPS 203 + OpenSSH 9.9"},
            {"field": "Construction", "classical": "Single ECDH", "pqc": "Hybrid (classical + PQC)",
             "why_changed": "If either half is broken the other still protects the session",
             "standard": "IETF hybrid KEX drafts"},
            {"field": "Quantum Safe", "classical": False, "pqc": True,
             "why_changed": "CNSA 2.0 requires PQC for SSH by 2030",
             "standard": "NSA CNSA 2.0"},
            {"field": "Security Level", "classical": "128-bit classical", "pqc": "NIST Level 3 (192-bit PQC)",
             "why_changed": "ML-KEM-768 is the OpenSSH/NIST default for interactive transport",
             "standard": "NIST PQC Level 3"},
            {"field": "Host Key / MAC", "classical": "unchanged", "pqc": "unchanged",
             "why_changed": "Symmetric crypto and signatures are quantum-resistant at current sizes",
             "standard": "FIPS 180-4"},
        ],
        "current_kex": _current_kex(),
        "cnsa_deadline": "2030 (SSH)",
        "days_remaining": (datetime(2030, 1, 1, tzinfo=timezone.utc) - datetime.now(timezone.utc)).days,
    }


def _current_kex() -> str:
    try:
        out = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if line.lower().startswith("kexalgorithms"):
                return line.split()[1].split(",")[0]
    except Exception:
        pass
    return "unknown"


# ---- Attack simulations -----------------------------------------------------

async def _active_session_kex(conn) -> str:
    """Return the KEX of the most recent ACTIVE SSH session, or '' if none."""
    row = await conn.fetchrow(
        "SELECT kex_algorithm FROM ssh_connections WHERE state='ACTIVE' ORDER BY last_seen DESC LIMIT 1"
    )
    return row["kex_algorithm"] if row else ""


@router.post("/attacks/{name}", dependencies=[Depends(require_user)])
async def ssh_attack(name: str, conn: asyncpg.Connection = Depends(get_db)):
    kex = await _active_session_kex(conn)
    if not kex or kex == "unknown":
        kex = _current_kex()
    pqc = "mlkem" in kex.lower() or "sntrup" in kex.lower()

    if name == "downgrade":
        result = {
            "attack": "SSH KEX Downgrade",
            "result": "BLOCKED" if pqc else "VULNERABLE",
            "current_kex": kex,
            "mitm_action": "Strip hybrid KEX, force curve25519-sha256",
            "reason": (
                "sshd offers only PQC-hybrid KEX; classical-only clients are refused"
                if pqc else
                "Server accepts classical curve25519 — MITM can strip the PQC share"
            ),
            "outcome": (
                "Connection rejected — no shared classical KEX"
                if pqc else
                "Session negotiated pure X25519 — breakable by a quantum computer"
            ),
        }
    elif name == "shors":
        result = {
            "attack": "Shor's Algorithm (against X25519 half)",
            "result": "RESISTANT" if pqc else "VULNERABLE",
            "kex": kex,
            "explanation": (
                "Even though X25519 is present, the ML-KEM-768 share is combined into the "
                "session key. Breaking X25519 with Shor's leaves the Kyber secret intact."
                if pqc else
                "Pure X25519 key exchange — Shor's algorithm recovers the shared secret."
            ),
            "quantum_break_time": (
                "ML-KEM-768 lattice: no known quantum attack"
                if pqc else
                "~8 hours on 2500+ logical qubits (X25519)"
            ),
        }
    elif name == "harvest":
        result = {
            "attack": "Harvest Now, Decrypt Later",
            "result": "PROTECTED" if pqc else "VULNERABLE",
            "kex": kex,
            "future_decrypt": "IMPOSSIBLE" if pqc else "POSSIBLE",
            "reason": (
                "Hybrid session key includes ML-KEM-768 entropy — captured SSH traffic "
                "cannot be decrypted even with a future quantum computer."
                if pqc else
                "Recorded SSH sessions can be decrypted once X25519 is broken by Shor's."
            ),
        }
    else:
        raise HTTPException(status_code=404, detail=f"Unknown SSH attack: {name}")

    severity = "warning" if result["result"] in ("VULNERABLE",) else "info"
    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        f"ssh_attack_{name}", "ssh",
        f'{{"result":"{result["result"]}"}}', severity,
    )
    return result
