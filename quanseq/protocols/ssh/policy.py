"""
protocols/ssh/policy.py — SSH KEX policy engine.

Mirrors the IPsec policy engine: lets an admin switch the PQC sshd
(port 2222) between classical and post-quantum hybrid key exchange,
then reloads sshd.

  GET  /api/ssh/policies          list available KEX policies
  POST /api/ssh/policies/apply    switch the sshd KexAlgorithms (admin)

The sshd_config for the PQC daemon lives at /opt/openssh-pqc/etc/sshd_config.
We rewrite its KexAlgorithms line and restart the daemon.

Requires passwordless sudo for the sshd binary + a killall, added via
/etc/sudoers.d/quanseq-ssh (see SSH_POLICY_SETUP.md).
"""

import asyncio
import logging

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import get_db
from core.auth import require_user, require_admin
from core.host_control import HostControlError, host_control_request

logger = logging.getLogger("quanseq.ssh.policy")
router = APIRouter(prefix="/api/ssh/policies", tags=["SSH Policy"])

PQC_SSHD_CONFIG = "/opt/openssh-pqc/etc/sshd_config"
PQC_SSHD_BIN = "/opt/openssh-pqc/sbin/sshd"

SSH_POLICIES = {
    "classical": {
        "name": "classical",
        "label": "Classical SSH",
        "description": "Standard curve25519 key exchange — vulnerable to Shor",
        "kex": "curve25519-sha256",
        "pqc": False,
        "algorithms": {
            "key_exchange": "curve25519-sha256 (X25519)",
            "construction": "Single ECDH",
            "quantum_safe": False,
            "nist_level": "Classical 128-bit",
        },
        "threat": "Shor's algorithm breaks X25519 in hours on a quantum computer",
    },
    "pqc-hybrid": {
        "name": "pqc-hybrid",
        "label": "PQC Hybrid (ML-KEM-768)",
        "description": "Hybrid X25519 + ML-KEM-768 — NIST FIPS 203, OpenSSH 10",
        "kex": "mlkem768x25519-sha256",
        "pqc": True,
        "algorithms": {
            "key_exchange": "mlkem768x25519-sha256 (X25519 + ML-KEM-768)",
            "construction": "Hybrid (classical + PQC)",
            "quantum_safe": True,
            "nist_level": "NIST Level 3 (192-bit PQC)",
        },
        "threat": None,
    },
}


class SshPolicyApply(BaseModel):
    policy_name: str


@router.get("", dependencies=[Depends(require_user)])
async def list_ssh_policies():
    return list(SSH_POLICIES.values())


@router.post("/apply", dependencies=[Depends(require_admin)])
async def apply_ssh_policy(payload: SshPolicyApply, conn: asyncpg.Connection = Depends(get_db)):
    policy = SSH_POLICIES.get(payload.policy_name)
    if not policy:
        raise HTTPException(status_code=400, detail=f"Unknown policy. Available: {list(SSH_POLICIES.keys())}")

    try:
        result = await asyncio.to_thread(
            host_control_request, "apply_ssh", {"policy_name": payload.policy_name}
        )
    except HostControlError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        "ssh_policy_apply", "ssh",
        f'{{"policy":"{payload.policy_name}","real_daemon":true}}', "warning",
    )
    await _record_policy(conn, payload.policy_name, policy["kex"])
    logger.info("Applied SSH policy %s to real PQC sshd", payload.policy_name)
    return {
        "status": "applied",
        "policy": payload.policy_name,
        "kex": policy["kex"],
        "pqc_enabled": policy["pqc"],
        "real_daemon": True,
        "message": "PQC sshd accepted the configuration and was reloaded.",
        "controller": result,
    }


# ── One-click rollback ───────────────────────────────────────────────────────
POLICY_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS ssh_policy_history (
    id SERIAL PRIMARY KEY,
    policy_name TEXT,
    kex TEXT,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);
"""

async def _record_policy(conn, name, kex):
    await conn.execute(POLICY_HISTORY_TABLE)
    await conn.execute(
        "INSERT INTO ssh_policy_history (policy_name, kex) VALUES ($1,$2)", name, kex
    )

@router.get("/history", dependencies=[Depends(require_user)])
async def ssh_policy_history(conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute(POLICY_HISTORY_TABLE)
    rows = await conn.fetch(
        "SELECT policy_name, kex, applied_at FROM ssh_policy_history ORDER BY applied_at DESC LIMIT 10"
    )
    return [dict(r) for r in rows]

@router.post("/rollback", dependencies=[Depends(require_admin)])
async def ssh_policy_rollback(conn: asyncpg.Connection = Depends(get_db)):
    """One-click rollback: revert to the previous SSH policy."""
    await conn.execute(POLICY_HISTORY_TABLE)
    rows = await conn.fetch(
        "SELECT policy_name FROM ssh_policy_history ORDER BY applied_at DESC LIMIT 2"
    )
    if len(rows) < 2:
        raise HTTPException(status_code=400, detail="No previous policy to roll back to")
    previous = rows[1]["policy_name"]
    result = await apply_ssh_policy(SshPolicyApply(policy_name=previous), conn)
    return {"status": "rolled_back", "reverted_to": previous, "detail": result}
