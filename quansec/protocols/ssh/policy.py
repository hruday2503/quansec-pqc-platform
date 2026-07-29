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
/etc/sudoers.d/quansec-ssh (see SSH_POLICY_SETUP.md).
"""

import logging
import subprocess

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import get_db
from core.auth import require_user, require_admin

logger = logging.getLogger("quansec.ssh.policy")
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

    # Read the current config, replace the KexAlgorithms line
    try:
        with open(PQC_SSHD_CONFIG) as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="PQC sshd_config not found on this host")

    new_lines = []
    replaced = False
    for line in lines:
        if line.strip().startswith("KexAlgorithms"):
            new_lines.append(f"KexAlgorithms {policy['kex']}\n")
            replaced = True
        else:
            new_lines.append(line)
    if not replaced:
        new_lines.append(f"KexAlgorithms {policy['kex']}\n")

    # Write back (needs sudo tee via subprocess since file is root-owned)
    config_text = "".join(new_lines)
    try:
        proc = subprocess.run(
            ["sudo", "tee", PQC_SSHD_CONFIG],
            input=config_text, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Cannot write sshd_config: {proc.stderr}")
    except subprocess.SubprocessError as e:
        raise HTTPException(status_code=500, detail=f"Config write failed: {e}")

    # Validate then restart the PQC sshd
    check = subprocess.run(["sudo", PQC_SSHD_BIN, "-t", "-f", PQC_SSHD_CONFIG],
                           capture_output=True, text=True, timeout=10)
    if check.returncode != 0:
        raise HTTPException(status_code=500, detail=f"sshd config invalid: {check.stderr}")

    # Kill and restart the PQC daemon
    subprocess.run(["sudo", "pkill", "-f", f"{PQC_SSHD_BIN}.*2222"], capture_output=True, timeout=10)
    restart = subprocess.run(["sudo", PQC_SSHD_BIN, "-f", PQC_SSHD_CONFIG],
                             capture_output=True, text=True, timeout=10)
    if restart.returncode != 0:
        raise HTTPException(status_code=500, detail=f"sshd restart failed: {restart.stderr}")

    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        "ssh_policy_apply", "ssh", f'{{"policy":"{payload.policy_name}"}}', "warning",
    )
    await _record_policy(conn, payload.policy_name, policy["kex"])
    logger.info(f"Applied SSH policy {payload.policy_name} (KEX={policy['kex']})")
    return {
        "status": "applied",
        "policy": payload.policy_name,
        "kex": policy["kex"],
        "pqc_enabled": policy["pqc"],
        "message": "sshd restarted. New SSH connections use the new KEX. Reconnect to apply.",
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
