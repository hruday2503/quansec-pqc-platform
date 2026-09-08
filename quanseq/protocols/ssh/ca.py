"""
protocols/ssh/ca.py — QUANSEQ Certificate Authority service.

Issues short-lived SSH certificates for users, signed by the QUANSEQ CA.
This is the onboarding flow for Zero Trust access:

  1. User generates their own keypair locally (private key never leaves them)
  2. User submits their PUBLIC key here
  3. QUANSEQ signs it into a certificate scoped to an identity + principal(s)
     with a short validity window
  4. User downloads the certificate and pairs it with their private key

  POST /api/ssh/ca/issue      sign a submitted public key -> certificate
  GET  /api/ssh/ca/info       CA public key + fingerprint (what servers trust)
  GET  /api/ssh/ca/issued     list issued certificates (audit)

Security notes:
  - We NEVER receive or store private keys — only public keys.
  - Each cert gets a unique serial (for later revocation).
  - Validity is short by policy (default 8h).
"""

import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.database import get_db
from core.auth import require_user, require_admin

logger = logging.getLogger("quanseq.ssh.ca")
router = APIRouter(prefix="/api/ssh/ca", tags=["SSH Certificate Authority"])

CA_KEY = os.environ.get("QUANSEQ_CA_KEY", os.path.expanduser("~/quanseq-ca/quanseq_ca"))
CA_PUB = os.environ.get("QUANSEQ_CA_PUB", CA_KEY + ".pub")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS issued_certs (
    id           SERIAL PRIMARY KEY,
    serial       BIGINT,
    identity     TEXT,
    principals   TEXT,
    valid_hours  INT,
    issued_by    TEXT,
    issued_at    TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    revoked      BOOLEAN DEFAULT FALSE
);
"""

# Reject anything that isn't a well-formed single SSH public key line.
PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S+)?\s*$")


class IssueRequest(BaseModel):
    public_key: str = Field(..., description="The user's SSH public key (one line)")
    identity: str = Field(..., description="Certificate identity, e.g. alice@bank.com")
    principals: str = Field("hd6441", description="Comma-separated login principals")
    valid_hours: int = Field(8, ge=1, le=168, description="Validity window in hours")


async def _next_serial(conn) -> int:
    await conn.execute(CREATE_TABLE)
    row = await conn.fetchval("SELECT COALESCE(MAX(serial), 0) + 1 FROM issued_certs")
    return int(row)


@router.get("/info", dependencies=[Depends(require_user)])
async def ca_info():
    """Return the CA public key + fingerprint — what servers configure as trusted."""
    try:
        with open(CA_PUB) as f:
            pub = f.read().strip()
        fp = subprocess.run(["ssh-keygen", "-lf", CA_PUB], capture_output=True, text=True, timeout=5).stdout.strip()
        return {"ca_public_key": pub, "fingerprint": fp, "trusted_by": "all QUANSEQ PQC SSH servers"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CA not available: {e}")


@router.post("/issue", dependencies=[Depends(require_admin)])
async def issue_certificate(req: IssueRequest, conn: asyncpg.Connection = Depends(get_db)):
    # Validate the public key format (defensive — never trust raw input)
    pk = req.public_key.strip()
    if not PUBKEY_RE.match(pk):
        raise HTTPException(status_code=400, detail="Not a valid SSH public key line")
    if "PRIVATE KEY" in pk.upper():
        raise HTTPException(status_code=400, detail="That looks like a PRIVATE key — never submit private keys. Submit the .pub only.")

    serial = await _next_serial(conn)

    # Write the pubkey to a temp file, sign it, read back the cert
    with tempfile.TemporaryDirectory() as td:
        pub_path = os.path.join(td, "user_key.pub")
        with open(pub_path, "w") as f:
            f.write(pk + "\n")

        cmd = [
            "ssh-keygen", "-s", CA_KEY,
            "-I", req.identity,
            "-n", req.principals,
            "-V", f"-1h:+{req.valid_hours}h",
            "-z", str(serial),
            pub_path,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Signing failed: {proc.stderr}")

        cert_path = os.path.join(td, "user_key-cert.pub")
        try:
            with open(cert_path) as f:
                cert = f.read().strip()
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Certificate not produced")

    expires = datetime.now(timezone.utc)
    await conn.execute(
        """INSERT INTO issued_certs (serial, identity, principals, valid_hours, issued_by, expires_at)
           VALUES ($1,$2,$3,$4,$5, NOW() + make_interval(hours => $4))""",
        serial, req.identity, req.principals, req.valid_hours, "admin",
    )
    try:
        await conn.execute(
            "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
            "cert_issued", "ssh-ca", f'{{"identity":"{req.identity}","serial":{serial}}}', "info",
        )
    except Exception as e:
        logger.warning(f"audit log insert skipped: {e}")
    logger.info(f"Issued cert serial={serial} identity={req.identity}")

    return {
        "status": "issued",
        "serial": serial,
        "identity": req.identity,
        "principals": req.principals,
        "valid_hours": req.valid_hours,
        "certificate": cert,
        "filename": f"{req.identity.replace('@','_')}-cert.pub",
        "usage": "Save this as <yourkey>-cert.pub alongside your private key, then: ssh -i <yourkey> -o CertificateFile=<yourkey>-cert.pub -p 2222 user@host",
    }


@router.get("/issued", dependencies=[Depends(require_user)])
async def list_issued(conn: asyncpg.Connection = Depends(get_db)):
    await conn.execute(CREATE_TABLE)
    rows = await conn.fetch(
        """SELECT serial, identity, principals, valid_hours, issued_at, expires_at, revoked,
                  (expires_at < NOW()) AS expired
           FROM issued_certs ORDER BY issued_at DESC LIMIT 50"""
    )
    return [dict(r) for r in rows]
