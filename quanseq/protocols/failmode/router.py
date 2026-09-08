"""
protocols/failmode/router.py — fail-open / fail-closed mode controls.

A crypto-agility safety control named in the proposal. Defines what the
platform does if PQC negotiation fails:

  fail-closed (secure default): if PQC can't be negotiated, REFUSE the
     connection. No downgrade to classical. Maximum security.
  fail-open (availability): if PQC can't be negotiated, ALLOW a classical
     fallback so connectivity is preserved. Lower security, higher uptime.

This maps directly to protocol config:
  - SSH fail-closed  = KexAlgorithms lists ONLY the PQC hybrid (current)
  - SSH fail-open    = KexAlgorithms lists PQC first, classical as fallback
  - IPsec fail-closed = single PQC proposal
  - IPsec fail-open   = PQC proposal + classical proposal

  GET  /api/failmode              current mode per protocol
  POST /api/failmode/set          set mode (admin)
"""

import logging

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import get_db
from core.auth import require_user, require_admin

logger = logging.getLogger("quanseq.failmode")
router = APIRouter(prefix="/api/failmode", tags=["Fail Mode"])


class FailModeSet(BaseModel):
    protocol: str   # ipsec | ssh
    mode: str       # fail-closed | fail-open


MODES = {
    "ssh": {
        "fail-closed": {"kex": "mlkem768x25519-sha256", "desc": "PQC only — classical refused"},
        "fail-open": {"kex": "mlkem768x25519-sha256,curve25519-sha256", "desc": "PQC preferred, classical fallback"},
    },
    "ipsec": {
        "fail-closed": {"proposal": "aes256-sha256-mlkem1024", "desc": "PQC only — classical refused"},
        "fail-open": {"proposal": "aes256-sha256-mlkem1024,aes256-sha256-x25519", "desc": "PQC preferred, classical fallback"},
    },
    # TLS is ADVISORY ONLY. Unlike sshd and StrongSwan, whose config files
    # QUANSEQ rewrites and reloads, the TLS 1.3 group list is not reachable from
    # Python — the ssl module exposes no group-selection API. Choosing
    # fail-closed here records an intent; it does not stop a classical-only
    # client from connecting. Making it real needs OpenSSL SSL_CONF, native
    # bindings, or a terminating proxy with a strict group policy.
    "tls": {
        "fail-closed": {"groups": "X25519MLKEM768",
                        "desc": "PQC only — classical refused"},
        "fail-open": {"groups": "X25519MLKEM768:X25519",
                      "desc": "PQC preferred, classical fallback"},
    },
}

# In-memory current mode (also reflected in config). Defaults to fail-closed.
_CURRENT = {"ssh": "fail-closed", "ipsec": "fail-closed", "tls": "fail-closed"}

# Protocols whose fail mode QUANSEQ can actually apply to a live daemon.
_ENFORCEABLE = {"ipsec", "ssh"}

_TLS_ADVISORY_NOTE = (
    "Advisory only. QUANSEQ cannot enforce TLS 1.3 group selection through "
    "Python's ssl module, so this records intent rather than changing what the "
    "TLS service accepts."
)


@router.get("", dependencies=[Depends(require_user)])
async def get_failmode():
    return {
        "ssh": {"mode": _CURRENT["ssh"], "enforceable": True,
                **MODES["ssh"][_CURRENT["ssh"]]},
        "ipsec": {"mode": _CURRENT["ipsec"], "enforceable": True,
                  **MODES["ipsec"][_CURRENT["ipsec"]]},
        "tls": {"mode": _CURRENT["tls"], "enforceable": False,
                **MODES["tls"][_CURRENT["tls"]], "note": _TLS_ADVISORY_NOTE},
        "recommendation": "fail-closed for maximum quantum safety; fail-open only where uptime outweighs downgrade risk",
    }


@router.post("/set", dependencies=[Depends(require_admin)])
async def set_failmode(payload: FailModeSet, conn: asyncpg.Connection = Depends(get_db)):
    if payload.protocol not in MODES:
        raise HTTPException(
            status_code=400,
            detail=f"protocol must be one of {', '.join(sorted(MODES))}",
        )
    if payload.mode not in MODES[payload.protocol]:
        raise HTTPException(status_code=400, detail="mode must be fail-closed or fail-open")

    _CURRENT[payload.protocol] = payload.mode
    cfg = MODES[payload.protocol][payload.mode]

    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        "failmode_set", payload.protocol,
        f'{{"mode":"{payload.mode}"}}', "warning" if payload.mode == "fail-open" else "info",
    )
    enforceable = payload.protocol in _ENFORCEABLE
    logger.info(
        f"Fail mode for {payload.protocol} set to {payload.mode}"
        f"{'' if enforceable else ' (advisory only — not enforceable)'}"
    )
    return {
        "status": "set",
        "protocol": payload.protocol,
        "mode": payload.mode,
        "config": cfg,
        "enforceable": enforceable,
        "note": (
            "Apply via the protocol policy engine to enforce on the live daemon."
            if enforceable else _TLS_ADVISORY_NOTE
        ),
    }
