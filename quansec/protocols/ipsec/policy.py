import asyncio
import logging
from datetime import datetime, timezone
import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.database import get_db
from core.auth import require_user, require_admin
from core.host_control import HostControlError, host_control_request

logger = logging.getLogger("quansec.ipsec.policy")
router = APIRouter(prefix="/api/ipsec/policies", tags=["IPsec Policy"])

POLICIES = {
    "classical": {"name":"classical","label":"Classical IKEv2","description":"Standard IKEv2 with ECDH - vulnerable to Shor","ike_proposal":"aes256-sha256-ecp384","esp_proposal":"aes256-sha256","pqc":False,"algorithms":{"key_exchange":"ECDH (ECP-384)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":False,"nist_standard":None,"security_level":"Classical ~192-bit"},"threat":"Shors algorithm breaks ECDH in hours"},
    "pqc-level3": {"name":"pqc-level3","label":"PQC Level 3 (ML-KEM-768)","description":"Kyber768 NIST FIPS 203 Level 3","ike_proposal":"aes256-sha256-mlkem768","esp_proposal":"aes256-sha256","pqc":True,"algorithms":{"key_exchange":"ML-KEM-768 (Kyber768)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":True,"nist_standard":"FIPS 203","security_level":"PQC Level 3 (192-bit)"},"threat":None},
    "pqc-level5": {"name":"pqc-level5","label":"PQC Level 5 (ML-KEM-1024)","description":"Kyber1024 NIST FIPS 203 Level 5 CNSA 2.0","ike_proposal":"aes256-sha256-mlkem1024","esp_proposal":"aes256-sha256","pqc":True,"algorithms":{"key_exchange":"ML-KEM-1024 (Kyber1024)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":True,"nist_standard":"FIPS 203","security_level":"PQC Level 5 (256-bit)"},"threat":None},
}

class PolicyApplyRequest(BaseModel):
    policy_name: str
    tunnel_name: str = "pqc-tunnel"

@router.get("", dependencies=[Depends(require_user)])
async def list_policies():
    return list(POLICIES.values())

@router.post("/apply", dependencies=[Depends(require_admin)])
async def apply_policy(payload: PolicyApplyRequest, conn: asyncpg.Connection = Depends(get_db)):
    policy = POLICIES.get(payload.policy_name)
    if not policy:
        raise HTTPException(status_code=400, detail=f"Unknown policy. Available: {list(POLICIES.keys())}")

    try:
        result = await asyncio.to_thread(
            host_control_request,
            "apply_ipsec",
            {"policy_name": payload.policy_name},
        )
    except HostControlError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        "policy_apply", "ipsec", f'{{"policy":"{payload.policy_name}","real_daemon":true}}', "warning"
    )
    logger.info("Applied policy %s to real StrongSwan", payload.policy_name)
    return {
        "status": "applied",
        "policy": payload.policy_name,
        "ike_proposal": policy["ike_proposal"],
        "pqc_enabled": policy["pqc"],
        "real_daemon": True,
        "message": "StrongSwan accepted the configuration and reloaded it.",
        "controller": result,
    }

@router.get("/compare", dependencies=[Depends(require_user)])
async def compare_policies():
    c = POLICIES["classical"]
    p = POLICIES["pqc-level5"]
    return {
        "comparison": [
            {"field":"Key Exchange","classical":c["algorithms"]["key_exchange"],"pqc":p["algorithms"]["key_exchange"],"why_changed":"Shors algorithm breaks ECDH on a quantum computer in hours","standard":"NIST FIPS 203 (ML-KEM)"},
            {"field":"Quantum Safe","classical":False,"pqc":True,"why_changed":"CNSA 2.0 requires PQC migration by 2030 TLS/SSH and 2033 IPsec","standard":"NSA CNSA 2.0"},
            {"field":"Security Level","classical":c["algorithms"]["security_level"],"pqc":p["algorithms"]["security_level"],"why_changed":"ML-KEM-1024 provides 256-bit post-quantum security","standard":"NIST PQC Level 5"},
            {"field":"Encryption","classical":c["algorithms"]["encryption"],"pqc":p["algorithms"]["encryption"],"why_changed":"AES-256 remains quantum-safe","standard":"FIPS 197"},
            {"field":"NIST Standard","classical":"None (pre-PQC)","pqc":p["algorithms"]["nist_standard"],"why_changed":"NIST finalized ML-KEM FIPS 203 on August 13 2024","standard":"FIPS 203"},
        ],
        "current_policy": "pqc-level5",
        "cnsa_deadline": "2033 (IPsec)",
        "days_remaining": (datetime(2033,1,1,tzinfo=timezone.utc) - datetime.now(timezone.utc)).days,
    }
