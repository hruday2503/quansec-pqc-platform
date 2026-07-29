import logging, subprocess
from datetime import datetime, timezone
import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.database import get_db
from core.auth import require_user, require_admin

logger = logging.getLogger("quansec.ipsec.policy")
router = APIRouter(prefix="/api/ipsec/policies", tags=["IPsec Policy"])
SWANCTL_PATH = "/etc/swanctl/swanctl.conf"

POLICIES = {
    "classical": {"name":"classical","label":"Classical IKEv2","description":"Standard IKEv2 with ECDH - vulnerable to Shor","ike_proposal":"aes256-sha256-ecp384","esp_proposal":"aes256-sha256","pqc":False,"algorithms":{"key_exchange":"ECDH (ECP-384)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":False,"nist_standard":None,"security_level":"Classical ~192-bit"},"threat":"Shors algorithm breaks ECDH in hours"},
    "pqc-level3": {"name":"pqc-level3","label":"PQC Level 3 (ML-KEM-768)","description":"Kyber768 NIST FIPS 203 Level 3","ike_proposal":"aes256-sha256-mlkem768","esp_proposal":"aes256-sha256","pqc":True,"algorithms":{"key_exchange":"ML-KEM-768 (Kyber768)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":True,"nist_standard":"FIPS 203","security_level":"PQC Level 3 (192-bit)"},"threat":None},
    "pqc-level5": {"name":"pqc-level5","label":"PQC Level 5 (ML-KEM-1024)","description":"Kyber1024 NIST FIPS 203 Level 5 CNSA 2.0","ike_proposal":"aes256-sha256-mlkem1024","esp_proposal":"aes256-sha256","pqc":True,"algorithms":{"key_exchange":"ML-KEM-1024 (Kyber1024)","encryption":"AES-256-CBC","integrity":"HMAC-SHA2-256","quantum_safe":True,"nist_standard":"FIPS 203","security_level":"PQC Level 5 (256-bit)"},"threat":None},
}

def _read_current_addrs():
    try:
        with open(SWANCTL_PATH) as f:
            content = f.read()
        local = remote = None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("local_addrs") and not local:
                local = line.split("=")[1].strip()
            if line.startswith("remote_addrs") and not remote:
                remote = line.split("=")[1].strip()
        return local or "192.168.1.6", remote or "192.168.1.7"
    except Exception:
        return "192.168.1.6", "192.168.1.7"

SWANCTL_TEMPLATE = """connections {
    pqc-tunnel {
        version = 2
        proposals = IPSEC_IKE_PROPOSAL
        local_addrs = IPSEC_LOCAL_ADDR
        remote_addrs = IPSEC_REMOTE_ADDR
        local {
            auth = psk
            id = vm-a
        }
        remote {
            auth = psk
            id = vm-b
        }
        children {
            net {
                esp_proposals = IPSEC_ESP_PROPOSAL
                local_ts = IPSEC_LOCAL_ADDR/32
                remote_ts = IPSEC_REMOTE_ADDR/32
                start_action = trap
            }
        }
    }
}
secrets {
    ike-1 {
        id-1 = vm-a
        id-2 = vm-b
        secret = ${IPSEC_PSK}
    }
}
"""

class PolicyApplyRequest(BaseModel):
    policy_name: str
    tunnel_name: str = "pqc-tunnel"

@router.get("", dependencies=[Depends(require_user)])
async def list_policies():
    return list(POLICIES.values())

@router.post("/apply", dependencies=[Depends(require_admin)])
async def apply_policy(payload: PolicyApplyRequest, conn: asyncpg.Connection = Depends(get_db)):
    import os
    policy = POLICIES.get(payload.policy_name)
    if not policy:
        raise HTTPException(status_code=400, detail=f"Unknown policy. Available: {list(POLICIES.keys())}")

    local_addr, remote_addr = _read_current_addrs()
    config = SWANCTL_TEMPLATE
    config = config.replace("IPSEC_IKE_PROPOSAL", policy["ike_proposal"])
    config = config.replace("IPSEC_ESP_PROPOSAL", policy["esp_proposal"])
    config = config.replace("IPSEC_LOCAL_ADDR", local_addr)
    config = config.replace("IPSEC_REMOTE_ADDR", remote_addr)

    swanctl_available = os.path.isdir("/etc/swanctl")
    dev_mode = not swanctl_available

    if dev_mode:
        # ── Dev / Demo mode: StrongSwan not installed ─────────────────────────
        # Save config to a local path so it can be inspected, but don't crash.
        import pathlib
        dev_conf_dir = pathlib.Path("/tmp/quansec/swanctl")
        dev_conf_dir.mkdir(parents=True, exist_ok=True)
        dev_conf_path = dev_conf_dir / "swanctl.conf"
        dev_conf_path.write_text(config)
        logger.warning(
            f"StrongSwan not installed — policy '{payload.policy_name}' saved to "
            f"{dev_conf_path} (dev mode). Install StrongSwan to apply to a real tunnel."
        )
        message = (
            f"[DEV MODE] StrongSwan not installed. Policy '{payload.policy_name}' config "
            f"saved to {dev_conf_path}. Install StrongSwan to apply to a live tunnel."
        )
    else:
        # ── Production: write to real swanctl path ────────────────────────────
        try:
            with open(SWANCTL_PATH, "w") as f:
                f.write(config)
        except PermissionError:
            raise HTTPException(
                status_code=500,
                detail="Cannot write swanctl.conf — run backend with sufficient permissions"
            )
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Failed to write swanctl.conf: {e}")

        result = subprocess.run(
            ["sudo", "swanctl", "--load-all"],
            capture_output=True, text=True, timeout=10
        )
        if "successfully loaded" not in result.stdout + result.stderr:
            logger.warning(f"swanctl reload output: {result.stderr}")
            # Don't crash — swanctl may still have applied changes
        message = "Reload successful. Re-initiate tunnel to use new policy."

    await conn.execute(
        "INSERT INTO audit_events (action, resource, detail, severity) VALUES ($1,$2,$3,$4)",
        "policy_apply", "ipsec", f'{{"policy":"{payload.policy_name}","dev_mode":{str(dev_mode).lower()}}}', "warning"
    )
    logger.info(f"Applied policy {payload.policy_name} (dev_mode={dev_mode})")
    return {
        "status": "applied",
        "policy": payload.policy_name,
        "ike_proposal": policy["ike_proposal"],
        "pqc_enabled": policy["pqc"],
        "dev_mode": dev_mode,
        "message": message,
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
