import logging
from datetime import datetime, timezone, timedelta
import socket as _socket
import vici

logger = logging.getLogger("quansec.ipsec.vici")
PQC_KEYWORDS = {"kyber", "mlkem", "ml_kem", "ml-kem", "ntru", "bike", "hqc", "frodo", "newhope"}

def _decode(val):
    if isinstance(val, bytes):
        return val.decode(errors="replace")
    if isinstance(val, dict):
        return {_decode(k): _decode(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_decode(i) for i in val]
    return val

def _is_pqc(proposal):
    if not proposal:
        return False
    normalized = proposal.lower().replace("_", "").replace("-", "")
    return any(k.replace("_", "").replace("-", "") in normalized for k in PQC_KEYWORDS)

def _extract_pqc_kem(proposal):
    if not proposal:
        return None
    parts = proposal.replace("_", " ").replace("-", " ").lower().split()
    joined = "".join(parts)
    if "mlkem1024" in joined:
        return "ML-KEM-1024"
    if "mlkem768" in joined:
        return "ML-KEM-768"
    if "mlkem512" in joined:
        return "ML-KEM-512"
    if "kyber1024" in joined:
        return "Kyber1024"
    if "kyber768" in joined:
        return "Kyber768"
    for part in parts:
        if any(k.replace("_", "").replace("-", "") in part for k in PQC_KEYWORDS):
            return part
    return None

class ViciClient:
    def __init__(self, socket_path="/var/run/charon.vici"):
        self.socket_path = socket_path
        self._session = None

    def connect(self):
        try:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.connect(self.socket_path)
            self._session = vici.Session(sock)
            return True
        except Exception as e:
            logger.warning(f"VICI connection failed: {e}")
            self._session = None
            return False

    def close(self):
        self._session = None

    def version(self):
        if not self._session:
            return {}
        try:
            return _decode(dict(self._session.version()))
        except Exception as e:
            logger.error(f"VICI version error: {e}")
            return {}

    def list_sas(self):
        if not self._session:
            return []
        try:
            return [_decode(dict(sa)) for sa in self._session.list_sas()]
        except Exception as e:
            logger.error(f"VICI list_sas error: {e}")
            return []

    def list_conns(self):
        if not self._session:
            return []
        try:
            return [_decode(dict(c)) for c in self._session.list_conns()]
        except Exception as e:
            logger.error(f"VICI list_conns error: {e}")
            return []

def normalise_sa(raw_sa):
    tunnels = []
    for ike_name, ike in raw_sa.items():
        if not isinstance(ike, dict):
            continue
        encr         = ike.get("encr-alg", "")
        keysize      = ike.get("encr-keysize", "")
        integ        = ike.get("integ-alg", "")
        prf          = ike.get("prf-alg", "")
        dh           = ike.get("dh-group", "")
        ike_proposal = f"{encr}-{keysize}-{integ}-{prf}-{dh}".strip("-")
        local_host   = ike.get("local-host", "")
        local_id     = ike.get("local-id")
        remote_host  = ike.get("remote-host", "")
        remote_id    = ike.get("remote-id")
        state        = ike.get("state", "UNKNOWN").upper()
        version      = int(ike.get("version", "2"))
        try:
            established_at = datetime.now(timezone.utc) - timedelta(seconds=int(ike.get("established", 0)))
        except Exception:
            established_at = None
        child_sas = ike.get("child-sas", {})
        if not child_sas:
            tunnels.append({
                "name": ike_name, "local_host": local_host, "local_id": local_id,
                "remote_host": remote_host, "remote_id": remote_id, "state": state,
                "ike_version": version, "ike_proposal": ike_proposal, "esp_proposal": None,
                "pqc_kem": _extract_pqc_kem(ike_proposal), "pqc_enabled": _is_pqc(ike_proposal),
                "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0,
                "established_at": established_at,
            })
        else:
            for child_name, child in child_sas.items():
                if not isinstance(child, dict):
                    continue
                esp = f"{child.get('encr-alg','')}-{child.get('encr-keysize','')}-{child.get('integ-alg','')}".strip("-")
                tunnels.append({
                    "name": f"{ike_name}/{child_name}", "local_host": local_host, "local_id": local_id,
                    "remote_host": remote_host, "remote_id": remote_id,
                    "state": child.get("state", state).upper(), "ike_version": version,
                    "ike_proposal": ike_proposal, "esp_proposal": esp,
                    "pqc_kem": _extract_pqc_kem(ike_proposal) or _extract_pqc_kem(esp),
                    "pqc_enabled": _is_pqc(ike_proposal) or _is_pqc(esp),
                    "bytes_in": int(child.get("bytes-in", 0)), "bytes_out": int(child.get("bytes-out", 0)),
                    "packets_in": int(child.get("packets-in", 0)), "packets_out": int(child.get("packets-out", 0)),
                    "established_at": established_at,
                })
    return tunnels
