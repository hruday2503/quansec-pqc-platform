"""Root host agent exposing only two allow-listed policy operations.

Run this on the Ubuntu host via the supplied systemd unit. Containers receive
access only to its Unix socket; they never receive sudo, the Docker socket, the
host PID namespace, or broad privileges.
"""

import json
import os
import pathlib
import re
import socketserver
import subprocess
import tempfile

SOCKET_PATH = os.environ.get("QUANSEC_CONTROL_SOCKET", "/run/quansec/policy.sock")
SWANCTL_CONFIG = pathlib.Path(os.environ.get("QUANSEC_SWANCTL_CONFIG", "/etc/quansec-strongswan/swanctl/swanctl.conf"))
SWANCTL_BIN = os.environ.get(
    "QUANSEC_SWANCTL_BIN", "/opt/quansec-pqc/sbin/swanctl"
)

PQC_SSHD_CONFIG = pathlib.Path(os.environ.get("QUANSEC_PQC_SSHD_CONFIG", "/opt/openssh-pqc/etc/sshd_config"))
PQC_SSHD_BIN = os.environ.get("QUANSEC_PQC_SSHD_BIN", "/opt/openssh-pqc/sbin/sshd")
PQC_SSHD_SERVICE = os.environ.get("QUANSEC_PQC_SSHD_SERVICE", "quansec-pqc-sshd.service")

IPSEC_POLICIES = {
    "classical": ("aes256-sha256-ecp384", "aes256-sha256"),
    "pqc-level3": ("aes256-sha256-mlkem768", "aes256-sha256"),
    "pqc-level5": ("aes256-sha256-mlkem1024", "aes256-sha256"),
}
SSH_POLICIES = {
    "classical": "curve25519-sha256",
    "pqc-hybrid": "mlkem768x25519-sha256",
}

def _run(command: list[str]) -> str:
    process = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if process.returncode:
        raise RuntimeError(f"{' '.join(command)} failed: {(process.stderr or process.stdout).strip()}")
    return (process.stdout or process.stderr).strip()


def _atomic_replace(path: pathlib.Path, content: str) -> bytes:
    previous = path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return previous


def _restore(path: pathlib.Path, previous: bytes) -> None:
    path.write_bytes(previous)
    os.chmod(path, 0o600)


def apply_ipsec(parameters: dict) -> dict:
    policy = parameters.get("policy_name")
    if policy not in IPSEC_POLICIES:
        raise ValueError("IPsec policy is not allow-listed")
    if not SWANCTL_CONFIG.is_file() or not os.path.isfile(SWANCTL_BIN):
        raise RuntimeError("real StrongSwan swanctl runtime/configuration is missing")
    ike, esp = IPSEC_POLICIES[policy]
    config = SWANCTL_CONFIG.read_text()
    config, ike_changes = re.subn(
        r"(?m)^(\s*)proposals\s*=.*$", rf"\1proposals = {ike}", config, count=1
    )
    config, esp_changes = re.subn(
        r"(?m)^(\s*)esp_proposals\s*=.*$", rf"\1esp_proposals = {esp}", config, count=1
    )
    if ike_changes != 1 or esp_changes != 1:
        raise RuntimeError("real swanctl config must contain one proposals and one esp_proposals line")
    previous = _atomic_replace(SWANCTL_CONFIG, config)
    try:
        output = _run([SWANCTL_BIN, "--load-all", "--noprompt"])
    except Exception:
        _restore(SWANCTL_CONFIG, previous)
        try:
            _run([SWANCTL_BIN, "--load-all", "--noprompt"])
        except Exception:
            pass
        raise
    return {"policy": policy, "daemon": "strongswan", "reload": output}


def apply_ssh(parameters: dict) -> dict:
    policy = parameters.get("policy_name")
    if policy not in SSH_POLICIES:
        raise ValueError("SSH policy is not allow-listed")
    if not PQC_SSHD_CONFIG.is_file() or not os.path.isfile(PQC_SSHD_BIN):
        raise RuntimeError("real PQC OpenSSH runtime/configuration is missing")
    lines = PQC_SSHD_CONFIG.read_text().splitlines(keepends=True)
    replacement = f"KexAlgorithms {SSH_POLICIES[policy]}\n"
    updated = [replacement if line.strip().startswith("KexAlgorithms") else line for line in lines]
    if not any(line.strip().startswith("KexAlgorithms") for line in lines):
        updated.append(replacement)
    previous = _atomic_replace(PQC_SSHD_CONFIG, "".join(updated))
    try:
        _run([PQC_SSHD_BIN, "-t", "-f", str(PQC_SSHD_CONFIG)])
        output = _run(["systemctl", "reload-or-restart", PQC_SSHD_SERVICE])
    except Exception:
        _restore(PQC_SSHD_CONFIG, previous)
        try:
            _run([PQC_SSHD_BIN, "-t", "-f", str(PQC_SSHD_CONFIG)])
            _run(["systemctl", "reload-or-restart", PQC_SSHD_SERVICE])
        except Exception:
            pass
        raise
    return {"policy": policy, "daemon": "openssh-pqc", "reload": output}


def status(_: dict) -> dict:
    return {
        "strongswan": SWANCTL_CONFIG.is_file() and os.path.isfile(SWANCTL_BIN),
        "openssh_pqc": PQC_SSHD_CONFIG.is_file() and os.path.isfile(PQC_SSHD_BIN),
    }


ACTIONS = {"status": status, "apply_ipsec": apply_ipsec, "apply_ssh": apply_ssh}


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            request = json.loads(self.rfile.readline(65537))
            if not isinstance(request, dict) or request.get("action") not in ACTIONS:
                raise ValueError("action is not allow-listed")
            parameters = request.get("parameters") or {}
            if not isinstance(parameters, dict):
                raise ValueError("parameters must be an object")
            result = ACTIONS[request["action"]](parameters)
            response = {"ok": True, "result": result}
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        self.wfile.write(json.dumps(response).encode() + b"\n")


def main() -> None:
    pathlib.Path(SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    with socketserver.ThreadingUnixStreamServer(SOCKET_PATH, Handler) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
