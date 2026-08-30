"""Client for the narrowly scoped host policy controller."""

import json
import os
import socket


class HostControlError(RuntimeError):
    pass


def host_control_request(action: str, parameters: dict) -> dict:
    socket_path = os.environ.get("QUANSEC_CONTROL_SOCKET", "/run/quansec/policy.sock")
    request = json.dumps({"action": action, "parameters": parameters}).encode() + b"\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(float(os.environ.get("QUANSEC_CONTROL_TIMEOUT", "20")))
            client.connect(socket_path)
            client.sendall(request)
            response = b""
            while not response.endswith(b"\n"):
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
    except (OSError, TimeoutError) as exc:
        raise HostControlError(f"real host policy controller unavailable at {socket_path}: {exc}") from exc
    try:
        payload = json.loads(response)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HostControlError("host policy controller returned an invalid response") from exc
    if not payload.get("ok"):
        raise HostControlError(payload.get("error", "host policy operation failed"))
    return payload.get("result", {})
