# tls13/client.py
# Vendored from tls13_module/client.py — see VENDOR.md
#
# QUANSEQ PATCH 1/6: stdlib logging, application payloads redacted by default.

import logging
import socket
import ssl
import time
from typing import Any, Dict, Optional

from .config import TLSConfig
from .exceptions import CertVerificationError, TLSConnectionError, TLSHandshakeError
from .utils import build_client_context, get_session_info, redact_payload

logger = logging.getLogger("quanseq.tls.transport")

RECV_BYTES = 4096


class TLSClient:
    """
    TLS 1.3 client. Certificate verification and hostname checking are always on.

    Context manager (preferred):
        with TLSClient(config) as client:
            info     = client.session_info()
            response = client.send("Hello")

    Manual:
        client = TLSClient(config)
        client.connect()
        response = client.send("Hello")
        client.disconnect()
    """

    def __init__(self, config: Optional[TLSConfig] = None):
        self.config = config or TLSConfig()
        self._sock: Optional[ssl.SSLSocket] = None
        self._session: Optional[Dict[str, Any]] = None
        self._handshake_ms: Optional[float] = None

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "TLSClient":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()

    # ── Public API ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """
        Open a TCP connection and perform the TLS 1.3 handshake.

        Raises TLSConnectionError, CertVerificationError or TLSHandshakeError.
        """
        cfg = self.config
        ctx = build_client_context(cfg)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(cfg.timeout)

        started = time.perf_counter()
        try:
            raw_sock.connect((cfg.host, cfg.port))
        except ConnectionRefusedError as exc:
            raw_sock.close()
            raise TLSConnectionError(
                f"Connection refused at {cfg.host}:{cfg.port}"
            ) from exc
        except socket.timeout as exc:
            raw_sock.close()
            raise TLSConnectionError(
                f"Timed out connecting to {cfg.host}:{cfg.port} after {cfg.timeout}s"
            ) from exc
        except OSError as exc:
            raw_sock.close()
            raise TLSConnectionError(
                f"Network error reaching {cfg.host}:{cfg.port}: {exc}"
            ) from exc

        try:
            self._sock = ctx.wrap_socket(raw_sock, server_hostname=cfg.server_hostname)
        except ssl.SSLCertVerificationError as exc:
            raw_sock.close()
            raise CertVerificationError(
                f"Certificate verification failed for {cfg.server_hostname}: {exc.verify_message or exc}"
            ) from exc
        except ssl.SSLError as exc:
            raw_sock.close()
            raise TLSHandshakeError(f"TLS handshake failed: {exc}") from exc
        except socket.timeout as exc:
            raw_sock.close()
            raise TLSHandshakeError(
                f"TLS handshake timed out after {cfg.timeout}s"
            ) from exc

        self._handshake_ms = (time.perf_counter() - started) * 1000
        self._session = get_session_info(self._sock, cfg)

        logger.info(
            "TLS 1.3 handshake with %s:%s complete: %s %s (%s bits) in %.1f ms",
            cfg.host, cfg.port, self._session["tls_version"],
            self._session["cipher_name"], self._session["cipher_bits"],
            self._handshake_ms,
        )
        if self._session["peer_cert"]:
            cert = self._session["peer_cert"]
            logger.info(
                "Server certificate verified: CN=%s issuer=%s SAN=%s",
                cert["cn"], cert["issuer_cn"], ",".join(cert["san"]),
            )

    def send(self, message: str) -> str:
        """
        Send a message and return the server's response.

        Raises TLSHandshakeError or TLSConnectionError — see send_raw for why a
        send can still surface a handshake failure.
        """
        logger.info("Sending: %s", redact_payload(message, self.config))
        response_bytes = self.send_raw(message.encode("utf-8"))
        logger.info("Received %d byte response", len(response_bytes))
        return response_bytes.decode("utf-8", errors="replace")

    def send_raw(self, data: bytes) -> bytes:
        """
        Send raw bytes and receive raw bytes — for binary protocols.

        QUANSEQ PATCH 8: translate socket-level failures into module exceptions.

        Upstream let ssl.SSLError escape from here, which matters more than it
        looks: in TLS 1.3 the client finishes its side of the handshake before
        the server has validated the client certificate, so an mTLS rejection
        arrives as an alert on the FIRST READ, not from wrap_socket(). Callers
        that only caught TLSHandshakeError around connect() would see a raw
        ssl.SSLError here and mis-handle a plain authentication failure.
        """
        if not self._sock:
            raise RuntimeError("Not connected. Call connect() or use 'with TLSClient(...)'")

        try:
            self._sock.sendall(data)
            return self._sock.recv(RECV_BYTES)
        except ssl.SSLCertVerificationError as exc:
            raise CertVerificationError(f"Certificate rejected by peer: {exc}") from exc
        except ssl.SSLError as exc:
            raise TLSHandshakeError(
                f"TLS error during exchange with {self.config.host}:{self.config.port}: {exc}"
            ) from exc
        except socket.timeout as exc:
            raise TLSConnectionError(
                f"Timed out waiting for {self.config.host}:{self.config.port} "
                f"after {self.config.timeout}s"
            ) from exc
        except OSError as exc:
            raise TLSConnectionError(f"Connection error: {exc}") from exc

    def disconnect(self) -> None:
        """Close the TLS connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def session_info(self) -> Optional[Dict[str, Any]]:
        """
        TLS session metadata captured at handshake time, or None if not connected.

        `negotiated_group` is always None — see get_session_info in utils.py.
        """
        return self._session

    def handshake_ms(self) -> Optional[float]:
        """Wall-clock milliseconds for TCP connect plus TLS handshake."""
        return self._handshake_ms

    def is_connected(self) -> bool:
        return self._sock is not None
