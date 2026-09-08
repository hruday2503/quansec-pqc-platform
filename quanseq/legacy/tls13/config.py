# tls13/config.py
# Vendored from tls13_module/config.py — see VENDOR.md
from dataclasses import dataclass


@dataclass
class TLSConfig:
    """
    Central configuration for the TLS 1.3 server or client.

    Usage:
        config = TLSConfig()                        # localhost defaults
        config = TLSConfig(host="0.0.0.0")          # bind all interfaces
        config = TLSConfig(mtls=True)               # mutual TLS
        config = TLSConfig.for_server()             # named constructor
        config = TLSConfig.for_client("192.168.1.5")

    In QUANSEQ this is built from validated environment settings by
    protocols/tls/settings.py — it is not constructed with defaults at runtime.
    """

    # ── Connection ────────────────────────────────────────────────────────
    host: str            = "127.0.0.1"
    port: int            = 8443

    # ── Certificate paths ─────────────────────────────────────────────────
    cert_dir:    str     = "certs"
    ca_cert:     str     = "certs/ca.crt"
    server_cert: str     = "certs/server.crt"
    server_key:  str     = "certs/server.key"
    client_cert: str     = "certs/client.crt"
    client_key:  str     = "certs/client.key"

    # ── TLS options ───────────────────────────────────────────────────────
    server_hostname: str  = "localhost"   # SNI + cert CN/SAN check
    mtls: bool            = False         # mutual TLS
    timeout: int          = 10            # client socket timeout (seconds)

    # Gates startup on a runtime that *can* do the hybrid group. It does NOT
    # enforce that the group is negotiated — Python's ssl module exposes no
    # TLS 1.3 group-selection API. See VENDOR.md patch 3.
    require_hybrid_tls: bool = True
    hybrid_group: str       = "X25519MLKEM768"

    # ── Server options ────────────────────────────────────────────────────
    max_clients: int      = 10

    # QUANSEQ PATCH 4: cap per-connection handshake time so a stalled client
    # cannot occupy a worker indefinitely.
    handshake_timeout: float = 5.0
    max_concurrent_handshakes: int = 8

    # QUANSEQ PATCH 1/6: application payloads are never logged unless this is
    # explicitly enabled for local debugging.
    log_payloads: bool = False

    # Path to the OpenSSL CLI used for capability probes and cert inspection.
    openssl_bin: str = "openssl"

    # ── Named constructors ────────────────────────────────────────────────
    @classmethod
    def for_server(cls, host: str = "127.0.0.1", port: int = 8443,
                   mtls: bool = False) -> "TLSConfig":
        """Quick config for running a server."""
        return cls(host=host, port=port, mtls=mtls)

    @classmethod
    def for_client(cls, host: str = "127.0.0.1", port: int = 8443,
                   server_hostname: str = "localhost",
                   mtls: bool = False) -> "TLSConfig":
        """Quick config for running a client."""
        return cls(host=host, port=port,
                   server_hostname=server_hostname, mtls=mtls)
