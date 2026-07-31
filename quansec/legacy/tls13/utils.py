# tls13/utils.py
# Vendored from tls13_module/utils.py — see VENDOR.md
#
# QUANSEC PATCH 1: stdlib logging instead of coloured print(); payload redaction.
# QUANSEC PATCH 2: honest negotiated-group reporting.
# QUANSEC PATCH 3: _require_hybrid_tls_runtime renamed and widened.

import datetime
import logging
import os
import re
import ssl
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .config import TLSConfig
from .exceptions import CertNotFoundError, TLSVersionError

logger = logging.getLogger("quansec.tls.transport")

# The Python ssl module has no API for reading the negotiated TLS 1.3 named
# group. Any caller that sees negotiated_group is None must consult this to
# learn whether that means "classical" or "we cannot tell".
GROUP_SOURCE_UNAVAILABLE = "unavailable-python-ssl"

# Minimum linked OpenSSL that ships the standardised hybrid groups.
MIN_HYBRID_OPENSSL: Tuple[int, int, int] = (3, 5, 5)


def build_server_context(config: TLSConfig) -> ssl.SSLContext:
    """
    Build a TLS 1.3-only server SSLContext from a TLSConfig.
    Raises CertNotFoundError if cert/key files are missing.
    Raises TLSVersionError if TLS 1.3 or a required hybrid runtime is unavailable.
    """
    for path, label in [
        (config.server_cert, "Server certificate"),
        (config.server_key,  "Server private key"),
    ]:
        if not os.path.isfile(path):
            raise CertNotFoundError(
                f"{label} not found: {path}. "
                "Generate a development PKI with scripts/generate_tls_certs.py"
            )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _enforce_tls13(ctx)
    _require_hybrid_capable_runtime(config)
    ctx.load_cert_chain(certfile=config.server_cert, keyfile=config.server_key)

    if config.mtls:
        if not os.path.isfile(config.ca_cert):
            raise CertNotFoundError(f"CA cert not found for mTLS: {config.ca_cert}")
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=config.ca_cert)
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def build_client_context(config: TLSConfig) -> ssl.SSLContext:
    """
    Build a TLS 1.3-only client SSLContext from a TLSConfig.
    Certificate verification is always ON (CERT_REQUIRED + check_hostname).
    """
    if not os.path.isfile(config.ca_cert):
        raise CertNotFoundError(
            f"CA certificate not found: {config.ca_cert}. "
            "Generate a development PKI with scripts/generate_tls_certs.py"
        )

    # PROTOCOL_TLS_CLIENT sets verify_mode=CERT_REQUIRED, check_hostname=True by
    # default; both are set again below so the guarantee is explicit in-source.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _enforce_tls13(ctx)
    _require_hybrid_capable_runtime(config)

    ctx.verify_mode    = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=config.ca_cert)

    if config.mtls:
        for path, label in [
            (config.client_cert, "Client certificate"),
            (config.client_key,  "Client private key"),
        ]:
            if not os.path.isfile(path):
                raise CertNotFoundError(f"{label} not found: {path}")
        ctx.load_cert_chain(certfile=config.client_cert, keyfile=config.client_key)

    return ctx


def get_session_info(sock: ssl.SSLSocket,
                     config: Optional[TLSConfig] = None) -> Dict[str, Any]:
    """
    Extract TLS session metadata from a connected SSLSocket.

    QUANSEC PATCH 2 — on negotiated_group:
        Python's ssl module cannot report the negotiated TLS 1.3 named group, so
        this value is always None. `negotiated_group_source` records *why*, so a
        caller never reads None as "the peer used no group" or as evidence that a
        classical group was chosen. `hybrid_group_configured` is the group that
        was asked for, never a claim that it was used. The only way to establish
        the negotiated group is out-of-band verification (openssl s_client -brief
        or a packet capture).
    """
    cipher      = sock.cipher()       # (name, protocol, bits)
    peer_cert   = sock.getpeercert()
    version     = sock.version()

    info: Dict[str, Any] = {
        "tls_version":      version,
        "cipher_name":      cipher[0] if cipher else None,
        "cipher_bits":      cipher[2] if cipher else None,
        "openssl_version":  ssl.OPENSSL_VERSION,
        "negotiated_group": None,
        "negotiated_group_source": GROUP_SOURCE_UNAVAILABLE,
        "hybrid_group_configured": config.hybrid_group if config else None,
        "peer_cert":        None,
    }

    if peer_cert:
        subj   = dict(x[0] for x in peer_cert.get("subject",  []))
        issuer = dict(x[0] for x in peer_cert.get("issuer",   []))
        san    = peer_cert.get("subjectAltName", [])
        info["peer_cert"] = {
            "cn":         subj.get("commonName",   None),
            "issuer_cn":  issuer.get("commonName", None),
            "not_before": peer_cert.get("notBefore", None),
            "not_after":  peer_cert.get("notAfter",  None),
            "san":        [f"{t}:{v}" for t, v in san],
        }

    return info


def redact_payload(message: str, config: TLSConfig) -> str:
    """
    QUANSEC PATCH 1/6 — return a loggable stand-in for an application payload.

    Upstream logged every message body in cleartext on both ends. Payloads may
    carry tokens, credentials or PII, so the default is a length-only summary.
    """
    if config.log_payloads:
        return message
    return f"<redacted {len(message.encode('utf-8'))} bytes>"


# ─── Internal helpers ────────────────────────────────────────────────────────
def _enforce_tls13(ctx: ssl.SSLContext) -> None:
    """Pin the context to TLS 1.3 as the only allowed version."""
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except (AttributeError, ValueError) as exc:
        raise TLSVersionError(
            f"TLS 1.3 is not available on this system: {exc}"
        ) from exc


def linked_openssl_version() -> Tuple[int, int, int]:
    """Version triple of the OpenSSL that Python's ssl module is linked against."""
    match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", ssl.OPENSSL_VERSION)
    if match:
        return tuple(int(part) for part in match.groups())  # type: ignore[return-value]
    return tuple(ssl.OPENSSL_VERSION_INFO[:3])              # type: ignore[return-value]


def list_tls_groups(openssl_bin: str = "openssl") -> List[str]:
    """
    Names of the TLS groups the OpenSSL CLI reports.

    Returns an empty list when the CLI is missing or predates `list -tls-groups`
    (added in OpenSSL 3.5). An empty list means "cannot confirm", and callers
    must treat that as the group being unavailable rather than assuming support.
    """
    try:
        result = subprocess.run(
            [openssl_bin, "list", "-tls-groups"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("openssl list -tls-groups unavailable: %s", exc)
        return []

    if result.returncode != 0:
        # OpenSSL < 3.5 answers "list: Unknown option: -tls-groups".
        logger.debug("openssl list -tls-groups failed: %s", result.stderr.strip())
        return []

    # `openssl list -tls-groups` prints ONE colon-separated line, not one name
    # per line. Splitting on newlines alone silently returns nothing, which the
    # caller would read as "group unsupported".
    groups: List[str] = []
    for chunk in re.split(r"[:\s,]+", result.stdout):
        name = chunk.split("@")[0].strip()
        if name:
            groups.append(name)
    return groups


def runtime_supports_group(group: str, openssl_bin: str = "openssl") -> bool:
    """True only if `group` is listed by the OpenSSL CLI (case-insensitive)."""
    wanted = group.lower()
    return any(name.lower() == wanted for name in list_tls_groups(openssl_bin))


def _require_hybrid_capable_runtime(config: TLSConfig) -> None:
    """
    Gate startup on a runtime that is *capable* of the configured hybrid group.

    This is a runtime capability check, not an enforcement mechanism. It cannot
    make hybrid key exchange mandatory: Python's ssl module exposes no TLS 1.3
    group-selection API, so a peer offering only classical X25519 will still
    complete a handshake against this server even when this check passes.
    Enforcement requires OpenSSL SSL_CONF, native bindings, or a terminating
    proxy with a strict group policy.
    """
    if not config.require_hybrid_tls:
        return

    current = linked_openssl_version()
    if current < MIN_HYBRID_OPENSSL:
        raise TLSVersionError(
            "Hybrid TLS was required, but Python is linked against "
            f"{ssl.OPENSSL_VERSION}. The hybrid group {config.hybrid_group} needs "
            f"OpenSSL {'.'.join(str(p) for p in MIN_HYBRID_OPENSSL)}+ or 4.x. "
            "Run with QUANSEC_TLS_REQUIRE_HYBRID=false, or use a Python linked "
            "against a newer OpenSSL."
        )

    if not runtime_supports_group(config.hybrid_group, config.openssl_bin):
        raise TLSVersionError(
            f"Hybrid TLS was required, but the group {config.hybrid_group} is not "
            f"listed by '{config.openssl_bin} list -tls-groups'. "
            "Run with QUANSEC_TLS_REQUIRE_HYBRID=false, or point "
            "QUANSEC_TLS_OPENSSL_BIN at an OpenSSL that provides the group."
        )


def capture_handshake_info(ssl_sock: ssl.SSLSocket,
                           config: Optional[TLSConfig] = None) -> Dict[str, Any]:
    """
    Handshake facts for logging and persistence.

    Every field is read off the live socket. Nothing here is inferred from
    configuration, and nothing asserts a post-quantum property.
    """
    info = get_session_info(ssl_sock, config)

    try:
        peer_addr = ssl_sock.getpeername()
        peer_address = f"{peer_addr[0]}:{peer_addr[1]}"
    except OSError:
        peer_address = None

    info["peer_address"] = peer_address
    info["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return info
