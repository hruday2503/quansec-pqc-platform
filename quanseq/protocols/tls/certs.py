"""
protocols/tls/certs.py — structured inspection of the TLS data-plane certificate.

Answers one question the rest of the module depends on: **is certificate
authentication post-quantum?** The answer today is no, and this module is
written so that it cannot accidentally start saying otherwise.

`pqc_signature` is decided by looking up the certificate's signature algorithm
OID in an explicit allow-list of post-quantum algorithms. It is never inferred
from the negotiated key exchange, from the OpenSSL version, or from what the
runtime advertises. X25519MLKEM768 makes the *key exchange* hybrid
post-quantum; an ECDSA certificate leaves *authentication* classical, and the
two must be reported on separate axes.

Chain verification is a real `openssl verify` against the configured CA, run
with the **runtime** OpenSSL — the system 3.0.13 would not understand an ML-DSA
certificate if one were ever installed, and would report a confusing failure
rather than an accurate one.
"""

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .settings import TlsSettings, get_tls_settings

logger = logging.getLogger("quanseq.tls.certs")


class CertificateUnavailable(RuntimeError):
    """The certificate is missing, unreadable, or not parseable."""


# Post-quantum signature algorithm OIDs (NIST FIPS 204 / 205).
#
# An explicit allow-list, not a name match. Substring matching on the algorithm
# name would call an "ecdsa-with-SHA256-mldsa-test" certificate post-quantum,
# and the whole value of this flag is that it cannot be talked into being true.
PQC_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
}


@dataclass
class CertificateFacts:
    """Everything read off the certificate itself."""

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    signature_oid: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    san: List[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    pqc_signature: bool = False
    self_signed: bool = False


def describe_certificate(settings: Optional[TlsSettings] = None,
                         path: Optional[str] = None) -> CertificateFacts:
    """
    Parse the server certificate into structured facts.

    Raises CertificateUnavailable rather than returning a half-populated record:
    a status page that shows "unknown" for every field is more honest than one
    showing blanks that read as measurements.
    """
    s = settings or get_tls_settings()
    cert_path = path or s.server_cert

    if not os.path.isfile(cert_path):
        raise CertificateUnavailable(f"Certificate not found at {cert_path}")
    if not os.access(cert_path, os.R_OK):
        raise CertificateUnavailable(f"Certificate at {cert_path} is not readable")

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    except ImportError as exc:                   # pragma: no cover
        raise CertificateUnavailable(
            "The `cryptography` package is required to parse certificates"
        ) from exc

    try:
        with open(cert_path, "rb") as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
    except Exception as exc:                     # noqa: BLE001
        raise CertificateUnavailable(f"Could not parse {cert_path}: {exc}") from exc

    # Signature algorithm. The OID is authoritative; the name is for display.
    try:
        signature_oid = cert.signature_algorithm_oid.dotted_string
        signature_name = cert.signature_algorithm_oid._name          # noqa: SLF001
    except Exception:                            # noqa: BLE001
        signature_oid, signature_name = None, None

    pqc_signature = signature_oid in PQC_SIGNATURE_OIDS if signature_oid else False
    if pqc_signature:
        signature_name = PQC_SIGNATURE_OIDS[signature_oid]

    # Public key.
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    try:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key_algorithm, key_size = "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key_algorithm = f"ECDSA ({public_key.curve.name})"
            key_size = public_key.curve.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key_algorithm, key_size = "Ed25519", 256
        else:
            public_key_algorithm = type(public_key).__name__
    except Exception as exc:                     # noqa: BLE001
        logger.debug("Could not classify public key in %s: %s", cert_path, exc)

    san: List[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(name.value) for name in extension.value]
    except x509.ExtensionNotFound:
        pass
    except Exception as exc:                     # noqa: BLE001
        logger.debug("Could not read SAN from %s: %s", cert_path, exc)

    # `not_valid_after_utc` replaced the naive property in cryptography 42;
    # fall back so an older pin does not break certificate reporting entirely.
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:                       # pragma: no cover
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    days_until_expiry = (not_after - datetime.now(timezone.utc)).days

    return CertificateFacts(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        signature_algorithm=signature_name,
        signature_oid=signature_oid,
        public_key_algorithm=public_key_algorithm,
        key_size=key_size,
        san=san,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        pqc_signature=pqc_signature,
        self_signed=cert.subject == cert.issuer,
    )


def verify_chain(settings: Optional[TlsSettings] = None) -> bool:
    """
    Verify the server certificate against the configured CA.

    A real `openssl verify` with the **runtime** binary, not a string comparison
    of issuer and subject: only the real verification catches an expired CA, a
    bad signature, or a certificate that merely claims the right issuer name.

    Returns False on any failure, including being unable to run the binary. An
    unverifiable certificate must never be reported as verified.
    """
    s = settings or get_tls_settings()

    for path in (s.ca_cert, s.server_cert):
        if not os.path.isfile(path):
            logger.info("Chain verification skipped: %s does not exist", path)
            return False

    binary = s.openssl_bin if os.path.isfile(s.openssl_bin) else "openssl"
    try:
        result = subprocess.run(
            [binary, "verify", "-CAfile", s.ca_cert, s.server_cert],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Could not run `openssl verify`: %s", exc)
        return False

    output = (result.stdout or "") + (result.stderr or "")
    verified = result.returncode == 0 and ": OK" in output
    if not verified:
        logger.info("Certificate chain verification failed: %s", output.strip())
    return verified


def signature_algorithm_report(settings: Optional[TlsSettings] = None) -> dict:
    """
    Whether the runtime advertises any post-quantum signature algorithm.

    Input to the ML-DSA research profile. Advertising is not use: nothing here
    sets `authentication_quantum_safe`, which comes only from a real certificate
    parsed by describe_certificate().
    """
    s = settings or get_tls_settings()
    try:
        result = subprocess.run(
            [s.openssl_bin, "list", "-signature-algorithms"],
            capture_output=True, text=True, timeout=15,
        )
        text = (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.SubprocessError):
        text = ""

    names = [n.strip() for n in re.split(r"[:\s,]+", text) if n.strip()]
    mldsa = [n for n in names if "mldsa" in n.lower() or "ml-dsa" in n.lower()]
    return {
        "openssl_binary": s.openssl_bin,
        "total_advertised": len(names),
        "ml_dsa_advertised": mldsa,
        "ml_dsa_available": bool(mldsa),
        "note": (
            "Advertised by the runtime only. Post-quantum authentication is NOT "
            "claimed until an ML-DSA certificate is generated, loaded by NGINX, "
            "and verified by a client."
        ),
    }
