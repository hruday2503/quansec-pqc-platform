"""
tls13 — vendored TLS 1.3 client and certificate tooling
───────────────────────────────────────────────────────
Supporting library for the TLS module. Provides a verifying TLS 1.3 client and
development-PKI generation, both built on Python's stdlib `ssl`.

Vendored from https://github.com/V-Preetha/TLS-SMOAD-HSC (commit 2b361a9) and
patched for QUANSEQ. See VENDOR.md for provenance, excluded files, and the
rationale for every patch.

**This package is not the TLS data plane.** NGINX 1.27.5 linked against
OpenSSL 3.5.7 is — see protocols/tls/service.py. The vendored TLS *server* was
removed precisely because Python's `ssl` cannot restrict TLS 1.3 groups to a
named hybrid group, so it could never enforce X25519MLKEM768. What remains is
the client and certificate side, which probe.py reuses for validation.

Two limits still apply to anything this package reports:

  * `negotiated_group` is always None — Python's `ssl` cannot read it.
    Authoritative group data comes from the NGINX `$ssl_curve` log and from the
    OpenSSL 3.5.7 CLI, not from here.
  * `require_hybrid_tls` gates on a *capable* runtime. Passing that gate is not
    evidence that a hybrid group was negotiated.
"""

from .cert_manager import CertManager
from .client import TLSClient
from .config import TLSConfig
from .exceptions import (
    CertGenerationError,
    CertNotFoundError,
    CertVerificationError,
    TLSConnectionError,
    TLSHandshakeError,
    TLSModuleError,
    TLSVersionError,
)
from .utils import (
    GROUP_SOURCE_UNAVAILABLE,
    MIN_HYBRID_OPENSSL,
    linked_openssl_version,
    list_tls_groups,
    runtime_supports_group,
)

__all__ = [
    "TLSClient",
    "TLSConfig",
    "CertManager",
    "TLSModuleError",
    "TLSHandshakeError",
    "CertVerificationError",
    "CertNotFoundError",
    "TLSConnectionError",
    "TLSVersionError",
    "CertGenerationError",
    "GROUP_SOURCE_UNAVAILABLE",
    "MIN_HYBRID_OPENSSL",
    "linked_openssl_version",
    "list_tls_groups",
    "runtime_supports_group",
]
