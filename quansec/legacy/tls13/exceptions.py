# tls13/exceptions.py
# Vendored unchanged from tls13_module/exceptions.py — see VENDOR.md


class TLSModuleError(Exception):
    """Base exception for all tls13 errors."""


class TLSHandshakeError(TLSModuleError):
    """Raised when TLS handshake fails."""


class CertVerificationError(TLSModuleError):
    """Raised when certificate verification fails."""


class CertNotFoundError(TLSModuleError):
    """Raised when a required certificate file is missing."""


class TLSConnectionError(TLSModuleError):
    """Raised when TCP/TLS connection cannot be established."""


class TLSVersionError(TLSModuleError):
    """Raised when TLS 1.3 is not supported by the system."""


class CertGenerationError(TLSModuleError):
    """Raised when certificate generation fails (openssl error)."""
