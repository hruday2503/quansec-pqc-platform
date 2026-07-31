# tls13/cert_manager.py
# Vendored from tls13_module/cert_manager.py — see VENDOR.md
#
# QUANSEC PATCH 7: Linux-only guidance; generated private keys are chmod 600.
#
# Certificate generation is reachable from the CLI only
# (quansec/scripts/generate_tls_certs.py). It is deliberately not exposed
# through any HTTP route.

import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Optional

from .exceptions import CertGenerationError, CertNotFoundError

logger = logging.getLogger("quansec.tls.certs")

KEY_MODE = 0o600


class CertManager:
    """
    Development PKI generation, wrapping the OpenSSL CLI.

    Produces a local root CA, a server certificate with SAN, and a client
    certificate for mTLS. This is development material: the CA private key sits
    on disk beside the server key. Production needs an HSM- or KMS-held CA.

    Usage:
        cm = CertManager(cert_dir="/home/me/quansec-certs")
        if not cm.certs_exist():
            cm.generate_all(extra_ips=["192.168.1.50"])
    """

    def __init__(self, cert_dir: str = "certs", days: int = 825,
                 openssl_bin: str = "openssl"):
        self.cert_dir    = cert_dir
        self.days        = days
        self.openssl_bin = openssl_bin

    # ── Paths ─────────────────────────────────────────────────────────────────

    @property
    def ca_key(self)     -> str: return os.path.join(self.cert_dir, "ca.key")
    @property
    def ca_cert(self)    -> str: return os.path.join(self.cert_dir, "ca.crt")
    @property
    def server_key(self) -> str: return os.path.join(self.cert_dir, "server.key")
    @property
    def server_cert(self)-> str: return os.path.join(self.cert_dir, "server.crt")
    @property
    def client_key(self) -> str: return os.path.join(self.cert_dir, "client.key")
    @property
    def client_cert(self)-> str: return os.path.join(self.cert_dir, "client.crt")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_all(self, extra_ips: Optional[List[str]] = None,
                     extra_dns: Optional[List[str]] = None) -> None:
        """
        Generate a full development PKI: CA, server certificate, client certificate.

        Args:
            extra_ips: additional IPs for the server SAN. Pass the peer machine's
                       address here to make the same PKI work in two-machine mode.
            extra_dns: additional DNS names for the server SAN.
        """
        self._ensure_dir()
        self._check_openssl()
        self.generate_ca()
        self.generate_server_cert(extra_ips=extra_ips or [], extra_dns=extra_dns or [])
        self.generate_client_cert()
        logger.info("Development PKI generated in %s", self.cert_dir)

    def generate_ca(self) -> None:
        """Generate the root CA key and self-signed certificate."""
        self._ensure_dir()
        self._run([self.openssl_bin, "genrsa", "-out", self.ca_key, "4096"])
        self._protect_key(self.ca_key)
        self._run([
            self.openssl_bin, "req", "-new", "-x509",
            "-key",  self.ca_key,
            "-out",  self.ca_cert,
            "-days", str(self.days),
            "-subj", "/C=IN/O=QUANSEC/CN=QUANSEC TLS Development Root CA",
        ])
        logger.info("CA ready: %s", self.ca_cert)

    def generate_server_cert(self, extra_ips: Optional[List[str]] = None,
                             extra_dns: Optional[List[str]] = None) -> None:
        """Generate the server key, CSR and CA-signed certificate with a SAN."""
        self._ensure_dir()
        self._run([self.openssl_bin, "genrsa", "-out", self.server_key, "2048"])
        self._protect_key(self.server_key)

        alt_names = ["DNS.1 = localhost", "IP.1 = 127.0.0.1"]
        for i, name in enumerate(extra_dns or [], start=2):
            alt_names.append(f"DNS.{i} = {name}")
        for i, ip in enumerate(extra_ips or [], start=2):
            alt_names.append(f"IP.{i} = {ip}")
        alt_block = "\n".join(alt_names)

        csr_conf = self._write_temp(f"""
[req]
default_bits       = 2048
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext
prompt             = no

[dn]
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
{alt_block}
""")

        ext_conf = self._write_temp(f"""
authorityKeyIdentifier = keyid, issuer
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[alt_names]
{alt_block}
""")

        csr_path = os.path.join(self.cert_dir, "server.csr")
        self._sign(csr_path, self.server_key, self.server_cert, csr_conf, ext_conf)
        logger.info("Server certificate ready: %s", self.server_cert)

    def generate_client_cert(self) -> None:
        """Generate the client key and CA-signed certificate, for mTLS."""
        self._ensure_dir()
        self._run([self.openssl_bin, "genrsa", "-out", self.client_key, "2048"])
        self._protect_key(self.client_key)

        csr_conf = self._write_temp("""
[req]
distinguished_name = dn
prompt = no

[dn]
CN = quansec-tls-client
""")
        ext_conf = self._write_temp("""
authorityKeyIdentifier = keyid, issuer
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
""")

        csr_path = os.path.join(self.cert_dir, "client.csr")
        self._sign(csr_path, self.client_key, self.client_cert, csr_conf, ext_conf)
        logger.info("Client certificate ready: %s", self.client_cert)

    def certs_exist(self) -> bool:
        """True if the CA, server and client material are all present."""
        return all(os.path.isfile(p) for p in [
            self.ca_cert, self.server_cert, self.server_key,
            self.client_cert, self.client_key,
        ])

    def verify(self, cert_path: str) -> bool:
        """Verify cert_path against the local CA. Returns True if the chain is valid."""
        if not os.path.isfile(cert_path):
            raise CertNotFoundError(f"Certificate not found: {cert_path}")
        result = subprocess.run(
            [self.openssl_bin, "verify", "-CAfile", self.ca_cert, cert_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.info("Chain verification failed for %s: %s",
                        cert_path, result.stderr.strip())
        return result.returncode == 0

    def get_cert_info(self, cert_path: str) -> Dict[str, str]:
        """
        Subject, issuer, dates and SAN for a certificate, as OpenSSL prints them.

        Structured parsing for the API lives in protocols/tls/certs.py; this stays
        as the upstream text view for CLI use.
        """
        if not os.path.isfile(cert_path):
            raise CertNotFoundError(f"Certificate not found: {cert_path}")
        result = subprocess.run(
            [self.openssl_bin, "x509", "-in", cert_path, "-noout",
             "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
            capture_output=True, text=True, timeout=30,
        )
        info: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip()
        return info

    # ── Internal ──────────────────────────────────────────────────────────────

    def _sign(self, csr_path: str, key_path: str, out_cert: str,
              csr_conf: str, ext_conf: str) -> None:
        """Create a CSR from key_path and sign it with the CA."""
        try:
            self._run([self.openssl_bin, "req", "-new",
                       "-key", key_path,
                       "-out", csr_path,
                       "-config", csr_conf])
            self._run([self.openssl_bin, "x509", "-req",
                       "-in",  csr_path,
                       "-CA",  self.ca_cert,
                       "-CAkey", self.ca_key,
                       "-CAcreateserial",
                       "-out", out_cert,
                       "-days", str(self.days),
                       "-sha256",
                       "-extfile", ext_conf])
        finally:
            for path in (csr_path, csr_conf, ext_conf,
                         os.path.join(self.cert_dir, "ca.srl")):
                try:
                    os.remove(path)
                except OSError:
                    pass

    def _run(self, cmd: List[str]) -> None:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise CertGenerationError(
                f"openssl command failed: {' '.join(cmd)}\n{result.stderr.strip()}"
            )

    def _ensure_dir(self) -> None:
        """
        QUANSEC PATCH 7: create the output directory before writing into it.

        Upstream only created it in generate_all(), so calling generate_ca() or
        generate_server_cert() directly failed with an opaque openssl error.
        """
        os.makedirs(self.cert_dir, mode=0o700, exist_ok=True)

    @staticmethod
    def _protect_key(path: str) -> None:
        """Private keys are owner-read-only from the moment they are written."""
        os.chmod(path, KEY_MODE)

    def _write_temp(self, content: str) -> str:
        """Write content to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".cnf", prefix="quansec_tls_")
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        return path

    def _check_openssl(self) -> None:
        try:
            result = subprocess.run(
                [self.openssl_bin, "version"], capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise CertGenerationError(
                f"Cannot run '{self.openssl_bin}': {exc}. Install it with "
                "'sudo apt install openssl'."
            ) from exc
        if result.returncode != 0:
            raise CertGenerationError(
                f"'{self.openssl_bin} version' failed: {result.stderr.strip()}"
            )
