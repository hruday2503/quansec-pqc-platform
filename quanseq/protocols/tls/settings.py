"""
protocols/tls/settings.py — validated configuration for the TLS module.

The TLS data plane is NGINX linked against OpenSSL 3.5.7. This module resolves
where that runtime lives, what policy it should enforce, and refuses to start
when anything required is missing.

Validation is strict and runs at application startup: a missing NGINX binary or
an unreadable certificate should stop the process with a message an operator can
act on, not surface later as a confusing 500 on an API call.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

from core.config import settings as app_settings

# The runtime must provide the hybrid group. 3.5.x is the LTS line that ships it.
MIN_OPENSSL = (3, 5, 0)
# ssl_conf_command needs 1.19.4+; $ssl_curve needs 1.21.8+. 1.27.5 is the floor
# this platform builds and tests against.
MIN_NGINX = (1, 27, 5)


class TlsConfigurationError(RuntimeError):
    """Raised when the TLS module is enabled but misconfigured."""


@dataclass(frozen=True)
class TlsSettings:
    """Resolved, validated TLS module settings."""

    enabled: bool

    # Endpoint the data plane listens on, and that probes connect to.
    host: str
    port: int
    server_hostname: str

    # Isolated runtime — never the system OpenSSL or system NGINX.
    runtime_dir: str
    nginx_bin: str
    openssl_bin: str
    nginx_conf: str
    access_log: str
    error_log: str
    pid_file: str
    evidence_dir: str

    cert_dir: str
    ca_cert: str
    server_cert: str
    server_key: str
    client_cert: str
    client_key: str

    # Enforced policy — rendered directly into NGINX directives.
    protocols: str
    groups: str
    ciphersuites: str
    hybrid_group: str
    mtls: bool
    early_data: bool

    upstream: str
    timeout: int
    poll_interval: int
    log_payloads: bool

    # Portal listener. Browser-reachable, deliberately NOT fail-closed, and
    # logged to its own file so its sessions are never counted as evidence
    # that the strict listener enforced anything.
    portal_enabled: bool
    portal_port: int
    portal_groups: str
    portal_ciphersuites: str
    portal_access_log: str
    ui_upstream: str

    @classmethod
    def from_env(cls) -> "TlsSettings":
        s = app_settings
        return cls(
            enabled=s.TLS_ENABLED,
            host=s.TLS_HOST,
            port=s.TLS_PORT,
            server_hostname=s.TLS_SERVER_HOSTNAME,
            runtime_dir=s.TLS_RUNTIME_DIR,
            nginx_bin=s.TLS_NGINX_BIN,
            openssl_bin=s.TLS_OPENSSL_BIN,
            nginx_conf=s.TLS_NGINX_CONF,
            access_log=s.TLS_ACCESS_LOG,
            error_log=s.TLS_ERROR_LOG,
            pid_file=s.TLS_PID_FILE,
            evidence_dir=s.TLS_EVIDENCE_DIR,
            cert_dir=s.TLS_CERT_DIR,
            ca_cert=s.TLS_CA_CERT,
            server_cert=s.TLS_SERVER_CERT,
            server_key=s.TLS_SERVER_KEY,
            client_cert=s.TLS_CLIENT_CERT,
            client_key=s.TLS_CLIENT_KEY,
            protocols=s.TLS_PROTOCOLS,
            groups=s.TLS_GROUPS,
            ciphersuites=s.TLS_CIPHERSUITES,
            hybrid_group=s.TLS_HYBRID_GROUP,
            mtls=s.TLS_MTLS,
            early_data=s.TLS_EARLY_DATA,
            upstream=s.TLS_UPSTREAM,
            timeout=s.TLS_TIMEOUT,
            poll_interval=s.TLS_POLL_INTERVAL,
            log_payloads=s.TLS_LOG_PAYLOADS,
            portal_enabled=s.TLS_PORTAL_ENABLED,
            portal_port=s.TLS_PORTAL_PORT,
            portal_groups=s.TLS_PORTAL_GROUPS,
            portal_ciphersuites=s.TLS_PORTAL_CIPHERSUITES,
            portal_access_log=s.TLS_PORTAL_ACCESS_LOG,
            ui_upstream=s.TLS_UI_UPSTREAM,
        )

    # ── Runtime introspection ─────────────────────────────────────────────────

    def runtime_available(self) -> bool:
        """True when the built runtime exists. False before build-pqc-tls-runtime.sh."""
        return os.path.isfile(self.nginx_bin) and os.path.isfile(self.openssl_bin)

    def openssl_version(self) -> Optional[str]:
        """Version string of the RUNTIME OpenSSL, or None if it cannot run."""
        return _run_capture([self.openssl_bin, "version"])

    def nginx_version_line(self) -> Optional[str]:
        """`nginx -v` output for the runtime binary."""
        return _run_capture([self.nginx_bin, "-v"])

    def nginx_build_info(self) -> Optional[str]:
        """Full `nginx -V` output — the proof of which OpenSSL it was built against."""
        return _run_capture([self.nginx_bin, "-V"])

    def nginx_linked_openssl(self) -> Optional[str]:
        """
        The OpenSSL version NGINX reports being built with.

        This is the single most important fact about the data plane: NGINX built
        against OpenSSL 3.0 cannot enforce X25519MLKEM768 no matter what the
        configuration says.
        """
        info = self.nginx_build_info() or ""
        match = re.search(r"built with OpenSSL\s+(\S+)", info)
        return match.group(1) if match else None

    def runtime_tls_groups(self) -> List[str]:
        """
        Group names the runtime OpenSSL advertises.

        `openssl list -tls-groups` prints a single colon-separated line, not one
        name per line — splitting on newlines alone silently finds nothing.
        Whitespace and `@` suffixes are tolerated so a format change does not
        turn "supported" into a false negative without anyone noticing.
        """
        output = _run_capture([self.openssl_bin, "list", "-tls-groups"]) or ""
        names: List[str] = []
        for chunk in re.split(r"[:\s,]+", output):
            name = chunk.split("@")[0].strip()
            if name:
                names.append(name)
        return names

    def runtime_lists_group(self, group: Optional[str] = None) -> bool:
        """Whether the runtime OpenSSL advertises the group."""
        wanted = (group or self.hybrid_group).lower()
        return any(name.lower() == wanted for name in self.runtime_tls_groups())

    def system_openssl_version(self) -> Optional[str]:
        """The system OpenSSL, reported separately so the two are never confused."""
        system = shutil.which("openssl")
        return _run_capture([system, "version"]) if system else None

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self, *, require_runtime: bool = True) -> List[str]:
        """
        Raise TlsConfigurationError on anything that would break at runtime.

        Args:
            require_runtime: require the built NGINX/OpenSSL. False lets the API
                start and report the module as unbuilt rather than refusing to boot.

        Returns non-fatal warnings for the caller to log.
        """
        if not self.enabled:
            return ["TLS module disabled (QUANSEQ_TLS_ENABLED=false)"]

        problems: List[str] = []
        warnings: List[str] = []

        if not 1 <= self.port <= 65535:
            problems.append(f"QUANSEQ_TLS_PORT must be 1-65535, got {self.port}")
        if self.timeout <= 0:
            problems.append(f"QUANSEQ_TLS_TIMEOUT must be positive, got {self.timeout}")
        if self.poll_interval <= 0:
            problems.append(
                f"QUANSEQ_TLS_POLL_INTERVAL must be positive, got {self.poll_interval}"
            )
        if not self.server_hostname:
            problems.append("QUANSEQ_TLS_SERVER_HOSTNAME must not be empty")
        if not self.groups.strip():
            problems.append("QUANSEQ_TLS_GROUPS must not be empty - that would remove enforcement")

        problems += _require_file(self.ca_cert, "QUANSEQ_TLS_CA_CERT")
        problems += _require_file(self.server_cert, "QUANSEQ_TLS_SERVER_CERT")
        problems += _require_file(self.server_key, "QUANSEQ_TLS_SERVER_KEY")
        if self.mtls:
            problems += _require_file(self.client_cert, "QUANSEQ_TLS_CLIENT_CERT")
            problems += _require_file(self.client_key, "QUANSEQ_TLS_CLIENT_KEY")

        if require_runtime:
            problems += self._validate_runtime()
        elif not self.runtime_available():
            warnings.append(
                f"TLS runtime not built at {self.runtime_dir} - run "
                "scripts/build-pqc-tls-runtime.sh. TLS endpoints will report "
                "the data plane as unavailable."
            )

        # A policy that lists a classical group alongside the hybrid one is legal
        # but is no longer fail-closed, so say so rather than letting the status
        # page imply enforcement.
        extra_groups = [g for g in re.split(r"[:,\s]+", self.groups) if g and g.lower() != self.hybrid_group.lower()]
        if extra_groups:
            warnings.append(
                f"QUANSEQ_TLS_GROUPS lists fallback groups {extra_groups} alongside "
                f"{self.hybrid_group}. Clients may negotiate classical key exchange; "
                "this is NOT fail-closed."
            )
        if self.early_data:
            warnings.append(
                "QUANSEQ_TLS_EARLY_DATA=true enables TLS 1.3 0-RTT, which is replayable."
            )
        if self.log_payloads:
            warnings.append(
                "QUANSEQ_TLS_LOG_PAYLOADS=true - local debugging only."
            )
        if not self.mtls:
            warnings.append("mTLS is off - the data plane does not authenticate its clients.")

        if problems:
            raise TlsConfigurationError(
                "TLS module configuration is invalid:\n  - " + "\n  - ".join(problems)
            )
        return warnings

    def _validate_runtime(self) -> List[str]:
        """Check the built runtime is present, correct, and hybrid-capable."""
        problems: List[str] = []

        if not os.path.isfile(self.openssl_bin):
            return [
                f"Runtime OpenSSL not found at {self.openssl_bin}. "
                "Run: bash scripts/build-pqc-tls-runtime.sh"
            ]
        if not os.path.isfile(self.nginx_bin):
            return [
                f"Runtime NGINX not found at {self.nginx_bin}. "
                "Run: bash scripts/build-pqc-tls-runtime.sh"
            ]

        openssl_version = self.openssl_version()
        if not openssl_version:
            problems.append(
                f"{self.openssl_bin} could not be executed - the build may be "
                "linked against the wrong libssl (check with ldd)"
            )
        else:
            triple = _version_triple(openssl_version)
            if triple and triple < MIN_OPENSSL:
                problems.append(
                    f"Runtime OpenSSL is {openssl_version}; "
                    f"{'.'.join(map(str, MIN_OPENSSL))}+ is required for {self.hybrid_group}"
                )

        nginx_openssl = self.nginx_linked_openssl()
        if not nginx_openssl:
            problems.append(f"Could not read `nginx -V` from {self.nginx_bin}")
        else:
            triple = _version_triple(nginx_openssl)
            if triple and triple < MIN_OPENSSL:
                problems.append(
                    f"NGINX is built against OpenSSL {nginx_openssl}, which cannot "
                    f"enforce {self.hybrid_group}. Rebuild with "
                    "scripts/build-pqc-tls-runtime.sh"
                )

        nginx_version = self.nginx_version_line() or ""
        triple = _version_triple(nginx_version)
        if triple and triple < MIN_NGINX:
            problems.append(
                f"NGINX is {nginx_version.strip()}; "
                f"{'.'.join(map(str, MIN_NGINX))}+ is required for ssl_conf_command "
                "and $ssl_curve"
            )

        if not problems and not self.runtime_lists_group():
            problems.append(
                f"{self.openssl_bin} does not list {self.hybrid_group} in "
                "`list -tls-groups` - the data plane cannot enforce it"
            )

        return problems

    def redacted(self) -> dict:
        """Loggable view: paths and policy, never file contents."""
        return {
            "enabled": self.enabled,
            "endpoint": f"{self.host}:{self.port}",
            "server_hostname": self.server_hostname,
            "runtime_dir": self.runtime_dir,
            "nginx_bin": self.nginx_bin,
            "openssl_bin": self.openssl_bin,
            "nginx_conf": self.nginx_conf,
            "access_log": self.access_log,
            "protocols": self.protocols,
            "groups": self.groups,
            "ciphersuites": self.ciphersuites,
            "mtls": self.mtls,
            "early_data": self.early_data,
            "upstream": self.upstream,
            "poll_interval": self.poll_interval,
            "ca_cert": self.ca_cert,
            "server_cert": self.server_cert,
            "server_key": self.server_key,
        }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _run_capture(command: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout+stderr, or None if it could not run."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 and not result.stdout and not result.stderr:
        return None
    # nginx writes -v/-V to stderr; openssl writes version to stdout.
    return (result.stdout or "") + (result.stderr or "")


def _version_triple(text: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(p) for p in match.groups()) if match else None  # type: ignore[return-value]


def _require_file(path: str, env_name: str) -> List[str]:
    if not path:
        return [f"{env_name} is not set"]
    if not os.path.isfile(path):
        return [
            f"{env_name}={path} does not exist. Generate a development PKI with: "
            "python scripts/generate_tls_certs.py"
        ]
    if not os.access(path, os.R_OK):
        return [f"{env_name}={path} is not readable by this user"]
    return []


def get_tls_settings() -> TlsSettings:
    """Read the current environment-backed TLS settings."""
    return TlsSettings.from_env()
