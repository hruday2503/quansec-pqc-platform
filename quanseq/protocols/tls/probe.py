"""
protocols/tls/probe.py — enforcement probes against the live data plane.

This module is where "enforced" stops being a claim and becomes a measurement.

Every probe is a real TLS handshake attempt made by the **runtime OpenSSL 3.5.7
client**, never the system 3.0.13 — a client that does not know X25519MLKEM768
could not tell an enforcing server from a broken one.

The asymmetry that matters: a *negative* probe passes when the handshake
**fails**. Proving a hybrid handshake works shows the server can do hybrid. Only
proving a classical client is refused shows it must. `expected_outcome` records
which assertion each probe makes, so the intent is in the data and not just in
the code that wrote it.
"""

import logging
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .settings import TlsSettings, get_tls_settings

logger = logging.getLogger("quanseq.tls.probe")

# ── Probe identifiers (must match the CHECK in migrations/007_tls.sql) ───────
POSITIVE_HYBRID = "positive_hybrid"
NEGATIVE_X25519 = "negative_x25519"
NEGATIVE_PRIME256V1 = "negative_prime256v1"
NEGATIVE_TLS12 = "negative_tls12"
NEGATIVE_AES128 = "negative_aes128"
NEGATIVE_INVALID_CA = "negative_invalid_ca"
NEGATIVE_MISSING_CLIENT_CERT = "negative_missing_client_cert"

OUTCOME_CONNECT = "connect"
OUTCOME_REJECT = "reject"
OUTCOME_ERROR = "error"

# The two probes that together prove fail-closed group enforcement. Both must
# pass: a server could allow prime256v1 but not X25519, and one refusal alone
# would not distinguish that from real enforcement.
ENFORCEMENT_PROBES = (NEGATIVE_X25519, NEGATIVE_PRIME256V1)

_NEGOTIATED_GROUP = re.compile(r"Negotiated\s+TLS1\.3\s+group:\s*(?P<group>\S+)", re.I)
_CIPHERSUITE = re.compile(r"Ciphersuite:\s*(?P<cipher>\S+)", re.I)
_PROTOCOL = re.compile(r"Protocol version:\s*(?P<proto>\S+)", re.I)
_VERIFICATION = re.compile(r"Verification(?: error)?:\s*(?P<result>.+)", re.I)


# How a probe decides it was refused.
#
# HANDSHAKE   the TLS handshake itself fails. This is how group, protocol and
#             cipher enforcement present: NGINX has no shared key share or
#             protocol version and aborts before any application data.
#
# HTTP_STATUS the handshake completes and the request is refused at the HTTP
#             layer. This is how NGINX enforces mTLS under **TLS 1.3**: the
#             client certificate arrives post-handshake, so `CONNECTION
#             ESTABLISHED` is printed and NGINX then answers 400 Bad Request
#             with $ssl_client_verify = NONE. Asserting a handshake failure
#             here would be wrong, and the probe would report a false negative
#             forever while mTLS was in fact working.
ASSERT_HANDSHAKE = "handshake"
ASSERT_HTTP_STATUS = "http_status"

_HTTP_REQUEST = (
    "GET /dataplane/echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)


@dataclass(frozen=True)
class ProbeSpec:
    """One enforcement assertion and the client flags that test it."""

    probe_type: str
    expected: str            # OUTCOME_CONNECT or OUTCOME_REJECT
    description: str
    args: List[str]
    use_valid_ca: bool = True
    requires_mtls_endpoint: bool = False
    assertion: str = ASSERT_HANDSHAKE
    # Statuses that count as a refusal at the HTTP layer. 400 is what NGINX
    # returns when a required client certificate is absent.
    reject_statuses: tuple = (400, 401, 403, 495, 496, 497)


PROBE_SPECS: Dict[str, ProbeSpec] = {
    POSITIVE_HYBRID: ProbeSpec(
        POSITIVE_HYBRID, OUTCOME_CONNECT,
        "Hybrid X25519MLKEM768 client completes a TLS 1.3 handshake",
        ["-tls1_3", "-groups", "X25519MLKEM768"],
    ),
    NEGATIVE_X25519: ProbeSpec(
        NEGATIVE_X25519, OUTCOME_REJECT,
        "Classical X25519-only client is refused - the mandatory fail-closed proof",
        ["-tls1_3", "-groups", "X25519"],
    ),
    NEGATIVE_PRIME256V1: ProbeSpec(
        NEGATIVE_PRIME256V1, OUTCOME_REJECT,
        "Classical prime256v1-only client is refused",
        ["-tls1_3", "-groups", "prime256v1"],
    ),
    NEGATIVE_TLS12: ProbeSpec(
        NEGATIVE_TLS12, OUTCOME_REJECT,
        "TLS 1.2 client is refused",
        ["-tls1_2"],
    ),
    NEGATIVE_AES128: ProbeSpec(
        NEGATIVE_AES128, OUTCOME_REJECT,
        "AES-128-GCM-only client is refused",
        ["-tls1_3", "-groups", "X25519MLKEM768",
         "-ciphersuites", "TLS_AES_128_GCM_SHA256"],
    ),
    NEGATIVE_INVALID_CA: ProbeSpec(
        NEGATIVE_INVALID_CA, OUTCOME_REJECT,
        "Certificate verification fails against an unrelated CA bundle",
        ["-tls1_3", "-groups", "X25519MLKEM768", "-verify_return_error"],
        use_valid_ca=False,
    ),
    NEGATIVE_MISSING_CLIENT_CERT: ProbeSpec(
        NEGATIVE_MISSING_CLIENT_CERT, OUTCOME_REJECT,
        "Client presenting no certificate is refused (HTTP 400) when mTLS is enabled",
        ["-tls1_3", "-groups", "X25519MLKEM768"],
        requires_mtls_endpoint=True,
        assertion=ASSERT_HTTP_STATUS,
    ),
}

# A CA bundle that certainly did not sign our development certificate.
_UNRELATED_CA = "/etc/ssl/certs/ca-certificates.crt"


@dataclass
class ProbeResult:
    """The outcome of one handshake attempt, with everything needed to audit it."""

    probe_type: str
    expected_outcome: str
    actual_outcome: str
    passed: bool
    description: str

    target_host: str
    target_port: int
    negotiated_group: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    tls_protocol: Optional[str] = None
    verify_result: Optional[str] = None
    http_status: Optional[int] = None

    openssl_binary: str = ""
    openssl_version: Optional[str] = None
    command: str = ""
    exit_code: Optional[int] = None
    stdout_excerpt: Optional[str] = None
    evidence_path: Optional[str] = None
    duration_ms: Optional[float] = None
    run_at: datetime = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["run_at"] = self.run_at.isoformat() if self.run_at else None
        return data


class TlsProber:
    """Runs enforcement probes with the runtime OpenSSL client."""

    def __init__(self, settings: Optional[TlsSettings] = None):
        self.settings = settings or get_tls_settings()

    # ── Public API ────────────────────────────────────────────────────────────

    def available(self) -> bool:
        return os.path.isfile(self.settings.openssl_bin)

    def run(self, probe_type: str, *, port: Optional[int] = None,
            timeout: int = 20) -> ProbeResult:
        """Run one probe. Never raises for a failed handshake — that is the data."""
        spec = PROBE_SPECS.get(probe_type)
        if spec is None:
            raise ValueError(f"unknown probe type: {probe_type}")
        return self._execute(spec, port=port, timeout=timeout)

    def run_standard_suite(self, *, timeout: int = 20) -> List[ProbeResult]:
        """
        Every probe that runs against the main endpoint.

        Excludes the mTLS probe, which needs a second endpoint configured with
        `ssl_verify_client on` — see run_mtls_probe().
        """
        return [
            self._execute(spec, timeout=timeout)
            for spec in PROBE_SPECS.values()
            if not spec.requires_mtls_endpoint
        ]

    def run_mtls_probe(self, *, port: int = 8444, timeout: int = 20) -> ProbeResult:
        """
        Prove that mTLS rejects a client with no certificate.

        mTLS is off on the main endpoint, so this starts a temporary NGINX
        instance with `ssl_verify_client on` on its own port, probes it, and
        stops it. Doing it this way keeps the production endpoint untouched and
        makes the test independent of how the main endpoint happens to be
        configured today.
        """
        from .service import NginxTlsService   # local import avoids a cycle

        spec = PROBE_SPECS[NEGATIVE_MISSING_CLIENT_CERT]
        runtime = self.settings.runtime_dir
        conf_path = os.path.join(runtime, "conf", "nginx-mtls.conf")
        pid_path = os.path.join(runtime, "run", "nginx-mtls.pid")
        log_path = os.path.join(runtime, "logs", "access-mtls.json.log")

        service = NginxTlsService(self.settings)
        overrides = dict(port=port, mtls=True, pid_file=pid_path,
                         access_log=log_path, config_path=conf_path)

        text = _render_to(service, conf_path, overrides)
        if text is None:
            return self._failed_result(spec, port, "could not render the mTLS config")

        ok, output = service.validate_config(conf_path)
        if not ok:
            return self._failed_result(spec, port, f"nginx -t rejected the mTLS config: {output}")

        started = subprocess.run(
            [self.settings.nginx_bin, "-c", conf_path],
            capture_output=True, text=True, timeout=30,
        )
        if started.returncode != 0:
            return self._failed_result(spec, port,
                                       f"mTLS instance failed to start: {started.stderr.strip()}")
        try:
            _wait_for_port(self.settings.host, port, timeout=10)
            return self._execute(spec, port=port, timeout=timeout)
        finally:
            subprocess.run([self.settings.nginx_bin, "-s", "quit", "-c", conf_path],
                           capture_output=True, text=True, timeout=30)
            _wait_for_port_release(self.settings.host, port, timeout=10)

    def probe_mtls_accepts_valid_client(self, *, port: int = 8444,
                                        timeout: int = 20) -> ProbeResult:
        """
        Counterpart to run_mtls_probe: with a valid client certificate the same
        endpoint must accept. Without this, "mTLS rejects" could equally mean
        "the endpoint is simply broken".
        """
        spec = ProbeSpec(
            POSITIVE_HYBRID, OUTCOME_CONNECT,
            "Client presenting a CA-signed certificate is accepted under mTLS",
            ["-tls1_3", "-groups", "X25519MLKEM768",
             "-cert", self.settings.client_cert, "-key", self.settings.client_key],
            assertion=ASSERT_HTTP_STATUS,
        )
        return self._execute(spec, port=port, timeout=timeout)

    # ── Signature algorithms, for the ML-DSA follow-up ────────────────────────

    def signature_algorithms(self) -> Dict[str, Any]:
        """
        What the runtime advertises for certificate authentication.

        Reported so the ML-DSA research profile can start from evidence. Nothing
        here enables or claims post-quantum authentication: that requires a real
        ML-DSA certificate that NGINX loads and a client verifies.
        """
        output = _run([self.settings.openssl_bin, "list", "-signature-algorithms"])
        text = output.stdout if output else ""
        names = [n.strip() for n in re.split(r"[:\s,]+", text) if n.strip()]
        mldsa = [n for n in names if "mldsa" in n.lower() or "ml-dsa" in n.lower()]
        return {
            "openssl_binary": self.settings.openssl_bin,
            "total_advertised": len(names),
            "ml_dsa_advertised": mldsa,
            "ml_dsa_available": bool(mldsa),
            "note": (
                "Advertised by the runtime only. Post-quantum authentication is "
                "NOT claimed until an ML-DSA certificate is generated, loaded by "
                "NGINX, and verified by a client."
            ),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _execute(self, spec: ProbeSpec, *, port: Optional[int] = None,
                 timeout: int = 20) -> ProbeResult:
        s = self.settings
        target_port = port or s.port
        ca = s.ca_cert if spec.use_valid_ca else _UNRELATED_CA

        http_mode = spec.assertion == ASSERT_HTTP_STATUS
        command = [
            s.openssl_bin, "s_client",
            "-connect", f"{s.host}:{target_port}",
            "-servername", s.server_hostname,
            "-CAfile", ca,
            # -quiet keeps the response body readable when we need the HTTP
            # status; -brief prints the handshake summary we parse otherwise.
            "-quiet" if http_mode else "-brief",
            *spec.args,
        ]

        started = time.perf_counter()
        result = _run(command, input_text=_HTTP_REQUEST if http_mode else "",
                      timeout=timeout)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        now = datetime.now(timezone.utc)

        if result is None:
            return ProbeResult(
                probe_type=spec.probe_type, expected_outcome=spec.expected,
                actual_outcome=OUTCOME_ERROR, passed=False,
                description=spec.description,
                target_host=s.host, target_port=target_port,
                openssl_binary=s.openssl_bin, command=" ".join(command),
                stdout_excerpt=f"could not execute {s.openssl_bin}",
                duration_ms=duration_ms, run_at=now,
            )

        output = (result.stdout or "") + (result.stderr or "")

        group = _search(_NEGOTIATED_GROUP, output, "group")
        cipher = _search(_CIPHERSUITE, output, "cipher")
        protocol = _search(_PROTOCOL, output, "proto")
        verification = _search(_VERIFICATION, output, "result")
        http_status = _http_status(output)

        if http_mode:
            # The handshake is expected to succeed here; the refusal is the HTTP
            # response. No status at all means we never got a reply, which is
            # also a refusal.
            if http_status is None:
                actual = OUTCOME_REJECT
            elif http_status in spec.reject_statuses:
                actual = OUTCOME_REJECT
            else:
                actual = OUTCOME_CONNECT
        else:
            connected = result.returncode == 0 and "CONNECTION ESTABLISHED" in output
            actual = OUTCOME_CONNECT if connected else OUTCOME_REJECT

            # An invalid-CA probe can still reach CONNECTION ESTABLISHED, so read
            # the verification line rather than the exit code alone.
            if spec.probe_type == NEGATIVE_INVALID_CA and verification:
                if "ok" not in verification.lower():
                    actual = OUTCOME_REJECT

        passed = actual == spec.expected

        evidence_path = self._write_evidence(spec, command, output, now)

        level = logger.info if passed else logger.warning
        level("Probe %s: expected %s, got %s (%s)",
              spec.probe_type, spec.expected, actual, "PASS" if passed else "FAIL")

        return ProbeResult(
            probe_type=spec.probe_type, expected_outcome=spec.expected,
            actual_outcome=actual, passed=passed, description=spec.description,
            target_host=s.host, target_port=target_port,
            negotiated_group=group, negotiated_cipher=cipher,
            tls_protocol=protocol, verify_result=verification,
            http_status=http_status,
            openssl_binary=s.openssl_bin,
            openssl_version=_openssl_version(s.openssl_bin),
            command=" ".join(command), exit_code=result.returncode,
            stdout_excerpt=output.strip()[:2000],
            evidence_path=evidence_path, duration_ms=duration_ms, run_at=now,
        )

    def _failed_result(self, spec: ProbeSpec, port: int, message: str) -> ProbeResult:
        logger.error("Probe %s could not run: %s", spec.probe_type, message)
        return ProbeResult(
            probe_type=spec.probe_type, expected_outcome=spec.expected,
            actual_outcome=OUTCOME_ERROR, passed=False, description=spec.description,
            target_host=self.settings.host, target_port=port,
            openssl_binary=self.settings.openssl_bin, command="",
            stdout_excerpt=message, run_at=datetime.now(timezone.utc),
        )

    def _write_evidence(self, spec: ProbeSpec, command: List[str],
                        output: str, when: datetime) -> Optional[str]:
        """Persist the transcript so a claim can be audited after the fact."""
        try:
            os.makedirs(self.settings.evidence_dir, exist_ok=True)
            stamp = when.strftime("%Y%m%dT%H%M%SZ")
            path = os.path.join(self.settings.evidence_dir,
                                f"probe-{spec.probe_type}-{stamp}.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(f"# QUANSEQ TLS enforcement probe\n")
                handle.write(f"# probe      : {spec.probe_type}\n")
                handle.write(f"# assertion  : {spec.description}\n")
                handle.write(f"# expected   : {spec.expected}\n")
                handle.write(f"# run at     : {when.isoformat()}\n")
                handle.write(f"# command    : {' '.join(command)}\n")
                handle.write("#" + "-" * 70 + "\n")
                handle.write(output)
            return path
        except OSError as exc:
            logger.warning("Could not write probe evidence: %s", exc)
            return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _run(command: List[str], *, input_text: Optional[str] = None,
         timeout: int = 20) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(command, input=input_text, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", f"timed out after {timeout}s")
    except (OSError, subprocess.SubprocessError):
        return None


def _http_status(text: str) -> Optional[int]:
    """First HTTP status line in the response, or None if there was no reply."""
    match = re.search(r"^HTTP/\d\.\d\s+(\d{3})", text or "", re.MULTILINE)
    return int(match.group(1)) if match else None


def _search(pattern: re.Pattern, text: str, group: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(group).strip() if match else None


def _openssl_version(binary: str) -> Optional[str]:
    result = _run([binary, "version"], timeout=10)
    return result.stdout.strip() if result and result.stdout else None


def _render_to(service, path: str, overrides: Dict[str, Any]) -> Optional[str]:
    """Render a config to an explicit path (used for the temporary mTLS instance)."""
    from .service import render_config
    try:
        service.ensure_layout()
        text = render_config(
            service.settings,
            port=overrides["port"], mtls=overrides["mtls"],
            access_log=overrides["access_log"], pid_file=overrides["pid_file"],
        )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return text
    except (OSError, KeyError):
        return None


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _wait_for_port_release(host: str, port: int, timeout: float = 10.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                time.sleep(0.1)
        except OSError:
            return True
    return False


def get_prober() -> TlsProber:
    return TlsProber()
