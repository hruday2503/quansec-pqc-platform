"""
protocols/tls/service.py — the NGINX TLS data plane.

QUANSEQ's relationship to NGINX here is the same as its relationship to
StrongSwan and sshd: it renders the configuration, manages the process, and
reads back what actually happened. NGINX does the enforcing.

The configuration this renders is **fail-closed**. `ssl_conf_command Groups`
lists exactly one group, so a client that cannot do X25519MLKEM768 is refused
during the handshake rather than quietly downgraded. There is no classical
fallback group, by design — adding one would make every "enforced" claim on the
dashboard false.

Status is computed in `evaluate_status()` from evidence passed in by the caller:
observed sessions from the NGINX log, and probe results from real handshake
attempts. Nothing in this module infers a post-quantum property from
configuration alone.
"""

import hashlib
import logging
import os
import re
import signal
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .settings import TlsSettings, get_tls_settings

logger = logging.getLogger("quanseq.tls.service")

# ── Overall status values ────────────────────────────────────────────────────
STATUS_UNAVAILABLE = "unavailable"          # runtime not built / NGINX not running
STATUS_CLASSICAL = "classical"              # no hybrid group configured
STATUS_CONFIGURED_UNPROVEN = "configured_unproven"   # configured, never observed
STATUS_HYBRID_OBSERVED = "hybrid_observed"  # observed, but downgrade not disproven
STATUS_HYBRID_ENFORCED = "hybrid_enforced"  # observed AND classical clients refused
STATUS_DEGRADED = "degraded"                # was enforced, a negative probe now connects

# The label the UI shows. Key establishment and certificate authentication are
# deliberately named separately: X25519MLKEM768 makes the key exchange hybrid
# post-quantum, but an RSA/ECDSA certificate leaves authentication classical.
LABEL_CLASSICAL_AUTH = "Hybrid post-quantum TLS with classical X.509 authentication"
LABEL_FULL_PQ = "Hybrid post-quantum TLS with post-quantum X.509 authentication"


@dataclass
class ProcessState:
    """What the NGINX process is doing right now."""

    running: bool
    pid: Optional[int] = None
    listening: bool = False
    config_path: Optional[str] = None
    config_sha256: Optional[str] = None
    error: Optional[str] = None


@dataclass
class TlsStatus:
    """
    The nine required status fields, each derived from named evidence.

    Read the docstring on every field below before trusting it. The distinction
    that matters most: `hybrid_group_configured` is what we asked NGINX to do,
    `hybrid_group_negotiated` is what a real handshake did, and
    `hybrid_only_enforced` is whether a classical client was actually refused.
    Only the third is a guarantee.
    """

    # Does the runtime OpenSSL provide the group at all?
    runtime_supported: bool
    # ssl_protocols is TLSv1.3-only AND a TLS 1.2 client was refused.
    tls13_enforced: bool
    # The running config lists the hybrid group. Says nothing about outcomes.
    hybrid_group_configured: bool
    # At least one real NGINX log line recorded the group as negotiated.
    hybrid_group_negotiated: bool
    # X25519-only AND prime256v1-only clients were both refused.
    hybrid_only_enforced: bool
    # A probe with the configured CA reported Verification: OK.
    certificate_verified: bool
    # ssl_verify_client is on in the running config.
    mtls_enabled: bool
    # The server certificate uses a post-quantum signature algorithm.
    authentication_quantum_safe: bool
    overall_status: str

    label: str = LABEL_CLASSICAL_AUTH
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Configuration rendering ──────────────────────────────────────────────────

# escape=json is required: without it a crafted request line could inject a
# quote and produce a log line the collector cannot parse. Numeric fields are
# left unquoted so they arrive as JSON numbers.
_LOG_FORMAT = """    log_format quanseq_tls escape=json
        '{'
        '"timestamp":"$time_iso8601",'
        '"connection_id":"$connection",'
        '"connection_requests":$connection_requests,'
        '"listener":"$server_port",'
        '"remote_addr":"$remote_addr",'
        '"remote_port":"$remote_port",'
        '"tls_protocol":"$ssl_protocol",'
        '"cipher":"$ssl_cipher",'
        '"negotiated_group":"$ssl_curve",'
        '"client_groups":"$ssl_curves",'
        '"client_verify":"$ssl_client_verify",'
        '"client_s_dn":"$ssl_client_s_dn",'
        '"server_name":"$ssl_server_name",'
        '"session_reused":"$ssl_session_reused",'
        '"request":"$request",'
        '"request_method":"$request_method",'
        '"request_uri":"$uri",'
        '"status":$status,'
        '"request_time":$request_time,'
        '"bytes_sent":$bytes_sent'
        '}';
"""

# $connection is NGINX's per-connection serial. Combined with
# $connection_requests it distinguishes "one connection, five requests" from
# "five connections", which is what the portal's session view needs and what a
# per-log-line surrogate key cannot express.
#
# There is no NGINX variable for the server certificate's signature algorithm:
# $ssl_ciphers and friends describe the negotiated suite, not how the
# certificate was signed. That fact comes from certs.py inspecting the
# certificate itself, and is joined in at the API layer — never guessed here.


def _render_portal_server(settings: TlsSettings) -> str:
    """
    The browser-facing listener.

    Serves the whole application over TLS 1.3 — Next.js at `/`, FastAPI under
    `/api/`, and the live-events socket with an Upgrade — so that end-to-end
    use of QUANSEQ genuinely passes through a TLS terminator rather than
    bypassing it on plaintext loopback ports.

    Its group list is deliberately WIDER than the strict listener's. The hybrid
    group is offered first and a browser that supports it will use it, but
    classical fallback is permitted because otherwise no browser could connect
    at all. That makes this listener NOT fail-closed, by construction:

      * it writes to its own access log, so its sessions are collected with
        evidence_source distinct from the strict listener's;
      * no probe runs against it, so it can never contribute to
        `hybrid_only_enforced`;
      * enforcement claims are derived only from port {settings.port}.

    Anyone reading a hybrid session on this listener is looking at what a
    browser chose, not at what the server required.
    """
    if not settings.portal_enabled:
        return ""

    return f"""
    # ── Portal listener — browser-facing, NOT the enforcement listener ───────
    server {{
        listen {settings.host}:{settings.portal_port} ssl;
        server_name {settings.server_hostname};

        access_log {settings.portal_access_log} quanseq_tls;

        ssl_certificate     {settings.server_cert};
        ssl_certificate_key {settings.server_key};

        ssl_protocols TLSv1.3;
        ssl_conf_command Groups {settings.portal_groups};
        ssl_conf_command Ciphersuites {settings.portal_ciphersuites};
        ssl_early_data off;
        ssl_session_tickets off;

        # Uploads are small; this is an API and a dashboard.
        client_max_body_size 2m;

        # The live-events socket. Matched BEFORE /api/ so the Upgrade headers
        # are set — a plain proxy_pass would strip them and the socket would
        # fall back to a hanging HTTP request.
        location /api/ws/ {{
            proxy_pass http://{settings.upstream};
            proxy_http_version 1.1;
            proxy_set_header Upgrade    $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host       $host;
            proxy_set_header X-Real-IP  $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            # Long-lived by design; the default 60s would drop idle sockets.
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
        }}

        location /api/ {{
            proxy_pass http://{settings.upstream};
            proxy_http_version 1.1;
            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            # Tells FastAPI the client leg was TLS, so Secure cookies are set
            # and redirects are https. Without it the app would see http.
            proxy_set_header X-Forwarded-Proto https;

            # What NGINX observed about THIS connection, for /dataplane/echo
            # and for any endpoint that wants to report the caller's own TLS
            # facts without trusting the caller.
            proxy_set_header X-QUANSEQ-TLS-Protocol   $ssl_protocol;
            proxy_set_header X-QUANSEQ-TLS-Cipher     $ssl_cipher;
            proxy_set_header X-QUANSEQ-TLS-Group      $ssl_curve;
            proxy_set_header X-QUANSEQ-TLS-Curves     $ssl_curves;
            proxy_set_header X-QUANSEQ-TLS-Verify     $ssl_client_verify;
            proxy_set_header X-QUANSEQ-TLS-ServerName $ssl_server_name;
            proxy_set_header X-QUANSEQ-TLS-Listener   portal;

            proxy_connect_timeout 5s;
            proxy_read_timeout 60s;
        }}

        # Next.js. Includes the dev server's HMR websocket, which is why the
        # Upgrade headers are set here too.
        location / {{
            proxy_pass http://{settings.ui_upstream};
            proxy_http_version 1.1;
            proxy_set_header Upgrade    $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host       $host;
            proxy_set_header X-Real-IP  $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_connect_timeout 5s;
            proxy_read_timeout 60s;
        }}
    }}
"""


def render_config(settings: TlsSettings, *,
                  port: Optional[int] = None,
                  mtls: Optional[bool] = None,
                  access_log: Optional[str] = None,
                  pid_file: Optional[str] = None,
                  error_log: Optional[str] = None,
                  protocols: Optional[str] = None,
                  groups: Optional[str] = None,
                  ciphersuites: Optional[str] = None,
                  include_portal: bool = True) -> str:
    """
    Render the NGINX configuration.

    Overrides exist so the mTLS negative test can start a second instance on a
    different port without disturbing the main one, and so a policy apply can
    render a candidate config for `nginx -t` before committing to it.

    `include_portal` is False for those throwaway instances: they must not bind
    the portal port out from under the running server.
    """
    port = port if port is not None else settings.port
    mtls = settings.mtls if mtls is None else mtls
    access_log = access_log or settings.access_log
    pid_file = pid_file or settings.pid_file
    error_log = error_log or settings.error_log
    protocols = protocols or settings.protocols
    groups = groups or settings.groups
    ciphersuites = ciphersuites or settings.ciphersuites

    runtime = settings.runtime_dir
    early_data = "on" if settings.early_data else "off"
    portal_block = _render_portal_server(settings) if include_portal else ""

    mtls_block = ""
    if mtls:
        mtls_block = f"""
        # Mutual TLS: a client certificate signed by our CA is required. A client
        # that presents none is rejected during the handshake.
        ssl_client_certificate {settings.ca_cert};
        ssl_verify_client on;
        ssl_verify_depth 2;
"""

    return f"""# QUANSEQ post-quantum TLS data plane — GENERATED FILE, DO NOT EDIT
#
# Rendered by protocols/tls/service.py. Any manual change is overwritten on the
# next policy apply, and the config_sha256 recorded in tls_policy_state would no
# longer match what QUANSEQ believes is running.
#
# Enforcement, in three directives, on the listener at port {port}:
#   ssl_protocols     {protocols}   — nothing below TLS 1.3 is accepted
#   Groups            {groups}      — exactly one group, no fallback
#   Ciphersuites      {ciphersuites}
#
# There is deliberately NO classical group in the list. A client offering only
# X25519 or prime256v1 fails the handshake. That refusal is what the enforcement
# probes verify, and it is the only thing that justifies an "enforced" status.
#
# The portal listener rendered below is a SEPARATE server block with a wider
# group list, because a browser cannot negotiate the strict policy. It is never
# probed and never contributes to an enforcement claim.

worker_processes 1;
daemon on;
pid {pid_file};
error_log {error_log} info;

events {{
    worker_connections 256;
}}

http {{
    default_type application/json;
    access_log off;

{_LOG_FORMAT}
    # Required by the portal listener's `/` block: maps the client's Upgrade
    # header to the value Connection must carry, so a normal request sends
    # `Connection: close` while a websocket sends `Connection: upgrade`.
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        ''      close;
    }}

    client_body_temp_path {runtime}/tmp/client_body;
    proxy_temp_path       {runtime}/tmp/proxy;
    fastcgi_temp_path     {runtime}/tmp/fastcgi;
    uwsgi_temp_path       {runtime}/tmp/uwsgi;
    scgi_temp_path        {runtime}/tmp/scgi;

    server {{
        listen {settings.host}:{port} ssl;
        server_name {settings.server_hostname};

        access_log {access_log} quanseq_tls;

        ssl_certificate     {settings.server_cert};
        ssl_certificate_key {settings.server_key};

        ssl_protocols {protocols};
        ssl_conf_command Groups {groups};
        ssl_conf_command Ciphersuites {ciphersuites};
        ssl_early_data {early_data};
        ssl_prefer_server_ciphers on;
        ssl_session_tickets off;
{mtls_block}
        # The ONLY thing exposed through the post-quantum endpoint. It proxies a
        # single QUANSEQ endpoint that echoes the TLS facts NGINX observed.
        location /dataplane/ {{
            proxy_pass http://{settings.upstream}/api/tls/dataplane/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-QUANSEQ-TLS-Protocol   $ssl_protocol;
            proxy_set_header X-QUANSEQ-TLS-Cipher     $ssl_cipher;
            proxy_set_header X-QUANSEQ-TLS-Group      $ssl_curve;
            proxy_set_header X-QUANSEQ-TLS-Curves     $ssl_curves;
            proxy_set_header X-QUANSEQ-TLS-Verify     $ssl_client_verify;
            proxy_set_header X-QUANSEQ-TLS-ServerName $ssl_server_name;
            proxy_connect_timeout 5s;
            proxy_read_timeout 10s;
        }}

        # Everything else is closed. THIS listener is a measurement surface, not
        # a general reverse proxy — the portal listener below is the front door.
        location / {{
            return 404 '{{"error":"not found","hint":"only /dataplane/ is served on the strict listener"}}';
        }}
    }}
{portal_block}}}
"""


def config_digest(text: str) -> str:
    """SHA-256 of a rendered config, used to detect drift from what is running."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── The service ──────────────────────────────────────────────────────────────

class NginxTlsService:
    """Lifecycle and status for the NGINX post-quantum TLS data plane."""

    def __init__(self, settings: Optional[TlsSettings] = None):
        self.settings = settings or get_tls_settings()

    # ── Filesystem ────────────────────────────────────────────────────────────

    def ensure_layout(self) -> None:
        """Create the runtime directories NGINX needs before it will start."""
        s = self.settings
        for path in (
            os.path.dirname(s.nginx_conf), os.path.dirname(s.access_log),
            os.path.dirname(s.pid_file), s.evidence_dir,
            os.path.join(s.runtime_dir, "tmp"),
        ):
            os.makedirs(path, exist_ok=True)

    def write_config(self, **overrides) -> str:
        """Render and write nginx.conf. Returns the SHA-256 of what was written."""
        self.ensure_layout()
        text = render_config(self.settings, **overrides)
        path = overrides.get("config_path") or self.settings.nginx_conf
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        digest = config_digest(text)
        logger.info("Rendered NGINX config to %s (sha256 %s)", path, digest[:16])
        return digest

    def current_config_digest(self) -> Optional[str]:
        """SHA-256 of the config file currently on disk, or None if absent."""
        try:
            with open(self.settings.nginx_conf, "r", encoding="utf-8") as handle:
                return config_digest(handle.read())
        except OSError:
            return None

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_config(self, config_path: Optional[str] = None) -> tuple[bool, str]:
        """
        Run `nginx -t`. Returns (ok, output).

        Always called before start or reload: applying a policy that NGINX would
        reject must fail loudly rather than take the data plane down.
        """
        path = config_path or self.settings.nginx_conf
        result = self._nginx(["-t", "-c", path])
        if result is None:
            return False, f"could not execute {self.settings.nginx_bin}"
        ok = result.returncode == 0
        output = (result.stdout or "") + (result.stderr or "")
        if not ok:
            logger.error("nginx -t rejected %s: %s", path, output.strip())
        return ok, output.strip()

    # ── Process ───────────────────────────────────────────────────────────────

    def read_pid(self) -> Optional[int]:
        try:
            with open(self.settings.pid_file, "r", encoding="utf-8") as handle:
                return int(handle.read().strip())
        except (OSError, ValueError):
            return None

    def is_running(self) -> bool:
        pid = self.read_pid()
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def is_listening(self, port: Optional[int] = None, timeout: float = 1.0) -> bool:
        """TCP-level check that something is accepting on the endpoint."""
        try:
            with socket.create_connection(
                (self.settings.host, port or self.settings.port), timeout=timeout
            ):
                return True
        except OSError:
            return False

    def process_state(self) -> ProcessState:
        return ProcessState(
            running=self.is_running(),
            pid=self.read_pid(),
            listening=self.is_listening(),
            config_path=self.settings.nginx_conf,
            config_sha256=self.current_config_digest(),
        )

    def start(self, *, wait: float = 10.0, **overrides) -> ProcessState:
        """
        Render, validate, then start NGINX. Refuses to start an invalid config.
        """
        if self.is_running():
            logger.info("NGINX already running (pid %s)", self.read_pid())
            return self.process_state()

        digest = self.write_config(**overrides)
        ok, output = self.validate_config()
        if not ok:
            return ProcessState(running=False, config_sha256=digest,
                                config_path=self.settings.nginx_conf,
                                error=f"nginx -t failed: {output}")

        result = self._nginx(["-c", self.settings.nginx_conf])
        if result is None or result.returncode != 0:
            detail = (result.stderr.strip() if result else
                      f"could not execute {self.settings.nginx_bin}")
            return ProcessState(running=False, config_sha256=digest,
                                config_path=self.settings.nginx_conf,
                                error=f"nginx failed to start: {detail}")

        port = overrides.get("port") or self.settings.port
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if self.is_listening(port):
                logger.info("NGINX TLS data plane listening on %s:%s (pid %s)",
                            self.settings.host, port, self.read_pid())
                return self.process_state()
            time.sleep(0.1)

        return ProcessState(running=self.is_running(), pid=self.read_pid(),
                            config_sha256=digest, config_path=self.settings.nginx_conf,
                            error=f"started but not listening on {port} within {wait}s")

    def stop(self, *, wait: float = 10.0) -> bool:
        """
        Graceful shutdown, then wait for the listening socket to be released.

        Returning only once the port is free is what makes restart and
        port-reuse deterministic instead of racy.
        """
        pid = self.read_pid()
        if pid is None:
            logger.info("NGINX not running (no pid file)")
            return True

        result = self._nginx(["-s", "quit", "-c", self.settings.nginx_conf])
        if result is None or result.returncode != 0:
            try:
                os.kill(pid, signal.SIGQUIT)
            except OSError:
                pass

        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if not self.is_running() and not self.is_listening(timeout=0.2):
                logger.info("NGINX stopped and port %s released", self.settings.port)
                try:
                    os.remove(self.settings.pid_file)
                except OSError:
                    pass
                return True
            time.sleep(0.1)

        logger.warning("NGINX did not stop within %.1fs (pid %s)", wait, pid)
        return False

    def reload(self) -> tuple[bool, str]:
        """Validate then `nginx -s reload`. Existing connections drain."""
        ok, output = self.validate_config()
        if not ok:
            return False, output
        result = self._nginx(["-s", "reload", "-c", self.settings.nginx_conf])
        if result is None or result.returncode != 0:
            return False, (result.stderr.strip() if result else "could not execute nginx")
        return True, "reloaded"

    def _nginx(self, args: List[str]) -> Optional[subprocess.CompletedProcess]:
        try:
            return subprocess.run(
                [self.settings.nginx_bin, *args],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.error("nginx %s failed: %s", " ".join(args), exc)
            return None

    # ── Build provenance ──────────────────────────────────────────────────────

    def build_info(self) -> Dict[str, Any]:
        """
        What the data plane is actually made of.

        `nginx_openssl` is the load-bearing value: NGINX built against OpenSSL
        3.0 cannot enforce X25519MLKEM768 whatever the config says. The system
        OpenSSL is reported alongside so the two are never confused.
        """
        s = self.settings
        return {
            "runtime_dir": s.runtime_dir,
            "nginx_binary": s.nginx_bin,
            "nginx_version": _first_version(s.nginx_version_line()),
            "nginx_openssl": s.nginx_linked_openssl(),
            "openssl_binary": s.openssl_bin,
            "openssl_version": (s.openssl_version() or "").strip() or None,
            "system_openssl": (s.system_openssl_version() or "").strip() or None,
            "hybrid_group_available": s.runtime_lists_group(),
            "runtime_built": s.runtime_available(),
        }

    # ── Status ────────────────────────────────────────────────────────────────

    def evaluate_status(self, *,
                        observed_group_count: int = 0,
                        probe_results: Optional[Dict[str, bool]] = None,
                        certificate_pqc: bool = False,
                        was_enforced: bool = False) -> TlsStatus:
        """
        Derive the nine status fields.

        Args:
            observed_group_count: rows in tls_sessions whose negotiated_group is
                the hybrid group. Comes from real NGINX log lines.
            probe_results: probe_type -> passed, from tls_probe_results. A
                negative probe "passes" when the handshake was refused.
            certificate_pqc: server certificate uses a PQ signature algorithm.
            was_enforced: enforcement was previously proven, used to distinguish
                "never proven" from "regressed".

        Every field defaults to False. Absence of evidence is never treated as
        evidence of enforcement.
        """
        s = self.settings
        probes = probe_results or {}

        runtime_supported = s.runtime_available() and s.runtime_lists_group()

        config = self._running_policy()
        configured_groups = config.get("groups", "")
        hybrid_group_configured = (
            configured_groups.strip().lower() == s.hybrid_group.lower()
        )
        protocols_tls13_only = config.get("protocols", "").strip() == "TLSv1.3"

        # TLS 1.3 enforcement needs both the directive AND a refused 1.2 client.
        tls13_enforced = protocols_tls13_only and probes.get("negative_tls12", False)

        hybrid_group_negotiated = observed_group_count > 0

        # Both classical groups must have been refused. One is not enough:
        # NGINX could have been configured to allow prime256v1 but not X25519.
        hybrid_only_enforced = (
            probes.get("negative_x25519", False)
            and probes.get("negative_prime256v1", False)
        )

        certificate_verified = probes.get("positive_hybrid", False)
        mtls_enabled = config.get("mtls", False)

        overall = self._overall(
            runtime_built=s.runtime_available(),
            running=self.is_running(),
            hybrid_group_configured=hybrid_group_configured,
            hybrid_group_negotiated=hybrid_group_negotiated,
            hybrid_only_enforced=hybrid_only_enforced,
            was_enforced=was_enforced,
        )

        return TlsStatus(
            runtime_supported=runtime_supported,
            tls13_enforced=tls13_enforced,
            hybrid_group_configured=hybrid_group_configured,
            hybrid_group_negotiated=hybrid_group_negotiated,
            hybrid_only_enforced=hybrid_only_enforced,
            certificate_verified=certificate_verified,
            mtls_enabled=mtls_enabled,
            authentication_quantum_safe=certificate_pqc,
            overall_status=overall,
            label=LABEL_FULL_PQ if certificate_pqc else LABEL_CLASSICAL_AUTH,
            evidence={
                "observed_hybrid_sessions": observed_group_count,
                "probe_results": probes,
                "configured_groups": configured_groups,
                "configured_protocols": config.get("protocols"),
                "configured_ciphersuites": config.get("ciphersuites"),
                "config_sha256": self.current_config_digest(),
                "build": self.build_info(),
            },
        )

    @staticmethod
    def _overall(*, runtime_built: bool, running: bool,
                 hybrid_group_configured: bool, hybrid_group_negotiated: bool,
                 hybrid_only_enforced: bool, was_enforced: bool) -> str:
        if not runtime_built or not running:
            return STATUS_UNAVAILABLE
        if not hybrid_group_configured:
            return STATUS_CLASSICAL
        if hybrid_only_enforced and hybrid_group_negotiated:
            return STATUS_HYBRID_ENFORCED
        if was_enforced and not hybrid_only_enforced:
            # A classical client that used to be refused now connects.
            return STATUS_DEGRADED
        if hybrid_group_negotiated:
            return STATUS_HYBRID_OBSERVED
        return STATUS_CONFIGURED_UNPROVEN

    def _running_policy(self) -> Dict[str, Any]:
        """
        Parse the policy back out of the config file on disk.

        Reading the file rather than trusting settings means a hand-edited or
        stale config shows up as what it is, instead of being reported as the
        policy QUANSEQ intended.
        """
        try:
            with open(self.settings.nginx_conf, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            return {}

        def directive(pattern: str) -> str:
            match = re.search(pattern, text, re.MULTILINE)
            return match.group(1).strip() if match else ""

        return {
            "protocols": directive(r"^\s*ssl_protocols\s+([^;]+);"),
            "groups": directive(r"^\s*ssl_conf_command\s+Groups\s+([^;]+);"),
            "ciphersuites": directive(r"^\s*ssl_conf_command\s+Ciphersuites\s+([^;]+);"),
            "early_data": directive(r"^\s*ssl_early_data\s+([^;]+);") == "on",
            "mtls": directive(r"^\s*ssl_verify_client\s+([^;]+);") == "on",
            "listen": directive(r"^\s*listen\s+([^;]+);"),
        }


def _first_version(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    match = re.search(r"nginx/(\S+)", text)
    return match.group(1) if match else text.strip() or None


def get_service() -> NginxTlsService:
    """A service bound to the current environment settings."""
    return NginxTlsService()
