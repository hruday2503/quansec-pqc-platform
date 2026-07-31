"""
protocols/tls/models.py — request and response schemas for the TLS API.

Field names mirror what NGINX and OpenSSL actually report. Where a value cannot
be observed it is Optional and left None, never defaulted to something that
reads as a measurement — a `negotiated_group` of None means "NGINX did not
report one", which is not the same as "classical" and is certainly not evidence
of a hybrid exchange.

The status model is the important one. Its nine booleans are deliberately
separate rather than reduced to a single "secure" flag, because they answer
different questions and only some of them are guarantees. See TlsStatusResponse.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Requests ─────────────────────────────────────────────────────────────────

class ProbeRequest(BaseModel):
    """Body for POST /api/tls/probe."""

    probe_type: Optional[str] = Field(
        default=None,
        description="Single probe to run. Omit to run the whole standard suite.",
    )
    include_mtls: bool = Field(
        default=False,
        description="Also run the mTLS probe, which starts a temporary NGINX "
                    "instance on a second port with ssl_verify_client on.",
    )


class PolicyApplyRequest(BaseModel):
    """Body for POST /api/tls/policy/apply."""

    reload: bool = Field(
        default=True,
        description="Reload NGINX after validating. False writes and validates "
                    "the config without disturbing the running service.",
    )


# ── Status ───────────────────────────────────────────────────────────────────

class TlsStatusResponse(BaseModel):
    """
    The nine evidence-derived status fields.

    Read these three together, in order — they are not interchangeable:

      hybrid_group_configured   we asked NGINX for the hybrid group
      hybrid_group_negotiated   a real handshake used it, per the NGINX log
      hybrid_only_enforced      classical clients were actually refused

    Only the third is a guarantee. The first is an intention; the second proves
    the server *can* do hybrid, not that it *must*. A UI that renders the first
    as "protected" is making a claim the evidence does not support.
    """

    enabled: bool
    runtime_supported: bool = Field(
        description="The runtime OpenSSL lists the hybrid group in `list -tls-groups`"
    )
    tls13_enforced: bool = Field(
        description="ssl_protocols is TLSv1.3-only AND a TLS 1.2 client was refused"
    )
    hybrid_group_configured: bool = Field(
        description="The running config lists the hybrid group. An intention, not an outcome."
    )
    hybrid_group_negotiated: bool = Field(
        description="At least one real NGINX log line recorded the group as negotiated"
    )
    hybrid_only_enforced: bool = Field(
        description="X25519-only AND prime256v1-only clients were both refused"
    )
    certificate_verified: bool = Field(
        description="A probe using the configured CA reported Verification: OK"
    )
    mtls_enabled: bool
    authentication_quantum_safe: bool = Field(
        description="The server certificate uses a post-quantum signature "
                    "algorithm. False with an RSA or ECDSA certificate, "
                    "regardless of the key exchange."
    )
    overall_status: str = Field(
        description="unavailable | classical | configured_unproven | "
                    "hybrid_observed | hybrid_enforced | degraded"
    )
    label: str = Field(
        description="What may honestly be claimed, naming key establishment and "
                    "certificate authentication separately"
    )

    service: Dict[str, Any]
    build: Dict[str, Any]
    evidence: Dict[str, Any]
    last_updated: datetime


class TlsReadinessResponse(BaseModel):
    """
    Whether the data plane can be relied on right now, and what is missing.

    Distinct from /status: readiness is about the runtime being present and
    correct, status is about what it has been observed doing.
    """

    ready: bool
    checks: List[Dict[str, Any]]
    blocking: List[str]
    warnings: List[str]
    runtime: Dict[str, Any]


# ── Aggregates ───────────────────────────────────────────────────────────────

class TlsStatsResponse(BaseModel):
    """
    Counts and percentiles over the sessions the collector has recorded.

    Aggregates of observations, not of intent. `pqc_coverage` is the share of
    observed sessions that negotiated the hybrid group; it says nothing about
    whether a classical client would have been refused — only
    /status.hybrid_only_enforced answers that.

    With an empty table every count is 0, both percentiles are null and
    `outcomes` is empty. That is the honest empty state, not missing data.
    """

    total_observations: int
    successful: int = Field(description="Observations logged with HTTP status < 400")
    failed: int = Field(description="Observations logged with HTTP status >= 400")
    unrecorded: int = Field(
        description="Observations with no HTTP status in the log line. Not counted "
                    "as failures, because the log does not record one."
    )
    sessions_reused: int = Field(
        description="Resumed sessions. These perform no key exchange, so they "
                    "carry no negotiated group."
    )
    pqc_observations: int
    pqc_coverage: float = Field(
        description="pqc_observations / total_observations, as a percentage"
    )
    request_time_ms_p50: Optional[float] = Field(
        default=None,
        description="Median NGINX $request_time in ms — the whole request, "
                    "handshake included. Not a handshake timing.",
    )
    request_time_ms_p95: Optional[float] = Field(
        default=None, description="95th percentile NGINX $request_time in ms"
    )
    outcomes: Dict[str, int] = Field(
        default_factory=dict,
        description="Non-zero outcome buckets: success, client_error, "
                    "server_error, unrecorded",
    )


# ── Sessions ─────────────────────────────────────────────────────────────────

class TlsSessionResponse(BaseModel):
    """
    One observed TLS session, from a line NGINX wrote.

    `log_source` and `log_offset` are carried through so any row can be traced
    back to the exact byte range of the log it came from.
    """

    id: int
    occurred_at: datetime
    remote_addr: Optional[str] = None
    remote_port: Optional[str] = None
    tls_protocol: Optional[str] = None
    cipher: Optional[str] = None
    negotiated_group: Optional[str] = None
    client_groups: Optional[str] = None
    client_verify: Optional[str] = None
    client_s_dn: Optional[str] = None
    server_name: Optional[str] = None
    session_reused: bool = False
    http_status: Optional[int] = None
    request_time: Optional[float] = None
    bytes_sent: Optional[int] = None
    request_line: Optional[str] = None
    pqc_enabled: bool = False
    kem_label: Optional[str] = None
    log_source: Optional[str] = None
    log_offset: Optional[int] = None
    recorded_at: Optional[datetime] = None


class TlsSessionDetailResponse(TlsSessionResponse):
    """A single session, including the raw log line it was parsed from."""

    raw_line: Optional[str] = None


# ── Policy ───────────────────────────────────────────────────────────────────

class TlsPolicyResponse(BaseModel):
    """
    The intended policy, the running policy, and the drift between them.

    `running` is None when no nginx.conf has been rendered yet — a different
    state from "running something unexpected", and reported as such.
    """

    intended: Dict[str, Any]
    running: Optional[Dict[str, Any]] = None
    drift: Dict[str, Any]
    active_state: Optional[Dict[str, Any]] = None
    fail_closed: bool = Field(
        description="Exactly one group configured, and TLS 1.3 only. False means "
                    "a classical key exchange is still reachable."
    )


# ── Probes ───────────────────────────────────────────────────────────────────

class ProbeResultResponse(BaseModel):
    """
    One enforcement probe.

    `passed` is relative to `expected_outcome`: a negative probe passes when the
    handshake is REFUSED. A reader who assumes passed == connected will read
    every enforcement result backwards.
    """

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
    openssl_binary: str
    openssl_version: Optional[str] = None
    command: str
    exit_code: Optional[int] = None
    stdout_excerpt: Optional[str] = None
    evidence_path: Optional[str] = None
    duration_ms: Optional[float] = None
    run_at: Optional[datetime] = None


class ProbeSuiteResponse(BaseModel):
    """A probe run, with the verdict it supports."""

    total: int
    passed: int
    failed: int
    results: List[ProbeResultResponse]
    enforcement_proven: bool = Field(
        description="Both the X25519-only and prime256v1-only probes were "
                    "refused. This is the mandatory fail-closed proof."
    )
    summary: str


class DowngradeTestResponse(BaseModel):
    """
    A named downgrade test.

    `rejected` is the security-relevant field: True means the downgrade attempt
    failed, which is the desired outcome.
    """

    test: str
    rejected: bool
    description: str
    results: List[ProbeResultResponse]
    verdict: str


# ── Certificate ──────────────────────────────────────────────────────────────

class TlsCertificateResponse(BaseModel):
    """
    Server certificate facts.

    Key establishment and certificate authentication are reported on separate
    axes throughout. `pqc_signature` refers ONLY to the certificate's signature
    algorithm and is false for RSA and ECDSA no matter what the key exchange
    negotiated — hybrid TLS does not make a classical certificate
    post-quantum.
    """

    server_name: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    san: List[str] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    chain_verified: bool = False
    pqc_signature: bool = False
    authentication_class: str = Field(
        description="'classical X.509' or 'post-quantum X.509'"
    )
    note: str


class SignatureAlgorithmsResponse(BaseModel):
    """
    What the runtime OpenSSL advertises for certificate authentication.

    Reporting only. Advertising ML-DSA does not mean the platform uses it: that
    needs a generated certificate, NGINX loading it, and a client verifying the
    handshake. Until then `authentication_quantum_safe` stays false.
    """

    openssl_binary: str
    total_advertised: int
    ml_dsa_advertised: List[str]
    ml_dsa_available: bool
    note: str


# ── Data plane echo ──────────────────────────────────────────────────────────

class DataplaneEchoResponse(BaseModel):
    """
    What NGINX observed about the connection that reached this endpoint.

    Every field is populated from an `X-QUANSEC-TLS-*` header injected by NGINX
    from its own `$ssl_*` variables. The backend cannot see the TLS connection
    itself — it terminates at NGINX — so these are NGINX's observations relayed
    verbatim, not measurements this process made.
    """

    endpoint: str
    tls_protocol: Optional[str] = None
    cipher: Optional[str] = None
    negotiated_group: Optional[str] = None
    client_groups: Optional[str] = None
    client_verify: Optional[str] = None
    server_name: Optional[str] = None
    pqc_enabled: bool = False
    kem_label: Optional[str] = None
    observed_by: str = "nginx"
    note: str
