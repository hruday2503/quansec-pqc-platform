"""
protocols/tls/router.py — REST endpoints for the TLS PQC module.

  GET  /api/tls/status                    nine evidence-derived status fields
  GET  /api/tls/readiness                 can the data plane be relied on
  GET  /api/tls/stats                     counts and percentiles over sessions
  GET  /api/tls/sessions                  observed sessions from the NGINX log
  GET  /api/tls/sessions/{id}             one session, with its raw log line
  GET  /api/tls/events                    service and policy lifecycle events
  GET  /api/tls/policy                    intended vs running policy, and drift
  GET  /api/tls/certificate               certificate facts, auth reported separately
  GET  /api/tls/signature-algorithms      what the runtime advertises (ML-DSA research)
  POST /api/tls/policy/apply              render, validate, reload            [admin]
  POST /api/tls/probe                     run enforcement probes              [admin]
  POST /api/tls/tests/hybrid-downgrade    X25519-only + prime256v1-only       [admin]
  POST /api/tls/tests/tls12-downgrade     TLS 1.2 client                      [admin]
  POST /api/tls/tests/cipher-downgrade    AES-128-only client                 [admin]
  POST /api/tls/service/{action}          start | stop | reload               [admin]
  GET  /api/tls/dataplane/echo            proxied by NGINX; reports $ssl_* facts

AUTHORIZATION
-------------
Read endpoints require `tls:read` (implied by `tls:admin` and `system:admin`).
Everything that changes state, spawns a client, or touches the data plane
requires `tls:admin` or `system:admin` — policy, probes, downgrade tests,
service control and certificate operations, per the scope matrix in
core/scopes.py.

`/dataplane/echo` is the one unauthenticated route, and deliberately so: it is
reachable only through the NGINX endpoint on 127.0.0.1:8443, which is what the
positive probe connects to. An OpenSSL `s_client` handshake has no bearer token
to present, so requiring one would make the very test this module exists to run
impossible. It returns only what NGINX already told us about the caller's own
connection, so it discloses nothing the caller did not supply.

NOT PRESENT, ON PURPOSE
-----------------------
Certificate generation. It rotates the trust anchor for the whole module and
belongs to an operator with shell access — see scripts/generate_tls_certs.py.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from core.auth import require_scope
from core.database import get_db
from core.scopes import TLS_ADMIN_SCOPES, TLS_READ_SCOPES

from . import policy as tls_policy
from .certs import CertificateUnavailable, describe_certificate, verify_chain
from .collector import classify_group
from .models import (
    DataplaneEchoResponse,
    DowngradeTestResponse,
    PolicyApplyRequest,
    ProbeRequest,
    ProbeSuiteResponse,
    SignatureAlgorithmsResponse,
    TlsCertificateResponse,
    TlsPolicyResponse,
    TlsReadinessResponse,
    TlsSessionDetailResponse,
    TlsSessionResponse,
    TlsStatsResponse,
    TlsStatusResponse,
)
from .probe import (
    ENFORCEMENT_PROBES,
    NEGATIVE_AES128,
    NEGATIVE_PRIME256V1,
    NEGATIVE_TLS12,
    NEGATIVE_X25519,
    PROBE_SPECS,
    ProbeResult,
    TlsProber,
)
from .service import NginxTlsService
from .settings import TlsConfigurationError, get_tls_settings
from .stats import get_tls_stats

logger = logging.getLogger("quansec.tls.router")
router = APIRouter(prefix="/api/tls", tags=["TLS PQC"])

# Read and admin dependencies, named once so a route cannot accidentally be
# mounted with the wrong one.
_read = Depends(require_scope(*TLS_READ_SCOPES))
_admin = Depends(require_scope(*TLS_ADMIN_SCOPES))


def _require_enabled():
    """Resolve settings, or fail with a reason an operator can act on."""
    settings = get_tls_settings()
    if not settings.enabled:
        raise HTTPException(
            status_code=503,
            detail="TLS module is disabled (QUANSEC_TLS_ENABLED=false)",
        )
    return settings


async def _probe_results_map(conn: asyncpg.Connection) -> Dict[str, bool]:
    """
    The latest outcome per probe type.

    DISTINCT ON takes the most recent run of each type: an enforcement claim
    must rest on the current state of the data plane, not on a probe that
    passed last week before someone widened the group list.
    """
    rows = await conn.fetch(
        """SELECT DISTINCT ON (probe_type) probe_type, passed, run_at
           FROM tls_probe_results
           ORDER BY probe_type, run_at DESC"""
    )
    return {row["probe_type"]: row["passed"] for row in rows}


async def _observed_hybrid_count(conn: asyncpg.Connection, hybrid_group: str) -> int:
    """
    How many recorded sessions negotiated the hybrid group.

    Counted from `tls_sessions`, every row of which came from a line NGINX
    wrote. Configuration is not consulted here by design.
    """
    return await conn.fetchval(
        "SELECT COUNT(*) FROM tls_sessions WHERE lower(negotiated_group) = lower($1)",
        hybrid_group,
    ) or 0


async def _was_enforced(conn: asyncpg.Connection) -> bool:
    """
    Whether enforcement was ever proven.

    Distinguishes "never proven" from "regressed": if both enforcement probes
    passed at some point and one now fails, the status is `degraded`, which is a
    louder and more accurate signal than falling back to `configured_unproven`.
    """
    count = await conn.fetchval(
        """SELECT COUNT(DISTINCT probe_type) FROM tls_probe_results
           WHERE probe_type = ANY($1::text[]) AND passed""",
        list(ENFORCEMENT_PROBES),
    )
    return (count or 0) >= len(ENFORCEMENT_PROBES)


async def _store_probe_results(conn: asyncpg.Connection,
                               results: List[ProbeResult]) -> None:
    """Persist probe results, then record one summary event."""
    for r in results:
        await conn.execute(
            """INSERT INTO tls_probe_results (
                   probe_type, expected_outcome, actual_outcome, passed,
                   target_host, target_port, negotiated_group, negotiated_cipher,
                   tls_protocol, verify_result, openssl_binary, openssl_version,
                   command, exit_code, stdout_excerpt, evidence_path, run_at
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)""",
            r.probe_type, r.expected_outcome, r.actual_outcome, r.passed,
            r.target_host, r.target_port, r.negotiated_group, r.negotiated_cipher,
            r.tls_protocol, r.verify_result, r.openssl_binary, r.openssl_version,
            r.command, r.exit_code, r.stdout_excerpt, r.evidence_path, r.run_at,
        )

    passed = sum(1 for r in results if r.passed)
    await tls_policy.record_event(
        conn, "probe_run",
        f"Ran {len(results)} enforcement probe(s): {passed} passed, "
        f"{len(results) - passed} failed",
        severity="info" if passed == len(results) else "warning",
        detail={"probes": {r.probe_type: r.passed for r in results}},
    )


def _prober_or_503(settings) -> TlsProber:
    prober = TlsProber(settings)
    if not prober.available():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Runtime OpenSSL not found at {settings.openssl_bin}. "
                "Build it with: bash scripts/build-pqc-tls-runtime.sh"
            ),
        )
    return prober


# ── Status ───────────────────────────────────────────────────────────────────

@router.get("/status", response_model=TlsStatusResponse, dependencies=[_read])
async def tls_status(conn: asyncpg.Connection = Depends(get_db)):
    """
    The nine status fields, each derived from named evidence.

    Nothing here is inferred from configuration alone. `hybrid_group_negotiated`
    counts real log lines; `hybrid_only_enforced` requires both classical probes
    to have been refused. With no evidence every field is false, which is a
    truthful empty state rather than a placeholder.
    """
    settings = _require_enabled()
    service = NginxTlsService(settings)

    probe_results = await _probe_results_map(conn)
    observed = await _observed_hybrid_count(conn, settings.hybrid_group)
    was_enforced = await _was_enforced(conn)

    # Certificate PQ status is read from the certificate itself, never assumed.
    certificate_pqc = False
    try:
        facts = describe_certificate(settings)
        certificate_pqc = facts.pqc_signature
    except CertificateUnavailable as exc:
        logger.info("Certificate not readable for status: %s", exc)

    status = service.evaluate_status(
        observed_group_count=observed,
        probe_results=probe_results,
        certificate_pqc=certificate_pqc,
        was_enforced=was_enforced,
    )

    process = service.process_state()
    return {
        "enabled": True,
        **status.to_dict(),
        "service": {
            "host": settings.host,
            "port": settings.port,
            "running": process.running,
            "pid": process.pid,
            "listening": process.listening,
            "config_path": process.config_path,
            "config_sha256": process.config_sha256,
            "error": process.error,
        },
        "build": service.build_info(),
        "last_updated": datetime.now(timezone.utc),
    }


@router.get("/readiness", response_model=TlsReadinessResponse, dependencies=[_read])
async def tls_readiness():
    """
    Whether the data plane can be relied on, and precisely what is missing.

    Each check names the remedy. "Not ready" with no explanation is what sends
    an operator to read source code.
    """
    settings = _require_enabled()
    service = NginxTlsService(settings)

    checks: List[Dict[str, Any]] = []
    blocking: List[str] = []
    warnings: List[str] = []

    def check(name: str, ok: bool, detail: str, *, fatal: bool = True) -> None:
        checks.append({"check": name, "passed": ok, "detail": detail})
        if not ok:
            (blocking if fatal else warnings).append(f"{name}: {detail}")

    runtime_built = settings.runtime_available()
    check("runtime_built", runtime_built,
          f"OpenSSL and NGINX present under {settings.runtime_dir}" if runtime_built
          else "Run: bash scripts/build-pqc-tls-runtime.sh")

    if runtime_built:
        linked = settings.nginx_linked_openssl()
        check("nginx_linked_openssl_35", bool(linked and linked.startswith("3.5")),
              f"nginx -V reports OpenSSL {linked}" if linked
              else "Could not read `nginx -V`")

        lists_group = settings.runtime_lists_group()
        check("hybrid_group_available", lists_group,
              f"{settings.hybrid_group} listed by the runtime OpenSSL" if lists_group
              else f"{settings.hybrid_group} not in `openssl list -tls-groups`")

    for label, path in (("ca_certificate", settings.ca_cert),
                        ("server_certificate", settings.server_cert),
                        ("server_key", settings.server_key)):
        import os
        exists = os.path.isfile(path)
        check(label, exists, path if exists
              else f"{path} missing - run: python scripts/generate_tls_certs.py")

    intended = tls_policy.intended_policy(settings)
    check("policy_fail_closed", intended.fail_closed,
          f"groups={intended.groups} protocols={intended.protocols}"
          if intended.fail_closed
          else f"Fallback groups {intended.fallback_groups} would allow classical "
               "key exchange")

    running = service.is_running()
    check("service_running", running,
          f"NGINX pid {service.read_pid()}" if running
          else "Not running - start with: bash scripts/start-pqc-tls.sh",
          fatal=False)

    check("service_listening", service.is_listening(),
          f"accepting on {settings.host}:{settings.port}"
          if service.is_listening() else "nothing accepting on the endpoint",
          fatal=False)

    return {
        "ready": not blocking,
        "checks": checks,
        "blocking": blocking,
        "warnings": warnings,
        "runtime": service.build_info(),
    }


@router.get("/stats", response_model=TlsStatsResponse, dependencies=[_read])
async def tls_stats(conn: asyncpg.Connection = Depends(get_db)):
    """
    Counts and coverage over every session the collector has recorded.

    The aggregate companion to /sessions: same rows, summarised. Every number
    is a count over real log lines, so a table with no rows returns zeros, a
    null last_observed_at and has_evidence=false — rather than anything that
    reads as a measurement.

    `hybrid_coverage` reports what was observed, not what is required.
    Enforcement lives on /status.hybrid_only_enforced and nowhere else.
    """
    _require_enabled()
    return await get_tls_stats(conn)


# ── Sessions ─────────────────────────────────────────────────────────────────

@router.get("/sessions", response_model=List[TlsSessionResponse], dependencies=[_read])
async def tls_sessions(
    limit: int = Query(50, ge=1, le=500),
    pqc: Optional[bool] = None,
    group: Optional[str] = None,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Observed sessions, newest first. Every row came from a real NGINX log line.

    An empty list means the collector has seen no handshakes — a measurement,
    not a gap to be filled in.
    """
    _require_enabled()

    clauses, params = [], []
    if pqc is not None:
        params.append(pqc)
        clauses.append(f"pqc_enabled = ${len(params)}")
    if group:
        params.append(group)
        clauses.append(f"lower(negotiated_group) = lower(${len(params)})")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    rows = await conn.fetch(
        f"""SELECT id, occurred_at, remote_addr, remote_port, tls_protocol, cipher,
                   negotiated_group, client_groups, client_verify, client_s_dn,
                   server_name, session_reused, http_status, request_time,
                   bytes_sent, request_line, pqc_enabled, kem_label,
                   log_source, log_offset, recorded_at
            FROM tls_sessions {where}
            ORDER BY occurred_at DESC, id DESC
            LIMIT ${len(params)}""",
        *params,
    )
    return [dict(row) for row in rows]


@router.get("/sessions/{session_id}", response_model=TlsSessionDetailResponse,
            dependencies=[_read])
async def tls_session_detail(session_id: int,
                             conn: asyncpg.Connection = Depends(get_db)):
    """
    One session, including the raw log line it was parsed from.

    The raw line is the audit trail: it lets a reader confirm that
    `negotiated_group` was read from the log and not decided by this code.
    """
    _require_enabled()
    row = await conn.fetchrow("SELECT * FROM tls_sessions WHERE id = $1", session_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"No TLS session with id {session_id}")
    return dict(row)


@router.get("/events", dependencies=[_read])
async def tls_events(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    conn: asyncpg.Connection = Depends(get_db),
):
    """Service, policy and probe lifecycle events."""
    _require_enabled()
    if severity:
        rows = await conn.fetch(
            """SELECT * FROM tls_events WHERE severity = $1
               ORDER BY occurred_at DESC LIMIT $2""",
            severity, limit,
        )
    else:
        rows = await conn.fetch(
            "SELECT * FROM tls_events ORDER BY occurred_at DESC LIMIT $1", limit
        )
    return [dict(row) for row in rows]


# ── Policy ───────────────────────────────────────────────────────────────────

@router.get("/policy", response_model=TlsPolicyResponse, dependencies=[_read])
async def tls_get_policy(conn: asyncpg.Connection = Depends(get_db)):
    """
    The intended policy, the policy NGINX is actually running, and the drift.

    Kept separate because a hand-edited nginx.conf must not be reported as the
    policy QUANSEC intended.
    """
    settings = _require_enabled()
    service = NginxTlsService(settings)

    intended = tls_policy.intended_policy(settings)
    running = tls_policy.running_policy(service)

    return {
        "intended": intended.to_dict(),
        "running": running.to_dict() if running else None,
        "drift": tls_policy.compare(intended, running),
        "active_state": await tls_policy.active_policy_state(conn),
        # The running policy is what governs live connections. Falling back to
        # the intended one here would report enforcement that is not in effect.
        "fail_closed": running.fail_closed if running else False,
    }


@router.post("/policy/apply", dependencies=[_admin])
async def tls_apply_policy(
    body: PolicyApplyRequest | None = None,
    user: Dict[str, Any] = _admin,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Render, validate and reload the TLS policy. Requires `tls:admin`.

    Refuses to apply a policy that is not fail-closed — see policy.apply_policy.
    """
    settings = _require_enabled()
    reload = body.reload if body else True

    result = await tls_policy.apply_policy(
        conn, applied_by=user.get("email", "unknown"),
        settings=settings, reload=reload,
    )
    if not result["applied"]:
        raise HTTPException(status_code=409, detail=result)
    return result


@router.post("/service/{action}", dependencies=[_admin])
async def tls_service_control(
    action: str,
    user: Dict[str, Any] = _admin,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Control the NGINX data plane: start, stop or reload. Requires `tls:admin`.

    Stop waits for the listening socket to be released, so an immediate restart
    does not race the old process for the port.
    """
    settings = _require_enabled()
    service = NginxTlsService(settings)

    if action not in ("start", "stop", "reload"):
        raise HTTPException(status_code=400,
                            detail="action must be start, stop or reload")

    actor = user.get("email", "unknown")

    if action == "start":
        state = service.start()
        ok = state.running and state.listening
        await tls_policy.record_event(
            conn, "service_start" if ok else "config_rejected",
            f"NGINX start requested by {actor}: "
            + ("listening" if ok else f"failed - {state.error}"),
            severity="info" if ok else "critical",
            detail={"pid": state.pid, "error": state.error, "actor": actor},
        )
        if not ok:
            raise HTTPException(status_code=500,
                                detail=state.error or "NGINX did not start")
        return {"action": "start", "running": True, "pid": state.pid,
                "listening": state.listening}

    if action == "stop":
        stopped = service.stop()
        await tls_policy.record_event(
            conn, "service_stop",
            f"NGINX stop requested by {actor}: "
            + ("stopped and port released" if stopped else "did not stop cleanly"),
            severity="info" if stopped else "warning",
            detail={"actor": actor, "stopped": stopped},
        )
        return {"action": "stop", "stopped": stopped}

    ok, output = service.reload()
    await tls_policy.record_event(
        conn, "service_reload" if ok else "config_rejected",
        f"NGINX reload requested by {actor}: {output}",
        severity="info" if ok else "critical",
        detail={"actor": actor, "output": output[:1000]},
    )
    if not ok:
        raise HTTPException(status_code=409, detail=output)
    return {"action": "reload", "reloaded": True, "detail": output}


# ── Probes ───────────────────────────────────────────────────────────────────

@router.post("/probe", response_model=ProbeSuiteResponse, dependencies=[_admin])
async def tls_probe(
    body: ProbeRequest | None = None,
    conn: asyncpg.Connection = Depends(get_db),
):
    """
    Run enforcement probes with the runtime OpenSSL client. Requires `tls:admin`.

    Admin-gated because each probe spawns a subprocess and writes the records
    that govern whether the platform may claim enforcement at all.

    A failed probe returns 200. "We asked for X25519MLKEM768 and did not get it"
    is a finding to record, not a server error.
    """
    settings = _require_enabled()
    try:
        settings.validate(require_runtime=True)
    except TlsConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    prober = _prober_or_503(settings)
    probe_type = body.probe_type if body else None
    include_mtls = body.include_mtls if body else False

    if probe_type:
        if probe_type not in PROBE_SPECS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown probe type. Valid: {sorted(PROBE_SPECS)}",
            )
        results = [prober.run(probe_type)]
    else:
        results = prober.run_standard_suite()
        if include_mtls:
            results.append(prober.run_mtls_probe())

    await _store_probe_results(conn, results)

    latest = await _probe_results_map(conn)
    enforcement_proven = all(latest.get(p, False) for p in ENFORCEMENT_PROBES)
    passed = sum(1 for r in results if r.passed)

    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": [r.to_dict() for r in results],
        "enforcement_proven": enforcement_proven,
        "summary": (
            "Fail-closed enforcement proven: classical X25519-only and "
            "prime256v1-only clients were both refused."
            if enforcement_proven else
            "Enforcement NOT proven. Both the X25519-only and prime256v1-only "
            "probes must be refused before hybrid can be reported as enforced."
        ),
    }


async def _downgrade_test(conn: asyncpg.Connection, settings, probe_types: List[str],
                          *, test_name: str, description: str) -> Dict[str, Any]:
    """
    Shared body for the three downgrade tests.

    Each is a negative probe: `rejected` is True when every handshake FAILED,
    which is the desired outcome.
    """
    prober = _prober_or_503(settings)
    results = [prober.run(pt) for pt in probe_types]
    await _store_probe_results(conn, results)

    rejected = all(r.passed for r in results)
    await tls_policy.record_event(
        conn,
        "enforcement_verified" if rejected else "enforcement_regressed",
        f"{test_name}: " + ("downgrade refused" if rejected else "DOWNGRADE ACCEPTED"),
        severity="info" if rejected else "critical",
        detail={"probes": {r.probe_type: r.passed for r in results}},
    )

    return {
        "test": test_name,
        "rejected": rejected,
        "description": description,
        "results": [r.to_dict() for r in results],
        "verdict": (
            f"PASS - {description} was refused during the handshake."
            if rejected else
            f"FAIL - {description} COMPLETED. The endpoint is not fail-closed."
        ),
    }


@router.post("/tests/hybrid-downgrade", response_model=DowngradeTestResponse,
             dependencies=[_admin])
async def tls_test_hybrid_downgrade(conn: asyncpg.Connection = Depends(get_db)):
    """
    The mandatory fail-closed proof. Requires `tls:admin`.

    Runs BOTH classical clients: X25519-only and prime256v1-only. One refusal is
    not sufficient — a server could permit prime256v1 while refusing X25519, and
    a single probe could not tell that apart from real enforcement.
    """
    settings = _require_enabled()
    return await _downgrade_test(
        conn, settings, [NEGATIVE_X25519, NEGATIVE_PRIME256V1],
        test_name="hybrid-downgrade",
        description="a classical-only client (X25519 / prime256v1)",
    )


@router.post("/tests/tls12-downgrade", response_model=DowngradeTestResponse,
             dependencies=[_admin])
async def tls_test_tls12_downgrade(conn: asyncpg.Connection = Depends(get_db)):
    """
    Prove TLS 1.2 is refused. Requires `tls:admin`.

    TLS 1.2 binds key exchange into the cipher suite and cannot carry a hybrid
    group at all, so accepting it would reopen the classical path regardless of
    how the group list is written.
    """
    settings = _require_enabled()
    return await _downgrade_test(
        conn, settings, [NEGATIVE_TLS12],
        test_name="tls12-downgrade", description="a TLS 1.2 client",
    )


@router.post("/tests/cipher-downgrade", response_model=DowngradeTestResponse,
             dependencies=[_admin])
async def tls_test_cipher_downgrade(conn: asyncpg.Connection = Depends(get_db)):
    """
    Prove a weaker cipher suite is refused. Requires `tls:admin`.

    The client offers the correct hybrid group but only TLS_AES_128_GCM_SHA256,
    isolating cipher-suite enforcement from group enforcement.
    """
    settings = _require_enabled()
    return await _downgrade_test(
        conn, settings, [NEGATIVE_AES128],
        test_name="cipher-downgrade",
        description="a TLS_AES_128_GCM_SHA256-only client",
    )


# ── Certificate ──────────────────────────────────────────────────────────────

@router.get("/certificate", response_model=TlsCertificateResponse, dependencies=[_read])
async def tls_certificate(conn: asyncpg.Connection = Depends(get_db)):
    """
    Server certificate facts, with authentication reported separately from key
    establishment.

    A hybrid key exchange does not make an RSA or ECDSA certificate
    post-quantum. `pqc_signature` describes the certificate alone.
    """
    settings = _require_enabled()
    try:
        facts = describe_certificate(settings)
    except CertificateUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail=f"{exc}. Generate a development PKI with "
                   "python scripts/generate_tls_certs.py",
        ) from exc

    chain_verified = verify_chain(settings)

    await conn.execute(
        """INSERT INTO tls_certificates (
               server_name, subject, issuer, serial_number, signature_algorithm,
               public_key_algorithm, key_size, pqc_signature, chain_verified,
               not_before, not_after, last_checked
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
           ON CONFLICT (server_name, serial_number) DO UPDATE
           SET chain_verified = EXCLUDED.chain_verified, last_checked = NOW()""",
        settings.server_hostname, facts.subject, facts.issuer, facts.serial_number,
        facts.signature_algorithm, facts.public_key_algorithm, facts.key_size,
        facts.pqc_signature, chain_verified, facts.not_before, facts.not_after,
    )

    return {
        "server_name": settings.server_hostname,
        "subject": facts.subject,
        "issuer": facts.issuer,
        "serial_number": facts.serial_number,
        "signature_algorithm": facts.signature_algorithm,
        "public_key_algorithm": facts.public_key_algorithm,
        "key_size": facts.key_size,
        "san": facts.san,
        "not_before": facts.not_before,
        "not_after": facts.not_after,
        "days_until_expiry": facts.days_until_expiry,
        "chain_verified": chain_verified,
        "pqc_signature": facts.pqc_signature,
        "authentication_class": ("post-quantum X.509" if facts.pqc_signature
                                 else "classical X.509"),
        "note": (
            "Key establishment and certificate authentication are independent. "
            f"This certificate is signed with {facts.signature_algorithm}, which is "
            + ("post-quantum." if facts.pqc_signature else
               "classical — the hybrid key exchange does not change that. "
               "Signature forgery is a real-time risk rather than a retroactive "
               "one, so it is not exposed to harvest-now-decrypt-later and "
               "migrates after key exchange.")
        ),
    }


@router.get("/signature-algorithms", response_model=SignatureAlgorithmsResponse,
            dependencies=[_read])
async def tls_signature_algorithms():
    """
    What the runtime OpenSSL advertises for certificate authentication.

    Reporting only, for the ML-DSA research profile. Advertising an algorithm is
    not using it: post-quantum authentication is not claimed until a certificate
    is generated, NGINX loads it, and a client verifies the handshake.
    """
    settings = _require_enabled()
    prober = _prober_or_503(settings)
    return prober.signature_algorithms()


# ── Data plane ───────────────────────────────────────────────────────────────

@router.get("/dataplane/echo", response_model=DataplaneEchoResponse)
async def tls_dataplane_echo(
    request: Request,
    tls_protocol: Optional[str] = Header(None, alias="X-QUANSEC-TLS-Protocol"),
    cipher: Optional[str] = Header(None, alias="X-QUANSEC-TLS-Cipher"),
    negotiated_group: Optional[str] = Header(None, alias="X-QUANSEC-TLS-Group"),
    client_groups: Optional[str] = Header(None, alias="X-QUANSEC-TLS-Curves"),
    client_verify: Optional[str] = Header(None, alias="X-QUANSEC-TLS-Verify"),
    server_name: Optional[str] = Header(None, alias="X-QUANSEC-TLS-ServerName"),
):
    """
    Report what NGINX observed about the caller's own TLS connection.

    This is the only thing served through the post-quantum endpoint, and the
    target the positive probe connects to. Unauthenticated by necessity: an
    `openssl s_client` handshake has no bearer token, so requiring one would
    make the enforcement test impossible. It discloses nothing beyond the
    caller's own connection parameters.

    The values are NGINX's `$ssl_*` variables relayed through proxy headers —
    this process never sees the TLS connection, which terminates at NGINX.

    Reaching this endpoint directly on port 8000 yields nulls and
    `pqc_enabled: false`, correctly: a plain HTTP request to the backend carries
    no TLS facts, and it must never be mistaken for a protected connection.
    """
    def clean(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        text = value.strip()
        return None if text in ("", "-") else text

    group = clean(negotiated_group)
    pqc_enabled, kem_label = classify_group(group)
    via_nginx = any(h.lower().startswith("x-quansec-tls-")
                    for h in request.headers.keys())

    return {
        "endpoint": "/api/tls/dataplane/echo",
        "tls_protocol": clean(tls_protocol),
        "cipher": clean(cipher),
        "negotiated_group": group,
        "client_groups": clean(client_groups),
        "client_verify": clean(client_verify),
        "server_name": clean(server_name),
        "pqc_enabled": pqc_enabled,
        "kem_label": kem_label,
        "observed_by": "nginx" if via_nginx else "none",
        "note": (
            "Values observed by NGINX on the TLS connection and relayed as proxy "
            "headers."
            if via_nginx else
            "No TLS facts present. This request did not arrive through the NGINX "
            "post-quantum endpoint, so it is NOT post-quantum protected."
        ),
    }
