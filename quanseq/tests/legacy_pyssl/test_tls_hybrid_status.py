"""
tests/test_tls_hybrid_status.py — accuracy of post-quantum claims.

This is the most important file in the TLS suite. Everything else checks that
the transport works; these check that QUANSEQ does not overstate what it knows.

The failure mode being guarded against is subtle and attractive: OpenSSL 3.5.5+
offers X25519MLKEM768, so it is tempting to report "quantum-safe" whenever the
runtime is new enough. That would be a fabricated measurement. Only an
out-of-band verification of a real handshake may promote the status.
"""

import pathlib
import re
import shutil
import subprocess

import pytest

from conftest import free_port
from protocols.tls import hybrid
from protocols.tls.hybrid import (
    AVAILABILITY_NEGOTIATED_VERIFIED,
    AVAILABILITY_SUPPORTED,
    AVAILABILITY_UNAVAILABLE,
    ENFORCEMENT_NOT_ENABLED,
)
from protocols.tls.settings import TlsSettings
from protocols.tls.tls13.utils import MIN_HYBRID_OPENSSL, linked_openssl_version

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent

RUNTIME_HAS_HYBRID = linked_openssl_version() >= MIN_HYBRID_OPENSSL


@pytest.fixture
def settings(pki) -> TlsSettings:
    """TlsSettings pointing at the test PKI, with hybrid requested but not required."""
    return TlsSettings(
        enabled=True,
        host="127.0.0.1",
        port=free_port(),
        server_hostname="localhost",
        bind_host="127.0.0.1",
        cert_dir=pki.cert_dir,
        ca_cert=pki.ca_cert,
        server_cert=pki.server_cert,
        server_key=pki.server_key,
        client_cert=pki.client_cert,
        client_key=pki.client_key,
        mtls=False,
        timeout=5,
        handshake_timeout=2.0,
        max_clients=10,
        max_concurrent_handshakes=8,
        require_hybrid=False,
        hybrid_group="X25519MLKEM768",
        openssl_bin="openssl",
        log_payloads=False,
        poll_interval=30,
    )


# ── 11. Honest state on a runtime without the group ──────────────────────────

def test_availability_matches_the_actual_runtime(settings):
    """
    On stock Ubuntu 24.04 (OpenSSL 3.0.13) the group does not exist, so the only
    honest answer is 'unavailable'. On a 3.5.5+ runtime it may be 'supported' —
    but never better than that without verification evidence.
    """
    state = hybrid.build_state(settings)

    if RUNTIME_HAS_HYBRID and state.runtime_group_listed:
        assert state.availability == AVAILABILITY_SUPPORTED
    else:
        assert state.availability == AVAILABILITY_UNAVAILABLE

    assert state.availability != AVAILABILITY_NEGOTIATED_VERIFIED


def test_enforcement_is_always_reported_as_not_enabled(settings):
    """
    Python's ssl module cannot select TLS 1.3 groups, so hybrid can never be
    mandatory here. If this test ever fails, an enforcement mechanism was added
    and the surrounding claims must be re-examined rather than the test relaxed.
    """
    state = hybrid.build_state(settings)
    assert state.enforcement == ENFORCEMENT_NOT_ENABLED
    assert state.enforcement_reason == "python-ssl-cannot-select-tls13-groups"

    # Requiring hybrid at startup must not be mistaken for enforcing it.
    required = hybrid.build_state(
        TlsSettings(**{**settings.__dict__, "require_hybrid": True})
    )
    assert required.enforcement == ENFORCEMENT_NOT_ENABLED


def test_label_always_carries_the_enforcement_qualifier(settings):
    """
    The UI renders `label` directly. Any state that sounds reassuring must say,
    in the same breath, that enforcement is off.
    """
    for evidence in (None, {"verified": True, "negotiated_group": "X25519MLKEM768"}):
        label = hybrid.build_state(settings, evidence).label
        assert "quantum-safe" not in label.lower()
        if "verified" in label.lower() or "supported" in label.lower():
            assert "enforcement not enabled" in label.lower()


# ── 12. Verification evidence is required for the top state ──────────────────

def test_verified_state_requires_stored_evidence(settings):
    """Without an evidence record the status can never reach negotiated_verified."""
    assert hybrid.availability(settings, None) != AVAILABILITY_NEGOTIATED_VERIFIED
    assert hybrid.availability(settings, {}) != AVAILABILITY_NEGOTIATED_VERIFIED
    assert hybrid.availability(
        settings, {"verified": False, "negotiated_group": None}
    ) != AVAILABILITY_NEGOTIATED_VERIFIED


def test_verified_evidence_promotes_the_state(settings):
    """A real verification record is the one thing that does promote it."""
    evidence = {
        "verified": True,
        "negotiated_group": "X25519MLKEM768",
        "evidence_line": "Negotiated TLS1.3 group: X25519MLKEM768",
        "verified_at": "2026-07-30T00:00:00+00:00",
    }
    state = hybrid.build_state(settings, evidence)

    assert state.availability == AVAILABILITY_NEGOTIATED_VERIFIED
    assert state.last_external_verification == evidence
    assert state.enforcement == ENFORCEMENT_NOT_ENABLED


# ── 13. A new OpenSSL version alone proves nothing ───────────────────────────

def test_new_openssl_version_alone_does_not_claim_pqc(settings, monkeypatch):
    """
    The headline requirement: the UI must never claim a quantum-safe connection
    merely because the server runs OpenSSL 3.5.5+.

    Here the runtime is made to look like 3.5.5 and the group is made to look
    listed. That is the most favourable possible non-evidence, and it must still
    stop at 'supported'.
    """
    monkeypatch.setattr(
        hybrid, "linked_openssl_version", lambda: (3, 5, 5)
    )
    monkeypatch.setattr(
        hybrid, "runtime_supports_group", lambda group, openssl_bin="openssl": True
    )

    state = hybrid.build_state(settings)

    assert state.availability == AVAILABILITY_SUPPORTED
    assert state.availability != AVAILABILITY_NEGOTIATED_VERIFIED
    assert state.last_external_verification is None
    assert "not verified" in state.label.lower()


def test_group_absent_from_runtime_is_unavailable_even_on_new_openssl(
    settings, monkeypatch
):
    """A new OpenSSL that does not list the group is still 'unavailable'."""
    monkeypatch.setattr(hybrid, "linked_openssl_version", lambda: (4, 0, 0))
    monkeypatch.setattr(
        hybrid, "runtime_supports_group", lambda group, openssl_bin="openssl": False
    )

    assert hybrid.build_state(settings).availability == AVAILABILITY_UNAVAILABLE


# ── 14. Negative enforcement test — documents the current limitation ─────────

@pytest.mark.skipif(
    not RUNTIME_HAS_HYBRID,
    reason=(
        "Requires an OpenSSL CLI that knows -groups X25519MLKEM768 "
        "(3.5.5+). This runtime is older, so the classical-downgrade path "
        "cannot be exercised here."
    ),
)
def test_classical_only_client_is_accepted_documenting_no_enforcement(
    running_server, settings
):
    """
    NEGATIVE TEST — asserts a known weakness, deliberately.

    A client offering only classical X25519 completes a TLS 1.3 handshake
    against our service. This is upstream finding F-01 and it is not fixable in
    Python: `ssl` exposes no TLS 1.3 group-selection API.

    If hybrid enforcement is ever added (OpenSSL SSL_CONF, native bindings, or a
    terminating proxy), THIS TEST MUST BE INVERTED to assert the connection is
    refused, and hybrid.ENFORCEMENT_NOT_ENABLED must stop being a constant.
    """
    server, config = running_server()

    result = subprocess.run(
        [
            "openssl", "s_client",
            "-connect", f"{config.host}:{config.port}",
            "-tls1_3", "-groups", "X25519",
            "-CAfile", config.ca_cert,
            "-servername", "localhost", "-brief",
        ],
        input="", capture_output=True, text=True, timeout=20,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 0, (
        "A classical-only client was refused. If that is intentional, hybrid "
        "enforcement now exists and this test must be inverted."
    )
    assert "TLSv1.3" in output

    # ...and the reported state must be honest about it.
    assert hybrid.build_state(settings).enforcement == ENFORCEMENT_NOT_ENABLED


def test_external_verification_records_a_negative_result_without_raising(
    running_server, settings
):
    """
    Verification against a runtime that lacks the group must return a recorded
    negative, not an exception. 'We asked and it failed' is a finding.
    """
    server, config = running_server()
    probe_settings = TlsSettings(**{**settings.__dict__, "port": config.port})

    evidence = hybrid.verify_externally(probe_settings, timeout=20)

    assert evidence.requested_group == "X25519MLKEM768"
    assert evidence.target_port == config.port
    assert evidence.verified_at is not None

    if not RUNTIME_HAS_HYBRID:
        assert evidence.verified is False
        assert evidence.negotiated_group is None
    if evidence.verified:
        assert evidence.negotiated_group.lower() == "x25519mlkem768"


# ── 15. Source-level guards ──────────────────────────────────────────────────

def _backend_sources():
    """Every first-party Python source file in the backend."""
    skip = {".venv", "__pycache__", "compiled-backup", "tests"}
    for path in BACKEND_ROOT.rglob("*.py"):
        if any(part in skip for part in path.parts):
            continue
        yield path


def test_tls_native_hybrid_appears_nowhere_in_the_backend():
    """
    The upstream compatibility wrapper emitted `"tls_native_hybrid": True` as
    handshake evidence. That is a hardcoded post-quantum claim, so the wrapper
    was excluded from the vendored set. Make sure it never comes back.
    """
    offenders = [
        str(path.relative_to(BACKEND_ROOT))
        for path in _backend_sources()
        if "tls_native_hybrid" in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert not offenders, (
        f"tls_native_hybrid found in {offenders}. Hybrid status must come from "
        "protocols/tls/hybrid.py, which requires verification evidence."
    )


def test_no_source_hardcodes_a_successful_pqc_negotiation():
    """
    Scan for literals that assert a post-quantum OUTCOME, e.g. `pqc_enabled = True`
    or `"quantum_safe": True`. A positive value for any of these may only be
    produced by hybrid.py, from stored verification evidence.

    A bare `"pqc": True` is deliberately not matched. That key is the column name
    in the classical-vs-hybrid comparison table shared by all three protocol
    modules, where it describes what the hybrid policy would provide rather than
    what a session negotiated. Matching it would flag a documentation table and
    push the guard towards being disabled — the fields below are the ones that
    are persisted and reported as measurements.
    """
    pattern = re.compile(
        r"""["']?(pqc_enabled|quantum_safe|hybrid_verified|is_pqc|negotiated_verified)["']?\s*[:=]\s*True""",
        re.IGNORECASE,
    )

    # Scope: the TLS module only. IPsec and SSH derive pqc_enabled from live
    # daemon state through their own collectors, which is out of scope here.
    tls_sources = [
        path for path in _backend_sources()
        if "tls" in path.parts and path.name != "hybrid.py"
    ]
    assert tls_sources, "found no TLS sources to scan - the guard would pass vacuously"

    offenders = []
    for path in tls_sources:
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            code = line.split("#", 1)[0]
            if pattern.search(code):
                offenders.append(f"{path.relative_to(BACKEND_ROOT)}:{number}: {line.strip()}")

    assert not offenders, (
        "TLS sources hardcode a post-quantum result:\n  " + "\n  ".join(offenders)
    )


def test_pqc_enabled_is_only_ever_written_from_resolved_evidence():
    """
    Complements the pattern scan above by checking the call sites: every write of
    `pqc_enabled` in the TLS module must pass through resolve_pqc_enabled(), which
    requires a verified evidence row.
    """
    collector = (BACKEND_ROOT / "protocols" / "tls" / "collector.py").read_text()
    router = (BACKEND_ROOT / "protocols" / "tls" / "router.py").read_text()

    assert "async def resolve_pqc_enabled" in collector
    assert "if observation.outcome != OUTCOME_SUCCESS:" in collector
    assert "latest_verified_evidence" in collector

    # Both persistence call sites derive the flag rather than passing a literal.
    for source, name in ((collector, "collector"), (router, "router")):
        for line in source.splitlines():
            if "record_observation(" in line or "pqc_enabled=" in line:
                assert "pqc_enabled=True" not in line.replace(" ", ""), (
                    f"{name} writes pqc_enabled as a literal: {line.strip()}"
                )


def test_ui_never_claims_a_quantum_safe_connection_from_a_version():
    """
    hybrid.py is the single source of user-facing wording. None of its labels
    may contain an unqualified reassurance.
    """
    for label in hybrid._LABELS.values():
        lowered = label.lower()
        assert "quantum-safe connection established" not in lowered
        assert "quantum safe" not in lowered


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_runtime_report_is_read_live_not_asserted(settings):
    report = hybrid.runtime_report(settings)

    assert report["python_ssl_openssl"].startswith("OpenSSL")
    assert isinstance(report["tls13_available"], bool)
    assert isinstance(report["tls_groups_listed"], int)
    # On a pre-3.5 CLI `list -tls-groups` does not exist, and reporting zero
    # groups is the correct answer rather than a guess.
    if not RUNTIME_HAS_HYBRID:
        assert report["tls_groups_listed"] == 0
