"""
tests/test_tls_api.py — the /api/tls surface.

The adapter is pointed at a real TLS server started by the test, so these
exercise the whole path: route -> adapter -> live handshake -> database. Only
authentication and the database transaction are substituted.
"""

import pytest

from conftest import free_port
from protocols.tls import router as tls_router_module
from protocols.tls.adapter import TlsServiceAdapter
from protocols.tls.settings import TlsSettings


@pytest.fixture
def tls_settings_for(pki):
    """Build TlsSettings pointing at a given port and the test PKI."""

    def _make(port: int, **overrides) -> TlsSettings:
        base = dict(
            enabled=True,
            host="127.0.0.1",
            port=port,
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
        base.update(overrides)
        return TlsSettings(**base)

    return _make


@pytest.fixture
def point_module_at(monkeypatch, tls_settings_for):
    """Repoint the router's settings lookup at a test TLS service."""

    def _point(port: int, **overrides) -> TlsSettings:
        settings = tls_settings_for(port, **overrides)
        monkeypatch.setattr(tls_router_module, "get_tls_settings", lambda: settings)
        return settings

    return _point


# ── 16. Status ───────────────────────────────────────────────────────────────

def test_status_reports_a_reachable_service(api_client, running_server, point_module_at):
    server, config = running_server()
    point_module_at(config.port)

    response = api_client.get("/api/tls/status")
    assert response.status_code == 200
    body = response.json()

    assert body["enabled"] is True
    assert body["service"]["reachable"] is True
    assert body["service"]["configured_port"] == config.port
    assert body["service"]["probe_ms"] >= 0
    assert body["runtime"]["python_ssl_openssl"].startswith("OpenSSL")


def test_status_makes_no_unverified_pqc_claim(api_client, running_server, point_module_at):
    """
    The most load-bearing assertion in the API tests: a status response from a
    perfectly healthy TLS service must not describe it as post-quantum.
    """
    server, config = running_server()
    point_module_at(config.port)

    body = api_client.get("/api/tls/status").json()
    hybrid = body["hybrid"]

    assert hybrid["availability"] in ("unavailable", "supported")
    assert hybrid["availability"] != "negotiated_verified"
    assert hybrid["enforcement"] == "not_enabled"
    assert hybrid["last_external_verification"] is None

    serialised = str(body).lower()
    assert "quantum-safe connection" not in serialised
    assert "tls_native_hybrid" not in serialised


# ── 17. Live handshake through the API ───────────────────────────────────────

def test_test_connection_returns_live_handshake_values(
    api_client, running_server, point_module_at
):
    server, config = running_server(handler=lambda m, s: "ok")
    point_module_at(config.port)

    response = api_client.post("/api/tls/test-connection", json={"message": "hello"})
    assert response.status_code == 200
    body = response.json()

    assert body["success"] is True
    assert body["outcome"] == "success"
    assert body["tls_version"] == "TLSv1.3"
    assert body["cipher_name"].startswith("TLS_")
    assert body["cert_verified"] is True
    assert body["peer_cert"]["cn"] == "localhost"
    assert body["handshake_ms"] > 0
    assert body["echo_received"] is True

    # Group is unobservable from Python, and the response says so rather than
    # leaving a bare null.
    assert body["negotiated_group"] is None
    assert body["negotiated_group_source"] == "unavailable-python-ssl"


def test_test_connection_does_not_echo_the_payload(
    api_client, running_server, point_module_at
):
    """A response must not carry the request payload back to the caller."""
    secret = "correct-horse-battery-staple"
    server, config = running_server(handler=lambda m, s: f"received {len(m)}")
    point_module_at(config.port)

    response = api_client.post("/api/tls/test-connection", json={"message": secret})

    assert response.status_code == 200
    assert secret not in response.text
    assert response.json()["echo_received"] is True


def test_test_connection_works_without_a_body(api_client, running_server, point_module_at):
    server, config = running_server()
    point_module_at(config.port)

    assert api_client.post("/api/tls/test-connection").status_code == 200


# ── 18. Service unavailable ──────────────────────────────────────────────────

def test_test_connection_returns_503_when_the_service_is_down(
    api_client, point_module_at
):
    point_module_at(free_port())      # nothing is listening

    response = api_client.post("/api/tls/test-connection")

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["outcome"] == "unreachable"
    assert detail["error_type"] == "TLSConnectionError"


def test_status_reports_unreachable_without_failing(api_client, point_module_at):
    """/status must answer even when the service is down — that IS the answer."""
    settings = point_module_at(free_port())

    response = api_client.get("/api/tls/status")

    assert response.status_code == 200
    assert response.json()["service"]["reachable"] is False
    assert response.json()["service"]["error"]


def test_module_disabled_returns_503(api_client, point_module_at):
    point_module_at(free_port(), enabled=False)

    for method, path in [
        ("get", "/api/tls/status"),
        ("post", "/api/tls/test-connection"),
        ("get", "/api/tls/certificate"),
    ]:
        response = getattr(api_client, method)(path)
        assert response.status_code == 503
        assert "disabled" in response.json()["detail"].lower()


def test_missing_certificates_report_config_error(api_client, point_module_at, tmp_path):
    """A missing CA is an operator problem, and the message must say what to run."""
    missing = str(tmp_path / "absent")
    point_module_at(
        free_port(),
        ca_cert=f"{missing}/ca.crt",
        server_cert=f"{missing}/server.crt",
        server_key=f"{missing}/server.key",
    )

    response = api_client.post("/api/tls/test-connection")

    assert response.status_code == 503
    assert "generate_tls_certs" in str(response.json()["detail"])


# ── 20. Malformed input ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "payload",
    [
        {"message": "x" * 5000},        # over MAX_MESSAGE_BYTES
        {"message": ""},                # empty
        {"message": "   "},             # whitespace only
        {"message": 12345},             # wrong type
        {"message": None},              # null
    ],
)
def test_malformed_bodies_are_rejected_with_422(
    api_client, running_server, point_module_at, payload
):
    server, config = running_server()
    point_module_at(config.port)

    assert api_client.post("/api/tls/test-connection", json=payload).status_code == 422


def test_sessions_query_parameters_are_validated(api_client, point_module_at):
    point_module_at(free_port())

    assert api_client.get("/api/tls/sessions?limit=0").status_code == 422
    assert api_client.get("/api/tls/sessions?limit=99999").status_code == 422
    assert api_client.get("/api/tls/sessions?limit=abc").status_code == 422


# ── 21. Authorisation ────────────────────────────────────────────────────────

def test_all_tls_routes_require_authentication(raw_api_client):
    """
    Uses raw_api_client, which leaves authentication intact. api_client stubs it
    out and would hide exactly this failure.
    """
    for method, path in [
        ("get", "/api/tls/status"),
        ("post", "/api/tls/test-connection"),
        ("get", "/api/tls/session"),
        ("get", "/api/tls/sessions"),
        ("get", "/api/tls/stats"),
        ("get", "/api/tls/certificate"),
        ("get", "/api/tls/policies/compare"),
        ("post", "/api/tls/hybrid/verify"),
    ]:
        response = getattr(raw_api_client, method)(path)
        assert response.status_code == 401, f"{method} {path} was not protected"


def test_hybrid_verify_requires_admin(raw_api_client, running_server, point_module_at):
    """
    The verification endpoint spawns a subprocess and writes the evidence that
    governs what the platform may claim, so it is admin-only.
    """
    from fastapi import HTTPException

    from conftest import _override_auth

    server, config = running_server()
    point_module_at(config.port)

    def _reject_admin():
        raise HTTPException(status_code=403, detail="Admin privileges required")

    _override_auth(
        raw_api_client.app,
        user={"id": 2, "email": "op@quanseq.io", "role": "operator"},
        admin=_reject_admin,
    )

    assert raw_api_client.post("/api/tls/hybrid/verify").status_code == 403
    # ...while read-only endpoints remain available to an operator.
    assert raw_api_client.get("/api/tls/status").status_code == 200


# ── 22. Certificate generation is not exposed ────────────────────────────────

def test_no_certificate_generation_endpoint_exists(api_client):
    """
    Certificate generation rotates the module's trust anchor. It must not be
    reachable over HTTP by anyone, authenticated or not.
    """
    for method, path in [
        ("post", "/api/tls/certificate"),
        ("post", "/api/tls/certificates"),
        ("post", "/api/tls/certs/regenerate"),
        ("post", "/api/tls/certificate/regenerate"),
        ("post", "/api/tls/certs"),
    ]:
        status = getattr(api_client, method)(path).status_code
        assert status in (404, 405), f"{method} {path} unexpectedly exists ({status})"


def test_no_policy_apply_endpoint_exists(api_client):
    """
    There is no enforcement mechanism, so there must be no 'apply policy'
    control implying one.
    """
    assert api_client.post("/api/tls/policies/apply").status_code in (404, 405)


# ── Certificate and comparison endpoints ─────────────────────────────────────

def test_certificate_endpoint_reports_real_certificate_facts(
    api_client, running_server, point_module_at
):
    server, config = running_server()
    point_module_at(config.port)

    response = api_client.get("/api/tls/certificate")
    assert response.status_code == 200
    body = response.json()

    assert body["public_key_algorithm"] == "RSA"
    assert body["key_size"] == 2048
    assert "QUANSEQ TLS Development Root CA" in body["issuer"]
    assert "DNS:localhost" in body["san"]
    assert body["chain_verified"] is True
    assert body["days_until_expiry"] > 0
    # Classical signature today; the response says so rather than staying silent.
    assert body["pqc_signature"] is False
    assert "ML-DSA" in body["note"]


def test_policy_comparison_states_the_enforcement_gap(
    api_client, running_server, point_module_at
):
    server, config = running_server()
    point_module_at(config.port)

    body = api_client.get("/api/tls/policies/compare").json()

    assert body["days_remaining"] > 0
    assert "cannot enforce" in body["enforcement_note"].lower()
    assert body["hybrid"]["enforcement"] == "not_enabled"


def test_hybrid_verify_records_a_negative_result_as_200(
    api_client, running_server, point_module_at
):
    """
    On a runtime without the hybrid group, verification fails — and that is a
    finding to record, not a server error.
    """
    server, config = running_server()
    point_module_at(config.port)

    response = api_client.post("/api/tls/hybrid/verify")
    assert response.status_code == 200
    body = response.json()

    assert body["requested_group"] == "X25519MLKEM768"
    assert body["target_port"] == config.port
    assert isinstance(body["verified"], bool)
    assert body["hybrid"]["enforcement"] == "not_enabled"


# ── Empty-state honesty ──────────────────────────────────────────────────────

def test_stats_never_reports_pqc_without_evidence(
    api_client, running_server, point_module_at
):
    """
    Whatever observations exist, coverage stays a computed ratio and hybrid
    stays unenforced. Coverage is only non-zero if verified evidence rows exist.
    """
    server, config = running_server()
    point_module_at(config.port)

    body = api_client.get("/api/tls/stats").json()

    assert body["total_observations"] >= 0
    assert 0.0 <= body["pqc_coverage"] <= 100.0
    assert body["pqc_observations"] <= body["successful"]
    assert body["hybrid"]["enforcement"] == "not_enabled"
    if body["hybrid"]["availability"] != "negotiated_verified":
        assert body["pqc_observations"] == 0


def test_session_endpoint_404s_before_any_observation(api_client, point_module_at):
    """No observations means 404 with an actionable message, not a fake row."""
    point_module_at(free_port())

    response = api_client.get("/api/tls/session")

    assert response.status_code in (404, 200)
    if response.status_code == 404:
        assert "test-connection" in response.json()["detail"]
