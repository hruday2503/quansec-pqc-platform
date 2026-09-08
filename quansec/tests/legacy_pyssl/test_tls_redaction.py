"""
tests/test_tls_redaction.py — application payloads must not leak into logs.

The upstream module logged every message body in cleartext on both the client
and the server (its own security assessment, finding F-06). Payloads carried
over a TLS channel are exactly the kind of thing that holds tokens, credentials
or personal data, and logs travel further than the channel does — into terminal
scrollback, service logs, CI output and support bundles.

Redaction is therefore the default, and QUANSEC_TLS_LOG_PAYLOADS=true is an
explicit local-debugging opt-in.
"""

import logging

import pytest

from protocols.tls.tls13 import TLSClient
from protocols.tls.tls13.utils import redact_payload

SECRET = "Bearer eyJhbGciOiJIUzI1NiJ9.super-secret-session-token"


def _all_log_text(caplog) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


# ── 26. Payloads are redacted by default ─────────────────────────────────────

def test_payload_is_absent_from_logs_by_default(running_server, caplog):
    caplog.set_level(logging.DEBUG, logger="quansec.tls.transport")
    server, config = running_server(handler=lambda m, s: "ok")

    with TLSClient(config) as client:
        assert client.send(SECRET) == "ok"

    logged = _all_log_text(caplog)
    assert SECRET not in logged
    assert "super-secret-session-token" not in logged
    # The event is still logged, just without the body.
    assert "redacted" in logged.lower()


def test_server_side_logging_is_also_redacted(running_server, caplog):
    """Both ends logged payloads upstream; both must be covered."""
    caplog.set_level(logging.DEBUG, logger="quansec.tls.transport")
    server, config = running_server(handler=lambda m, s: "ok")

    with TLSClient(config) as client:
        client.send(SECRET)

    receive_lines = [
        record.getMessage() for record in caplog.records
        if "Received from" in record.getMessage()
    ]
    assert receive_lines, "the server did not log the receive event at all"
    for line in receive_lines:
        assert SECRET not in line
        assert "redacted" in line.lower()


def test_redaction_reports_size_so_the_log_stays_useful(tls_config):
    """A redacted line should still tell an operator something."""
    config = tls_config()
    redacted = redact_payload("hello world", config)

    assert "hello world" not in redacted
    assert "11 bytes" in redacted


def test_opt_in_disables_redaction(tls_config):
    """The escape hatch exists, and it is off unless explicitly enabled."""
    default = tls_config()
    debugging = tls_config(log_payloads=True)

    assert default.log_payloads is False
    assert redact_payload(SECRET, default) != SECRET
    assert redact_payload(SECRET, debugging) == SECRET


def test_settings_warn_when_payload_logging_is_enabled(pki):
    """Turning it on must produce a warning, not pass silently."""
    from protocols.tls.settings import TlsSettings

    settings = TlsSettings(
        enabled=True, host="127.0.0.1", port=8443, server_hostname="localhost",
        bind_host="127.0.0.1", cert_dir=pki.cert_dir, ca_cert=pki.ca_cert,
        server_cert=pki.server_cert, server_key=pki.server_key,
        client_cert=pki.client_cert, client_key=pki.client_key,
        mtls=False, timeout=10, handshake_timeout=5.0, max_clients=10,
        max_concurrent_handshakes=8, require_hybrid=False,
        hybrid_group="X25519MLKEM768", openssl_bin="openssl",
        log_payloads=True, poll_interval=30,
    )

    warnings = settings.validate()

    assert any("LOG_PAYLOADS" in warning for warning in warnings)


def test_redacted_settings_never_include_key_material(pki):
    """Config logging must show paths, never contents."""
    from protocols.tls.settings import TlsSettings

    settings = TlsSettings(
        enabled=True, host="127.0.0.1", port=8443, server_hostname="localhost",
        bind_host="127.0.0.1", cert_dir=pki.cert_dir, ca_cert=pki.ca_cert,
        server_cert=pki.server_cert, server_key=pki.server_key,
        client_cert=pki.client_cert, client_key=pki.client_key,
        mtls=False, timeout=10, handshake_timeout=5.0, max_clients=10,
        max_concurrent_handshakes=8, require_hybrid=False,
        hybrid_group="X25519MLKEM768", openssl_bin="openssl",
        log_payloads=False, poll_interval=30,
    )

    rendered = str(settings.redacted())

    assert settings.server_key in rendered            # the path is useful
    assert "PRIVATE KEY" not in rendered              # the contents are not
    assert "BEGIN" not in rendered


def test_api_error_details_do_not_leak_the_payload(
    api_client, running_server, monkeypatch
):
    """
    A failing handshake must not put the caller's payload into the error body.
    """
    from conftest import free_port
    from protocols.tls import router as tls_router_module
    from protocols.tls.settings import TlsSettings

    server, config = running_server()
    settings = TlsSettings(
        enabled=True, host="127.0.0.1", port=free_port(),   # nothing listening
        server_hostname="localhost", bind_host="127.0.0.1",
        cert_dir=config.cert_dir, ca_cert=config.ca_cert,
        server_cert=config.server_cert, server_key=config.server_key,
        client_cert=config.client_cert, client_key=config.client_key,
        mtls=False, timeout=3, handshake_timeout=2.0, max_clients=10,
        max_concurrent_handshakes=8, require_hybrid=False,
        hybrid_group="X25519MLKEM768", openssl_bin="openssl",
        log_payloads=False, poll_interval=30,
    )
    monkeypatch.setattr(tls_router_module, "get_tls_settings", lambda: settings)

    response = api_client.post("/api/tls/test-connection", json={"message": SECRET})

    assert response.status_code == 503
    assert SECRET not in response.text
