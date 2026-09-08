"""
tests/test_tls_transport.py — the vendored TLS 1.3 transport.

These tests run against a real TLS server on a real socket. Nothing is mocked:
a failure here means the transport genuinely does not do what QUANSEC reports it
does.

Two of them (test_port_is_reusable_immediately_after_stop and
test_slow_handshake_does_not_block_other_clients) are regression tests for
defects in the upstream module. See protocols/tls/tls13/VENDOR.md patches 4 and 5.
"""

import socket
import ssl
import threading
import time

import pytest

from conftest import free_port
from protocols.tls.tls13 import TLSClient, TLSServer
from protocols.tls.tls13.exceptions import (
    CertVerificationError,
    TLSConnectionError,
    TLSHandshakeError,
)
from protocols.tls.tls13.utils import GROUP_SOURCE_UNAVAILABLE


# ── 1. Handshake ─────────────────────────────────────────────────────────────

def test_tls13_handshake_succeeds(running_server):
    server, config = running_server()

    with TLSClient(config) as client:
        session = client.session_info()

    assert session["tls_version"] == "TLSv1.3"
    assert session["cipher_name"].startswith("TLS_")
    assert session["cipher_bits"] >= 128
    assert client.handshake_ms() is not None


def test_session_reports_group_as_unknown_not_as_absent(running_server):
    """
    Python's ssl cannot read the negotiated group. The session must say so
    explicitly rather than leaving a bare None that reads as 'no group'.
    """
    server, config = running_server()

    with TLSClient(config) as client:
        session = client.session_info()

    assert session["negotiated_group"] is None
    assert session["negotiated_group_source"] == GROUP_SOURCE_UNAVAILABLE
    # The configured group is recorded as a request, never as an outcome.
    assert session["hybrid_group_configured"] == config.hybrid_group


# ── 2. Encrypted message exchange ────────────────────────────────────────────

def test_encrypted_message_exchange_round_trips(running_server):
    server, config = running_server(handler=lambda msg, _s: f"Echo: {msg}")

    with TLSClient(config) as client:
        assert client.send("hello quansec") == "Echo: hello quansec"
        assert client.send("second message on the same connection") == (
            "Echo: second message on the same connection"
        )


def test_payload_is_not_readable_on_the_wire(running_server, recording_relay):
    """
    Confirm the transport genuinely encrypts.

    A passive man-in-the-middle records every byte in both directions. The
    plaintext request and the plaintext response must appear nowhere in it.
    """
    secret_request = "TOPSECRETPAYLOAD-request"
    secret_response = "TOPSECRETPAYLOAD-response"

    server, config = running_server(handler=lambda msg, _s: secret_response)
    relay = recording_relay(config.host, config.port)

    client_config = config
    client_config.port = relay.port      # talk to the server through the tap

    with TLSClient(client_config) as client:
        assert client.send(secret_request) == secret_response

    captured = relay.captured()
    assert captured, "the relay recorded nothing, so it proved nothing"
    assert secret_request.encode() not in captured
    assert secret_response.encode() not in captured
    # Sanity check that we really did capture the TLS stream: every TLS record
    # starts with a content type byte, and application data is 0x17.
    assert b"\x17\x03\x03" in captured


# ── 3-4. Certificate verification ────────────────────────────────────────────

def test_certificate_chain_verifies_against_the_ca(running_server, pki):
    server, config = running_server()

    with TLSClient(config) as client:
        cert = client.session_info()["peer_cert"]

    assert cert is not None
    assert cert["cn"] == "localhost"
    assert cert["issuer_cn"] == "QUANSEC TLS Development Root CA"
    assert "DNS:localhost" in cert["san"]
    assert pki.verify(pki.server_cert) is True


def test_hostname_mismatch_is_rejected(running_server):
    """A name absent from the certificate SAN must fail verification."""
    server, config = running_server()
    config.server_hostname = "not-in-the-san.example"

    with pytest.raises(CertVerificationError) as exc:
        TLSClient(config).connect()

    assert "not-in-the-san.example" in str(exc.value)


def test_untrusted_ca_is_rejected(running_server, tmp_path, pki):
    """A client trusting a different CA must refuse the server certificate."""
    from protocols.tls.tls13 import CertManager

    other = CertManager(cert_dir=str(tmp_path / "other-pki"))
    other.generate_ca()

    server, config = running_server()
    config.ca_cert = other.ca_cert

    with pytest.raises(CertVerificationError):
        TLSClient(config).connect()


# ── 5-6. Mutual TLS ──────────────────────────────────────────────────────────

def test_mtls_succeeds_with_a_client_certificate(running_server):
    server, config = running_server(mtls=True, handler=lambda m, s: "authenticated")

    with TLSClient(config) as client:
        assert client.send("hi") == "authenticated"


def test_mtls_rejects_a_client_without_a_certificate(running_server, tls_config):
    """
    The server requires a client certificate; a client that presents none must
    not get an established session.
    """
    server, server_config = running_server(mtls=True)

    # Same endpoint, but the client is configured not to present a certificate.
    client_config = tls_config(port=server_config.port, mtls=False)

    with pytest.raises((TLSHandshakeError, TLSConnectionError)):
        client = TLSClient(client_config)
        client.connect()
        # OpenSSL may defer the rejection to the first read on some versions.
        client.send("should not be delivered")


# ── 7. Version enforcement ───────────────────────────────────────────────────

def test_tls12_is_rejected(running_server):
    """The server is pinned to TLS 1.3; a TLS 1.2-only client must fail."""
    server, config = running_server()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=config.ca_cert)

    raw = socket.create_connection((config.host, config.port), timeout=5)
    with pytest.raises(ssl.SSLError) as exc:
        ctx.wrap_socket(raw, server_hostname="localhost")
    raw.close()

    assert "version" in str(exc.value).lower() or "protocol" in str(exc.value).lower()


# ── 8. Malformed input ───────────────────────────────────────────────────────

def test_malformed_handshake_does_not_take_the_server_down(running_server):
    """Garbage on the port must be dropped without affecting later clients."""
    server, config = running_server(handler=lambda m, s: "still alive")

    for junk in (b"\x00" * 64, b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\xff\xff"):
        raw = socket.create_connection((config.host, config.port), timeout=5)
        try:
            raw.sendall(junk)
            raw.recv(128)
        except OSError:
            pass
        finally:
            raw.close()

    assert server.is_running()
    with TLSClient(config) as client:
        assert client.send("after the garbage") == "still alive"


def test_oversized_and_binary_payloads_are_handled(running_server):
    """Non-UTF-8 bytes and a full-buffer payload must not crash the handler."""
    server, config = running_server(handler=lambda m, s: f"len={len(m)}")

    with TLSClient(config) as client:
        assert client.send("x" * 4000).startswith("len=")
        assert client.send_raw(b"\xff\xfe\xfd binary") != b""

    assert server.is_running()


# ── 9. Shutdown and port reuse ───────────────────────────────────────────────

def test_port_is_reusable_immediately_after_stop(tls_config):
    """
    Regression test for VENDOR.md patch 5.

    Upstream stop() closed the listening socket without joining the accept
    thread, so an immediate rebind could race a thread still inside accept().
    stop() must not return until the listener is genuinely released.
    """
    config = tls_config()

    first = TLSServer(config)
    first.start_background()
    with TLSClient(config) as client:
        client.send("before restart")
    first.stop()

    # No sleep: if stop() is honest, the port is free the instant it returns.
    second = TLSServer(config)
    second.start_background()
    try:
        with TLSClient(config) as client:
            assert client.send("after restart")
    finally:
        second.stop()


def test_stop_is_idempotent(running_server):
    server, _config = running_server()
    server.stop()
    server.stop()
    assert not server.is_running()


def test_start_background_reports_a_bind_failure(tls_config):
    """Two servers on one port: the second must fail loudly, not silently."""
    config = tls_config()

    first = TLSServer(config)
    first.start_background()
    try:
        second = TLSServer(config)
        with pytest.raises(OSError):
            second.start_background()
    finally:
        first.stop()


# ── 10. Slow-handshake isolation ─────────────────────────────────────────────

def test_slow_handshake_does_not_block_other_clients(running_server):
    """
    Regression test for VENDOR.md patch 4 (upstream finding F-03).

    Upstream ran wrap_socket inside the accept loop on a socket with no timeout,
    so a client that completed the TCP connection and then sent nothing stalled
    every subsequent handshake. Handshakes now run in a bounded worker pool with
    a per-connection timeout, so a healthy client is unaffected.
    """
    server, config = running_server(handler=lambda m, s: "responsive")

    # Open TCP and deliberately send no TLS bytes at all.
    stalled = socket.create_connection((config.host, config.port), timeout=5)
    try:
        time.sleep(0.2)   # let the server accept it

        started = time.perf_counter()
        with TLSClient(config) as client:
            assert client.send("ping") == "responsive"
        elapsed = time.perf_counter() - started

        # Must not have waited on the stalled client's handshake timeout.
        assert elapsed < config.handshake_timeout, (
            f"healthy handshake took {elapsed:.2f}s, which suggests it queued "
            f"behind the stalled connection"
        )
    finally:
        stalled.close()


def test_many_concurrent_clients_are_served(running_server):
    """Concurrency is bounded, not broken: every client still gets a response."""
    server, config = running_server(
        handler=lambda m, s: f"ok:{m}", max_clients=20, max_concurrent_handshakes=8
    )

    results = {}
    errors = []

    def worker(index: int):
        try:
            with TLSClient(config) as client:
                results[index] = client.send(str(index))
        except Exception as exc:      # noqa: BLE001 - recorded and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert not errors, f"clients failed: {errors}"
    assert len(results) == 12
    assert all(results[i] == f"ok:{i}" for i in range(12))


# ── Service unavailable ──────────────────────────────────────────────────────

def test_connecting_to_a_dead_service_raises_connection_error(tls_config):
    config = tls_config(port=free_port())   # nothing is listening there

    with pytest.raises(TLSConnectionError) as exc:
        TLSClient(config).connect()

    assert str(config.port) in str(exc.value)
