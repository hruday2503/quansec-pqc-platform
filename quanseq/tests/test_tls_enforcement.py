"""
tests/test_tls_enforcement.py — the enforcement matrix, run against the real
data plane with the real runtime OpenSSL.

These are not unit tests and they do not mock anything. Each one opens an
actual TLS connection to the running NGINX listener and asserts on what the
handshake did. That is the only thing that can establish enforcement: a
configuration file saying `Groups X25519MLKEM768` proves nothing about what a
classical client is actually able to negotiate.

The asymmetry matters and is stated in every test name: a NEGATIVE probe
passes when the handshake is REFUSED. A suite where everything "connects" is a
suite that has proven nothing.

Skipped rather than failed when the data plane is not running, because a
missing listener is an environment fact, not a defect in the code under test.
Run the listener with `bash scripts/start-pqc-tls.sh`.
"""

import pytest

from protocols.tls.probe import ENFORCEMENT_PROBES, TlsProber
from protocols.tls.settings import get_tls_settings

pytestmark = pytest.mark.tls_dataplane


@pytest.fixture(scope="module")
def settings():
    s = get_tls_settings()
    if not s.enabled:
        pytest.skip("TLS module disabled (QUANSEQ_TLS_ENABLED=false)")
    if not s.runtime_available():
        pytest.skip(f"PQC runtime not built at {s.runtime_dir}")
    return s


@pytest.fixture(scope="module")
def prober(settings):
    service_up = settings.host and settings.port
    if not service_up:
        pytest.skip("TLS listener not configured")
    p = TlsProber(settings)
    # One cheap positive probe decides whether the listener is up at all. If it
    # is not, every test below would fail for the same uninteresting reason.
    result = p.run("positive_hybrid")
    if result.actual_outcome == "error":
        pytest.skip(
            f"TLS listener unreachable on {settings.host}:{settings.port} — "
            f"start it with scripts/start-pqc-tls.sh ({result.stdout_excerpt})"
        )
    return p


class TestPositiveHandshake:
    """The hybrid group must actually work, or nothing else means anything."""

    def test_hybrid_handshake_connects(self, prober):
        r = prober.run("positive_hybrid")
        assert r.expected_outcome == "connect"
        assert r.actual_outcome == "connect", (
            f"Hybrid handshake failed: {r.stdout_excerpt}"
        )
        assert r.passed

    def test_negotiated_group_is_recorded_and_hybrid(self, prober, settings):
        r = prober.run("positive_hybrid")
        assert r.negotiated_group, "OpenSSL reported no negotiated group"
        assert r.negotiated_group.lower() == settings.hybrid_group.lower(), (
            f"Expected {settings.hybrid_group}, negotiated {r.negotiated_group}"
        )

    def test_handshake_used_tls13(self, prober):
        r = prober.run("positive_hybrid")
        assert r.tls_protocol == "TLSv1.3", f"Negotiated {r.tls_protocol}"

    def test_evidence_names_the_runtime_openssl(self, prober, settings):
        """
        The probe must run with the 3.5.x runtime, not the system OpenSSL.

        Ubuntu ships 3.0.13, which cannot do X25519MLKEM768 at all. A probe
        that silently used it would report a failure that says nothing about
        the server.
        """
        r = prober.run("positive_hybrid")
        assert r.openssl_binary == settings.openssl_bin
        # The recorded value is the full banner, e.g.
        # "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)".
        assert r.openssl_version, "Probe recorded no OpenSSL version"
        assert "OpenSSL 3.5" in r.openssl_version, (
            f"Probe used {r.openssl_version!r}; X25519MLKEM768 needs 3.5+, and "
            "the system OpenSSL 3.0.x cannot negotiate it at all"
        )


class TestNegativeHandshakes:
    """Each of these PASSES when the handshake is refused."""

    @pytest.mark.parametrize("probe_type", [
        "negative_x25519",
        "negative_prime256v1",
        "negative_tls12",
        "negative_aes128",
        "negative_invalid_ca",
    ])
    def test_refused(self, prober, probe_type):
        r = prober.run(probe_type)
        assert r.expected_outcome == "reject"
        assert r.actual_outcome == "reject", (
            f"{probe_type} CONNECTED but should have been refused. "
            f"Negotiated group={r.negotiated_group} protocol={r.tls_protocol}. "
            f"The policy is not fail-closed."
        )
        assert r.passed

    def test_classical_client_gets_no_group(self, prober):
        """A refused handshake negotiates nothing — there is no partial state."""
        r = prober.run("negative_x25519")
        assert not r.negotiated_group


class TestEnforcementVerdict:
    def test_standard_suite_proves_enforcement(self, prober):
        """
        The whole point. hybrid_only_enforced may be claimed only when BOTH
        classical-only clients are refused — one is not enough, because a
        server refusing x25519 while accepting prime256v1 is still downgradable.
        """
        results = [prober.run(name) for name in ENFORCEMENT_PROBES]
        assert len(results) >= 2, "Enforcement needs at least two negative probes"
        failed = [r.probe_type for r in results if not r.passed]
        assert not failed, f"Enforcement NOT proven; these did not refuse: {failed}"

    def test_mtls_probe_is_not_in_the_standard_suite(self):
        """
        negative_missing_client_cert connects when mTLS is off, which is
        correct and must not drag the enforcement verdict down. It is opt-in.
        """
        assert "negative_missing_client_cert" not in ENFORCEMENT_PROBES
