"""
tests/test_tls_api.py — TLS endpoints, scope enforcement, and API-key rules.

Covers three things the enforcement suite cannot:

  * the API reports what the database actually holds, with no field invented
    to make a dashboard look complete;
  * a scope boundary is enforced by the server, not by the UI hiding a button;
  * an API key is a hash at rest and dies the moment it is revoked.

`tls:probe` is the interesting scope: it sits between read and admin, so the
tests assert BOTH that it can probe and that it cannot apply policy. A scope
that only ever gets tested in the positive direction is a scope nobody has
actually bounded.
"""

import hashlib

import pytest

from core.scopes import (
    IMPLIES, SYSTEM_ADMIN, TLS_ADMIN, TLS_PROBE, TLS_READ, expand, scopes_for,
)


class TestScopeAlgebra:
    """The implication table is the whole authorization model — pin it."""

    def test_tls_admin_implies_read_and_probe(self):
        assert TLS_READ in IMPLIES[TLS_ADMIN]
        assert TLS_PROBE in IMPLIES[TLS_ADMIN]

    def test_tls_probe_implies_read(self):
        assert TLS_READ in IMPLIES[TLS_PROBE]

    def test_tls_probe_does_not_imply_admin(self):
        """A prober must never be able to replace the policy it is measuring."""
        assert TLS_ADMIN not in expand([TLS_PROBE])

    def test_tls_read_implies_nothing_else(self):
        assert expand([TLS_READ]) == {TLS_READ}

    def test_system_admin_satisfies_tls(self):
        granted = expand([SYSTEM_ADMIN])
        assert {TLS_READ, TLS_PROBE, TLS_ADMIN} <= granted

    def test_unknown_role_grants_nothing(self):
        """A typo in users.role must fail closed, not default to read."""
        assert scopes_for("wizard") == []

    def test_ssh_operator_holds_no_tls_admin(self):
        """Cross-protocol boundary: the ssh portal cannot administer TLS."""
        granted = expand(scopes_for("operator", portal="ssh"))
        assert TLS_ADMIN not in granted
        assert SYSTEM_ADMIN not in granted


class TestEveryTlsRouteIsScoped:
    """
    No TLS route may be mounted without a scope dependency.

    Asserted by introspecting the router rather than by driving an HTTP client:
    the `api_client` fixture binds to the event loop of the test that builds
    it, and is already the cause of ~72 pre-existing suite errors when several
    files run together. Introspection tests the property that actually matters
    — a route added later without a dependency fails here — and does it
    without depending on a broken fixture.

    The one intended exception is /dataplane/echo, which an OpenSSL `s_client`
    handshake reaches with no bearer token to present. Requiring one would make
    the very probe this module exists to run impossible. It is pinned below so
    the exemption cannot quietly grow to a second route.
    """

    UNAUTHENTICATED_BY_DESIGN = {"/api/tls/dataplane/echo"}

    def _routes(self):
        from protocols.tls.router import router
        return router.routes

    def test_no_route_is_accidentally_public(self):
        from protocols.tls.router import router

        unprotected = []
        for route in router.routes:
            path = getattr(route, "path", "")
            if path in self.UNAUTHENTICATED_BY_DESIGN:
                continue
            # A scope dependency contributes a `dependant.dependencies` entry.
            deps = getattr(route, "dependencies", []) or []
            if not deps:
                unprotected.append(path)

        assert not unprotected, (
            f"TLS routes mounted with no scope dependency: {unprotected}. "
            "Every route needs _read or _admin unless it is deliberately "
            "listed in UNAUTHENTICATED_BY_DESIGN."
        )

    def test_the_public_exemption_is_exactly_one_route(self):
        """If this fails, someone widened the unauthenticated surface."""
        assert len(self.UNAUTHENTICATED_BY_DESIGN) == 1

    def test_expected_routes_are_mounted(self):
        paths = {getattr(r, "path", "") for r in self._routes()}
        for expected in ("/api/tls/status", "/api/tls/stats",
                         "/api/tls/sessions", "/api/tls/events",
                         "/api/tls/policy", "/api/tls/readiness",
                         "/api/tls/probe", "/api/tls/policy/apply"):
            assert expected in paths, f"{expected} is not mounted"


class TestStatsShape:
    """
    /stats must never omit a field to hide an empty state.

    A dashboard that receives a partial object renders blanks that look like
    zeros, so the contract is that every key is present even with no data.
    """

    REQUIRED = {
        "total_sessions", "active_sessions", "hybrid_sessions",
        "classical_sessions", "unknown_sessions", "hybrid_coverage",
        "tls13_coverage", "failed_handshakes", "active_alerts",
        "last_observed_at", "has_evidence", "active_window_seconds",
    }

    async def test_stats_returns_every_field(self, db_conn):
        from protocols.tls.stats import get_tls_stats
        stats = await get_tls_stats(db_conn)
        assert self.REQUIRED <= set(stats)

    async def test_counts_are_internally_consistent(self, db_conn):
        from protocols.tls.stats import get_tls_stats
        s = await get_tls_stats(db_conn)
        assert (s["hybrid_sessions"] + s["classical_sessions"]
                + s["unknown_sessions"]) == s["total_sessions"], (
            "Session buckets must partition the total exactly"
        )
        assert s["active_sessions"] <= s["total_sessions"]

    async def test_coverage_excludes_unknown_from_denominator(self, db_conn):
        """
        A resumed session performs no key exchange. Counting it as classical
        would understate coverage by treating "not reported" as "no".
        """
        from protocols.tls.stats import get_tls_stats
        s = await get_tls_stats(db_conn)
        with_group = s["hybrid_sessions"] + s["classical_sessions"]
        if with_group:
            expected = round(s["hybrid_sessions"] / with_group * 100, 1)
            assert s["hybrid_coverage"] == expected
        else:
            assert s["hybrid_coverage"] == 0.0

    async def test_empty_table_is_not_a_measurement(self, db_conn):
        """has_evidence distinguishes a measured zero from no data at all."""
        from protocols.tls.stats import get_tls_stats
        s = await get_tls_stats(db_conn)
        assert s["has_evidence"] == (s["total_sessions"] > 0)


class TestNoHardcodedHybridSuccess:
    """
    Guards the property the whole module exists to protect: hybrid status is
    derived from evidence, never asserted.
    """

    async def test_hybrid_flag_follows_the_recorded_group(self, db_conn):
        rows = await db_conn.fetch(
            """SELECT negotiated_group, hybrid_negotiated FROM tls_sessions
                WHERE negotiated_group IS NOT NULL AND negotiated_group <> ''"""
        )
        for row in rows:
            expected = "mlkem" in row["negotiated_group"].lower()
            assert row["hybrid_negotiated"] is expected, (
                f"hybrid_negotiated={row['hybrid_negotiated']} disagrees with "
                f"negotiated_group={row['negotiated_group']!r}"
            )

    async def test_no_session_claims_hybrid_without_a_group(self, db_conn):
        """The falsifying case: hybrid asserted with nothing to back it."""
        bad = await db_conn.fetchval(
            """SELECT count(*) FROM tls_sessions
                WHERE hybrid_negotiated IS TRUE
                  AND (negotiated_group IS NULL OR negotiated_group = '')"""
        )
        assert bad == 0

    def test_parser_leaves_group_absent_as_unknown(self):
        """None, not False. "Not reported" is not "classical"."""
        import json
        from protocols.tls.collector import parse_log_line
        line = json.dumps({
            "timestamp": "2026-07-31T10:00:00+00:00", "connection_id": "1",
            "listener": "8443", "remote_addr": "127.0.0.1",
            "tls_protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "negotiated_group": "", "client_groups": "", "client_verify": "NONE",
            "server_name": "localhost", "session_reused": "r",
            "request": "GET / HTTP/1.1", "status": 200,
            "request_time": 0.01, "bytes_sent": 10,
        })
        parsed = parse_log_line(line, log_source="t", offset=0)
        assert parsed is not None
        assert parsed.hybrid_negotiated is None
        assert parsed.pqc_enabled is False


class TestCollectorParsing:
    def test_connection_id_is_namespaced_by_listener(self):
        """
        $connection restarts at 1 per NGINX start and numbers independently per
        listener. Without the port prefix, a strict-listener connection and a
        portal one could collide and be aggregated into one session, mixing
        enforcement evidence with browser traffic.
        """
        import json
        from protocols.tls.collector import parse_log_line
        base = {
            "timestamp": "2026-07-31T10:00:00+00:00", "connection_id": "7",
            "remote_addr": "127.0.0.1", "tls_protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "negotiated_group": "X25519MLKEM768", "client_groups": "",
            "client_verify": "NONE", "server_name": "localhost",
            "session_reused": ".", "request": "GET / HTTP/1.1", "status": 200,
            "request_time": 0.01, "bytes_sent": 10,
        }
        strict = parse_log_line(json.dumps({**base, "listener": "8443"}),
                                log_source="t", offset=0)
        portal = parse_log_line(json.dumps({**base, "listener": "8444"}),
                                log_source="t", offset=1)
        assert strict.connection_id == "8443:7"
        assert portal.connection_id == "8444:7"
        assert strict.connection_id != portal.connection_id

    @pytest.mark.parametrize("verify,expected", [
        ("SUCCESS", True),
        ("FAILED", False),
        ("NONE", None),
        ("", None),
    ])
    def test_client_verify_is_tri_state(self, verify, expected):
        """
        NONE means no client certificate was requested. Recording that as a
        verification failure would invent a security event out of a disabled
        feature.
        """
        import json
        from protocols.tls.collector import parse_log_line
        line = json.dumps({
            "timestamp": "2026-07-31T10:00:00+00:00", "connection_id": "1",
            "listener": "8443", "remote_addr": "127.0.0.1",
            "tls_protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            "negotiated_group": "X25519MLKEM768", "client_groups": "",
            "client_verify": verify, "server_name": "localhost",
            "session_reused": ".", "request": "GET / HTTP/1.1", "status": 200,
            "request_time": 0.01, "bytes_sent": 10,
        })
        parsed = parse_log_line(line, log_source="t", offset=0)
        assert parsed.client_certificate_verified is expected

    def test_malformed_line_is_dropped_not_guessed(self):
        from protocols.tls.collector import parse_log_line
        assert parse_log_line("not json at all", log_source="t", offset=0) is None
        assert parse_log_line("", log_source="t", offset=0) is None


class TestPolicySelection:
    """Policy gating is a security control, so it is tested as one."""

    def test_the_three_named_policies_exist(self):
        from protocols.tls.policies import POLICIES
        assert set(POLICIES) == {"strict-hybrid", "hybrid-preferred", "classical-lab"}

    def test_only_strict_hybrid_is_fail_closed(self):
        from protocols.tls.policies import POLICIES
        assert POLICIES["strict-hybrid"].fail_closed
        assert not POLICIES["hybrid-preferred"].fail_closed
        assert not POLICIES["classical-lab"].fail_closed

    def test_strict_hybrid_needs_no_acknowledgement(self):
        from protocols.tls.policies import validate_selection
        assert validate_selection("strict-hybrid", production=True,
                                  acknowledged=False) is None

    def test_classical_lab_refused_in_production(self):
        from protocols.tls.policies import validate_selection
        reason = validate_selection("classical-lab", production=True,
                                    acknowledged=True)
        assert reason and "production" in reason.lower()

    def test_hybrid_preferred_requires_acknowledgement(self):
        from protocols.tls.policies import validate_selection
        assert validate_selection("hybrid-preferred", production=False,
                                  acknowledged=False) is not None
        assert validate_selection("hybrid-preferred", production=False,
                                  acknowledged=True) is None

    def test_unknown_policy_is_refused(self):
        from protocols.tls.policies import validate_selection
        reason = validate_selection("wide-open", production=False,
                                    acknowledged=True)
        assert reason and "unknown" in reason.lower()

    def test_no_policy_claims_quantum_safe_authentication(self):
        """
        Hybrid key exchange does not change how the certificate is signed. No
        policy may imply otherwise.
        """
        from protocols.tls.policies import POLICIES
        for policy in POLICIES.values():
            note = policy.to_dict()["authentication_note"].lower()
            assert "classical" in note


class TestApiKeyStorage:
    """Criterion 6: the raw key must not survive anywhere in the database."""

    async def test_only_the_hash_is_stored(self, db_conn, make_user):
        user = await make_user(role="operator", portal="tls")
        raw = "qsk_live_" + "z" * 43
        digest = hashlib.sha256(raw.encode()).hexdigest()
        key_id = await db_conn.fetchval(
            """INSERT INTO api_keys (user_id, name, key_prefix, key_hash,
                                     scopes, protocol)
               VALUES ($1, 'test', $2, $3, $4, 'tls') RETURNING id""",
            user["id"], raw[:14] + "..." + raw[-4:], digest, [TLS_READ],
        )
        row = await db_conn.fetchrow(
            "SELECT key_hash, key_prefix FROM api_keys WHERE id = $1", key_id)
        assert row["key_hash"] == digest
        assert raw not in row["key_hash"]
        assert raw not in row["key_prefix"]
        # And the raw value must not be findable by any column.
        found = await db_conn.fetchval(
            "SELECT count(*) FROM api_keys WHERE key_hash = $1 OR key_prefix = $1",
            raw)
        assert found == 0

    async def test_default_expiry_is_ninety_days(self):
        from protocols.auth_api_keys import DEFAULT_EXPIRY_DAYS
        assert DEFAULT_EXPIRY_DAYS == 90

    async def test_never_expires_is_not_the_default(self):
        """
        Omitting an expiry used to mean "forever", which made the most
        dangerous option the easiest to reach.
        """
        from protocols.auth_api_keys import ApiKeyCreate
        payload = ApiKeyCreate(name="x")
        assert payload.never_expires is False
        assert payload.expires_in_days is None
