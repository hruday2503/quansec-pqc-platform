"""
tests/test_tls_persistence.py — what gets written to the database.

The rule under test: `tls_sessions.pqc_enabled` may be TRUE only when a verified
row in `tls_hybrid_evidence` covers the same host, port and group. A successful
handshake is not sufficient, because a successful handshake does not tell you
which key exchange was used.

These are async tests using the db_conn fixture, so each one runs inside a
transaction that is rolled back.
"""

from datetime import datetime, timezone

import pytest

from protocols.tls.adapter import (
    OUTCOME_SUCCESS,
    OUTCOME_UNREACHABLE,
    SessionObservation,
    TlsServiceAdapter,
)
from protocols.tls.collector import (
    latest_verified_evidence,
    record_observation,
    resolve_pqc_enabled,
)
from protocols.tls.settings import TlsSettings

HOST = "127.0.0.1"
PORT = 18443
GROUP = "X25519MLKEM768"


def successful_observation(**overrides) -> SessionObservation:
    base = dict(
        outcome=OUTCOME_SUCCESS,
        success=True,
        server_host=HOST,
        server_port=PORT,
        server_name="localhost",
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        negotiated_group=None,
        negotiated_group_source="unavailable-python-ssl",
        mtls_used=False,
        peer_cert={"cn": "localhost", "issuer_cn": "QUANSEC TLS Development Root CA"},
        cert_verified=True,
        handshake_ms=4.2,
        round_trip_ms=6.1,
        echo_received=True,
    )
    base.update(overrides)
    return SessionObservation(**base)


async def insert_evidence(conn, *, verified: bool, host=HOST, port=PORT, group=GROUP):
    await conn.execute(
        """INSERT INTO tls_hybrid_evidence (
               target_host, target_port, requested_group, negotiated_group,
               verified, method, openssl_version, evidence_line, verified_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
        host, port, group, group if verified else None, verified,
        "openssl-s_client", "OpenSSL 3.5.5 27 Jan 2026",
        f"Negotiated TLS1.3 group: {group}" if verified else "no group negotiated",
        datetime.now(timezone.utc),
    )


# ── 23. Observations are persisted with the observed values ──────────────────

async def test_successful_handshake_is_recorded(db_conn):
    observation = successful_observation()

    row_id = await record_observation(db_conn, observation, pqc_enabled=False)
    row = await db_conn.fetchrow("SELECT * FROM tls_sessions WHERE id = $1", row_id)

    assert row["server_host"] == HOST
    assert row["server_port"] == PORT
    assert row["tls_version"] == "TLSv1.3"
    assert row["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert row["cipher_bits"] == 256
    assert row["cert_verified"] is True
    assert row["peer_cert_cn"] == "localhost"
    assert row["handshake_ms"] == pytest.approx(4.2)
    assert row["outcome"] == "success"
    assert row["source"] == "collector"

    # The group is unobservable, and the row records why rather than leaving a
    # NULL that reads as "no group".
    assert row["named_group"] is None
    assert row["group_source"] == "unavailable-python-ssl"


async def test_failed_handshake_is_also_recorded(db_conn):
    """
    A failure is a measurement. An operator needs to see that the service was
    unreachable, not a gap in the record.
    """
    observation = SessionObservation(
        outcome=OUTCOME_UNREACHABLE,
        success=False,
        server_host=HOST,
        server_port=PORT,
        error_type="TLSConnectionError",
        error="Connection refused",
    )

    row_id = await record_observation(db_conn, observation, pqc_enabled=False)
    row = await db_conn.fetchrow("SELECT * FROM tls_sessions WHERE id = $1", row_id)

    assert row["outcome"] == "unreachable"
    assert row["error_type"] == "TLSConnectionError"
    assert row["pqc_enabled"] is False
    assert row["tls_version"] is None


async def test_outcome_column_rejects_an_unknown_value(db_conn):
    """The CHECK constraint is the last line of defence against invented states."""
    import asyncpg

    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await record_observation(
            db_conn, successful_observation(outcome="totally_fine"), pqc_enabled=False
        )


# ── 24. pqc_enabled requires evidence ────────────────────────────────────────

async def test_pqc_stays_false_without_evidence(db_conn):
    observation = successful_observation()

    assert await resolve_pqc_enabled(db_conn, observation, GROUP) is False

    row_id = await record_observation(
        db_conn, observation,
        pqc_enabled=await resolve_pqc_enabled(db_conn, observation, GROUP),
    )
    row = await db_conn.fetchrow("SELECT pqc_enabled FROM tls_sessions WHERE id = $1", row_id)
    assert row["pqc_enabled"] is False


async def test_pqc_stays_false_with_unverified_evidence(db_conn):
    """An attempt that did not verify must not promote anything."""
    await insert_evidence(db_conn, verified=False)

    assert await latest_verified_evidence(db_conn, HOST, PORT, GROUP) is None
    assert await resolve_pqc_enabled(db_conn, successful_observation(), GROUP) is False


async def test_pqc_becomes_true_only_with_verified_evidence(db_conn):
    await insert_evidence(db_conn, verified=True)

    evidence = await latest_verified_evidence(db_conn, HOST, PORT, GROUP)
    assert evidence is not None
    assert evidence["negotiated_group"] == GROUP
    assert "Negotiated TLS1.3 group" in evidence["evidence_line"]

    assert await resolve_pqc_enabled(db_conn, successful_observation(), GROUP) is True


async def test_evidence_for_a_different_endpoint_does_not_apply(db_conn):
    """
    Evidence is endpoint-scoped. Verifying hybrid against one service says
    nothing about another one on a different port.
    """
    await insert_evidence(db_conn, verified=True, port=PORT + 1)

    assert await latest_verified_evidence(db_conn, HOST, PORT, GROUP) is None
    assert await resolve_pqc_enabled(db_conn, successful_observation(), GROUP) is False


async def test_evidence_for_a_different_group_does_not_apply(db_conn):
    await insert_evidence(db_conn, verified=True, group="SecP256r1MLKEM768")

    assert await latest_verified_evidence(db_conn, HOST, PORT, GROUP) is None
    assert await resolve_pqc_enabled(db_conn, successful_observation(), GROUP) is False


async def test_a_failed_handshake_is_never_pqc_even_with_evidence(db_conn):
    """
    Verified evidence from an earlier check must not make a failed handshake
    count as post-quantum.
    """
    await insert_evidence(db_conn, verified=True)

    failed = SessionObservation(
        outcome=OUTCOME_UNREACHABLE, success=False,
        server_host=HOST, server_port=PORT,
    )
    assert await resolve_pqc_enabled(db_conn, failed, GROUP) is False


async def test_latest_evidence_wins(db_conn):
    """The most recent verified row is the one that counts."""
    await insert_evidence(db_conn, verified=True)
    await db_conn.execute(
        """INSERT INTO tls_hybrid_evidence (
               target_host, target_port, requested_group, negotiated_group,
               verified, method, evidence_line, verified_at
           ) VALUES ($1,$2,$3,$4,TRUE,'openssl-s_client',$5,$6)""",
        HOST, PORT, GROUP, GROUP, "Negotiated TLS1.3 group: X25519MLKEM768 (newer)",
        datetime.now(timezone.utc),
    )

    evidence = await latest_verified_evidence(db_conn, HOST, PORT, GROUP)
    assert "newer" in evidence["evidence_line"]


# ── 25. Scoring reads only recorded observations ─────────────────────────────

async def test_score_tls_handles_an_empty_table(db_conn):
    """With no observations the score is a defined zero, not an exception."""
    from protocols.scoring.router import score_tls

    await db_conn.execute("DELETE FROM tls_sessions")

    result = await score_tls(db_conn)

    assert result["protocol"] == "tls"
    assert result["score"] == 0.0
    assert result["grade"] == "F"
    assert result["observations_evaluated"] == 0
    assert result["factors"]["coverage"] == 0.0


async def test_score_tls_reflects_recorded_observations(db_conn):
    """A successful but non-verified handshake earns a low score, not a zero."""
    from protocols.scoring.router import score_tls

    await db_conn.execute("DELETE FROM tls_sessions")
    for _ in range(3):
        await record_observation(db_conn, successful_observation(), pqc_enabled=False)

    result = await score_tls(db_conn)

    assert result["observations_evaluated"] == 3
    assert result["factors"]["coverage"] == 0.0
    assert result["factors"]["downgrade_resistant"] is False
    assert result["score"] < 50          # no PQC coverage, so no passing grade
    assert result["score"] >= 0


async def test_score_tls_credits_verified_pqc(db_conn):
    """With verified evidence, coverage becomes real and the score rises."""
    from protocols.scoring.router import score_tls

    await db_conn.execute("DELETE FROM tls_sessions")
    await insert_evidence(db_conn, verified=True)
    for _ in range(3):
        observation = successful_observation()
        await record_observation(
            db_conn, observation,
            pqc_enabled=await resolve_pqc_enabled(db_conn, observation, GROUP),
        )

    result = await score_tls(db_conn)

    assert result["factors"]["coverage"] == 100.0
    assert result["score"] > 50


# ── Collector integration against a live service ─────────────────────────────

async def test_collector_records_a_real_handshake(db_conn, running_server, pki):
    """
    End-to-end: a real TLS handshake against a real server, persisted through the
    same code path the background collector uses.
    """
    server, config = running_server(handler=lambda m, s: "ok")

    settings = TlsSettings(
        enabled=True, host=config.host, port=config.port,
        server_hostname="localhost", bind_host="127.0.0.1",
        cert_dir=pki.cert_dir, ca_cert=pki.ca_cert,
        server_cert=pki.server_cert, server_key=pki.server_key,
        client_cert=pki.client_cert, client_key=pki.client_key,
        mtls=False, timeout=5, handshake_timeout=2.0, max_clients=10,
        max_concurrent_handshakes=8, require_hybrid=False,
        hybrid_group=GROUP, openssl_bin="openssl",
        log_payloads=False, poll_interval=30,
    )

    observation = await TlsServiceAdapter(settings).handshake()
    assert observation.success, observation.error

    pqc_enabled = await resolve_pqc_enabled(db_conn, observation, GROUP)
    row_id = await record_observation(db_conn, observation, pqc_enabled=pqc_enabled)

    row = await db_conn.fetchrow("SELECT * FROM tls_sessions WHERE id = $1", row_id)
    assert row["tls_version"] == "TLSv1.3"
    assert row["cert_verified"] is True
    assert row["pqc_enabled"] is False        # no verification evidence exists
    assert row["handshake_ms"] > 0
