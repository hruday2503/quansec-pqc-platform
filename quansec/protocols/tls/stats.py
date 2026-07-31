"""
protocols/tls/stats.py — aggregates over observed TLS sessions.

Every number is a count, a percentage of counts, or a timestamp taken from
rows the collector wrote from real NGINX log lines. Nothing is derived from
configuration, and an empty table yields zeros and nulls rather than anything
that reads as a measurement.

Three definitions that are easy to get wrong, so they are pinned here:

  session           One CONNECTION, not one request. NGINX logs a line per
                    request, and a keep-alive connection produces several
                    sharing one $connection id. Counting lines would inflate
                    every total. Rows written before 010 have no connection_id
                    and are counted individually, which is the truthful
                    reading: their connection identity was never recorded.

  failed_handshakes NOT countable from the access log. A refused handshake
                    never reaches the HTTP layer, so NGINX writes no line for
                    it — the absence is the whole point of fail-closed. The
                    only evidence of a failed handshake is a probe that
                    expected to connect and did not, so that is what this
                    counts. An HTTP 5xx is a failed REQUEST on a successful
                    handshake and is deliberately not included.

  hybrid_coverage   Share of sessions WITH A RECORDED GROUP that were hybrid.
                    Sessions whose group NGINX did not report (resumed
                    sessions perform no key exchange) are excluded from the
                    denominator rather than counted as classical, which would
                    understate coverage by treating "unknown" as "no".
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import asyncpg

# A session counts as active if a request on it was logged within this window.
# NGINX has no "connection closed" event in the access log, so liveness can
# only ever be inferred from recency — named here so the UI can say so.
ACTIVE_WINDOW_SECONDS = 300

# Telemetry older than this means the collector or the data plane has stopped.
TELEMETRY_FRESH_SECONDS = 120


async def get_tls_stats(conn: asyncpg.Connection) -> Dict[str, Any]:
    """Counts and coverage over every session the collector has recorded."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ACTIVE_WINDOW_SECONDS)

    # One pass, aggregated per connection. COALESCE gives pre-010 rows their
    # own identity instead of collapsing them all into a single NULL group.
    row = await conn.fetchrow(
        """
        WITH sessions AS (
            SELECT COALESCE(connection_id, 'row:' || id::text) AS sid,
                   bool_or(hybrid_negotiated IS TRUE)          AS is_hybrid,
                   bool_or(negotiated_group IS NOT NULL
                           AND negotiated_group <> '')         AS has_group,
                   bool_or(tls_protocol = 'TLSv1.3')           AS is_tls13,
                   max(COALESCE(last_seen, occurred_at))       AS seen_at
              FROM tls_sessions
             GROUP BY 1
        )
        SELECT
            count(*)                                          AS total_sessions,
            count(*) FILTER (WHERE seen_at >= $1)              AS active_sessions,
            count(*) FILTER (WHERE is_hybrid)                  AS hybrid_sessions,
            count(*) FILTER (WHERE has_group AND NOT is_hybrid) AS classical_sessions,
            count(*) FILTER (WHERE NOT has_group)              AS unknown_sessions,
            count(*) FILTER (WHERE is_tls13)                   AS tls13_sessions,
            max(seen_at)                                       AS last_observed_at
        FROM sessions
        """,
        cutoff,
    )

    total = row["total_sessions"] or 0
    hybrid = row["hybrid_sessions"] or 0
    classical = row["classical_sessions"] or 0
    unknown = row["unknown_sessions"] or 0
    tls13 = row["tls13_sessions"] or 0

    # Denominator excludes sessions with no recorded group. See module docstring.
    with_group = hybrid + classical

    # A handshake that was expected to succeed and did not. Probe evidence is
    # the only place this is observable.
    failed_handshakes = await conn.fetchval(
        """SELECT count(*) FROM tls_probe_results
            WHERE expected_outcome = 'connect' AND actual_outcome <> 'connect'"""
    ) or 0

    active_alerts = await conn.fetchval(
        "SELECT count(*) FROM tls_alerts WHERE acknowledged = FALSE"
    ) or 0

    last_observed: Optional[datetime] = row["last_observed_at"]

    return {
        "total_sessions": total,
        "active_sessions": row["active_sessions"] or 0,
        "hybrid_sessions": hybrid,
        "classical_sessions": classical,
        "unknown_sessions": unknown,
        "hybrid_coverage": round(hybrid / with_group * 100, 1) if with_group else 0.0,
        "tls13_coverage": round(tls13 / total * 100, 1) if total else 0.0,
        "failed_handshakes": failed_handshakes,
        "active_alerts": active_alerts,
        "last_observed_at": last_observed,
        # Stated rather than left implicit: a reader seeing hybrid_coverage of
        # 0.0 needs to know whether that is a measurement or an empty table.
        "has_evidence": total > 0,
        "active_window_seconds": ACTIVE_WINDOW_SECONDS,
    }


async def telemetry_is_fresh(conn: asyncpg.Connection) -> bool:
    """
    Whether the collector has seen anything recently enough to be trusted.

    Stale telemetry is not the same as no traffic, and neither is the same as a
    healthy quiet system — this only reports the timestamp fact, and the caller
    decides what to claim from it.
    """
    last = await conn.fetchval(
        "SELECT max(COALESCE(last_seen, occurred_at)) FROM tls_sessions"
    )
    if last is None:
        return False
    return (datetime.now(timezone.utc) - last).total_seconds() <= TELEMETRY_FRESH_SECONDS
