"""
protocols/tls/stats.py — aggregates over observed TLS sessions.

Every number here is a count or a percentile over rows in `tls_sessions`, and
every row in that table came from a line NGINX wrote. Nothing is derived from
configuration, and an empty table yields zeros rather than a placeholder.

Two naming points, because the field names are load-bearing:

  request_time_ms_*   percentiles over NGINX `$request_time`, which spans the
                      whole request — handshake plus HTTP exchange. It is NOT a
                      handshake timing, and is not named as if it were.

  pqc_coverage        the share of observed sessions whose recorded
                      `negotiated_group` was hybrid, per collector.classify_group.
                      It says the group was observed, never that it was enforced.
"""

from typing import Any, Dict

import asyncpg


async def get_tls_stats(conn: asyncpg.Connection) -> Dict[str, Any]:
    """Counts and percentiles over every session the collector has recorded."""
    row = await conn.fetchrow(
        """
        SELECT
            COUNT(*)                                            AS total_observations,
            COUNT(*) FILTER (WHERE http_status <  400)          AS successful,
            COUNT(*) FILTER (WHERE http_status >= 400)          AS failed,
            COUNT(*) FILTER (WHERE http_status IS NULL)         AS unrecorded,
            COUNT(*) FILTER (WHERE http_status >= 400
                               AND http_status <  500)          AS client_error,
            COUNT(*) FILTER (WHERE http_status >= 500)          AS server_error,
            COUNT(*) FILTER (WHERE pqc_enabled)                 AS pqc_observations,
            COUNT(*) FILTER (WHERE session_reused)              AS sessions_reused,
            percentile_cont(0.5)  WITHIN GROUP (ORDER BY request_time) AS p50,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY request_time) AS p95
        FROM tls_sessions
        """
    )

    total = row["total_observations"] or 0
    pqc = row["pqc_observations"] or 0

    # Only non-zero buckets are returned: a bucket of 0 is noise in the UI, and
    # the totals above already say how many observations exist.
    outcomes = {
        name: count
        for name, count in (
            ("success", row["successful"] or 0),
            ("client_error", row["client_error"] or 0),
            ("server_error", row["server_error"] or 0),
            ("unrecorded", row["unrecorded"] or 0),
        )
        if count
    }

    return {
        "total_observations": total,
        "successful": row["successful"] or 0,
        "failed": row["failed"] or 0,
        # Logged without an HTTP status. Counted separately rather than folded
        # into `failed`, which would assert a failure the log does not record.
        "unrecorded": row["unrecorded"] or 0,
        "sessions_reused": row["sessions_reused"] or 0,
        "pqc_observations": pqc,
        "pqc_coverage": round(pqc / total * 100, 1) if total else 0.0,
        "request_time_ms_p50": round(row["p50"] * 1000, 2) if row["p50"] is not None else None,
        "request_time_ms_p95": round(row["p95"] * 1000, 2) if row["p95"] is not None else None,
        "outcomes": outcomes,
    }
