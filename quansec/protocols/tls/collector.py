"""
protocols/tls/collector.py — reads real NGINX TLS access logs into PostgreSQL.

Follows the protocol module contract: `collect_once(pool)` does one cycle,
`collect_loop()` runs forever. It is the TLS equivalent of the IPsec VICI poller
and the SSH `ss`/journald reader — the difference is only where the truth lives.

**This module never invents a session.** Every row in `tls_sessions` comes from a
line NGINX wrote, and each row carries the log path and byte offset it came from,
so any record can be traced back to its source. If the log is empty, the table
stays empty; that is a measurement, not a gap to be filled in.

`negotiated_group` is stored exactly as `$ssl_curve` reported it. NGINX leaves
that field empty for a resumed session, which performs no key exchange — such a
row is stored with NULL and `pqc_enabled = false`, because "not reported" is not
the same as "classical" and neither is evidence of post-quantum protection.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import asyncpg

from .settings import TlsConfigurationError, TlsSettings, get_tls_settings

logger = logging.getLogger("quansec.tls.collector")

# Groups that constitute post-quantum key establishment. Membership is decided
# here, from the name NGINX reported — never from configuration. An unknown name
# is classical until it is added to this table deliberately.
PQC_GROUPS: Dict[str, str] = {
    "x25519mlkem768": "ML-KEM-768 + X25519",
    "secp256r1mlkem768": "ML-KEM-768 + P-256",
    "secp384r1mlkem1024": "ML-KEM-1024 + P-384",
    "mlkem512": "ML-KEM-512",
    "mlkem768": "ML-KEM-768",
    "mlkem1024": "ML-KEM-1024",
    "x25519kyber768draft00": "Kyber768 + X25519 (pre-standard)",
}

CLASSICAL_GROUPS: Dict[str, str] = {
    "x25519": "X25519 (classical)",
    "prime256v1": "ECDH P-256 (classical)",
    "secp256r1": "ECDH P-256 (classical)",
    "secp384r1": "ECDH P-384 (classical)",
    "secp521r1": "ECDH P-521 (classical)",
    "x448": "X448 (classical)",
}

_QUIET_AFTER = 5


def classify_group(group: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Classify a group name from the log into (pqc_enabled, kem_label).

    An empty or missing value returns (False, None): NGINX did not report a
    group, which is not evidence of anything. An unrecognised name that contains
    a known PQ KEM marker is treated as post-quantum, matching how the SSH
    collector handles unfamiliar KEX names.
    """
    if not group or not group.strip() or group.strip() in (".", "-"):
        return False, None

    key = group.strip().lower()
    if key in PQC_GROUPS:
        return True, PQC_GROUPS[key]
    if key in CLASSICAL_GROUPS:
        return False, CLASSICAL_GROUPS[key]
    if "mlkem" in key or "ml-kem" in key or "kyber" in key:
        return True, group.strip()
    return False, group.strip()


@dataclass
class ParsedSession:
    """One NGINX access-log line, parsed and classified."""

    occurred_at: datetime
    remote_addr: Optional[str]
    remote_port: Optional[str]
    tls_protocol: Optional[str]
    cipher: Optional[str]
    negotiated_group: Optional[str]
    client_groups: Optional[str]
    client_verify: Optional[str]
    client_s_dn: Optional[str]
    server_name: Optional[str]
    session_reused: bool
    http_status: Optional[int]
    request_time: Optional[float]
    bytes_sent: Optional[int]
    request_line: Optional[str]
    pqc_enabled: bool
    kem_label: Optional[str]
    log_source: str
    log_offset: int
    raw_line: str


def parse_log_line(line: str, *, log_source: str, offset: int) -> Optional[ParsedSession]:
    """
    Parse one JSON access-log line. Returns None if it is not usable.

    Malformed lines are skipped rather than guessed at: a partially-written line
    (the collector can read while NGINX is mid-write) must not become a session
    record with invented fields.
    """
    stripped = line.strip()
    if not stripped:
        return None

    try:
        record = json.loads(stripped)
    except ValueError:
        logger.debug("Skipping unparseable log line at offset %d", offset)
        return None
    if not isinstance(record, dict):
        return None

    timestamp = record.get("timestamp")
    try:
        occurred_at = datetime.fromisoformat(timestamp) if timestamp else None
    except (TypeError, ValueError):
        occurred_at = None
    if occurred_at is None:
        logger.debug("Skipping log line with no usable timestamp at offset %d", offset)
        return None

    group = _clean(record.get("negotiated_group"))
    pqc_enabled, kem_label = classify_group(group)

    return ParsedSession(
        occurred_at=occurred_at,
        remote_addr=_clean(record.get("remote_addr")),
        remote_port=_clean(record.get("remote_port")),
        tls_protocol=_clean(record.get("tls_protocol")),
        cipher=_clean(record.get("cipher")),
        negotiated_group=group,
        client_groups=_clean(record.get("client_groups")),
        client_verify=_clean(record.get("client_verify")),
        client_s_dn=_clean(record.get("client_s_dn")),
        server_name=_clean(record.get("server_name")),
        # NGINX logs "." for a fresh handshake and "r" for a resumed session.
        session_reused=str(record.get("session_reused", "")).strip().lower() == "r",
        http_status=_as_int(record.get("status")),
        request_time=_as_float(record.get("request_time")),
        bytes_sent=_as_int(record.get("bytes_sent")),
        request_line=_clean(record.get("request")),
        pqc_enabled=pqc_enabled,
        kem_label=kem_label,
        log_source=log_source,
        log_offset=offset,
        raw_line=stripped[:4000],
    )


class NginxLogReader:
    """
    Byte-offset tailer for the NGINX access log.

    Keeps the offset in the database rather than in memory, so a backend restart
    does not re-import the whole log or silently skip what arrived while it was
    down. Rotation is detected by the file shrinking below the stored offset.
    """

    def __init__(self, path: str):
        self.path = path

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def read_from(self, offset: int) -> Tuple[List[Tuple[int, str]], int]:
        """
        Read complete lines from `offset`. Returns (lines, new_offset).

        A trailing partial line is left unread: its offset is not advanced, so it
        is picked up whole on the next cycle instead of being parsed truncated.
        """
        if not os.path.isfile(self.path):
            return [], offset

        size = self.size()
        if size < offset:
            logger.info("Access log shrank (%d < %d) - assuming rotation, restarting at 0",
                        size, offset)
            offset = 0
        if size == offset:
            return [], offset

        lines: List[Tuple[int, str]] = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                data = handle.read()
        except OSError as exc:
            logger.warning("Could not read %s: %s", self.path, exc)
            return [], offset

        position = offset
        *complete, trailing = data.split("\n")
        for line in complete:
            lines.append((position, line))
            position += len(line.encode("utf-8")) + 1

        # `trailing` is whatever followed the last newline — possibly a partial
        # write. Leave the offset before it.
        return lines, position


# ── Offset persistence ───────────────────────────────────────────────────────

_OFFSET_TABLE = """
CREATE TABLE IF NOT EXISTS tls_collector_state (
    log_source  TEXT PRIMARY KEY,
    log_offset  BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def _read_offset(conn: asyncpg.Connection, log_source: str) -> int:
    await conn.execute(_OFFSET_TABLE)
    value = await conn.fetchval(
        "SELECT log_offset FROM tls_collector_state WHERE log_source = $1", log_source
    )
    return int(value or 0)


async def _write_offset(conn: asyncpg.Connection, log_source: str, offset: int) -> None:
    await conn.execute(
        """INSERT INTO tls_collector_state (log_source, log_offset, updated_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (log_source) DO UPDATE
           SET log_offset = EXCLUDED.log_offset, updated_at = NOW()""",
        log_source, offset,
    )


async def insert_sessions(conn: asyncpg.Connection,
                          sessions: List[ParsedSession]) -> int:
    """
    Persist parsed sessions. Returns how many rows were newly inserted.

    ON CONFLICT DO NOTHING on (log_source, log_offset) makes re-reading a range
    harmless, which matters because a crash between insert and offset-commit
    would otherwise duplicate rows.
    """
    inserted = 0
    for s in sessions:
        result = await conn.execute(
            """INSERT INTO tls_sessions (
                   occurred_at, remote_addr, remote_port, tls_protocol, cipher,
                   negotiated_group, client_groups, client_verify, client_s_dn,
                   server_name, session_reused, http_status, request_time,
                   bytes_sent, request_line, pqc_enabled, kem_label,
                   log_source, log_offset, raw_line
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
               ON CONFLICT (log_source, log_offset) DO NOTHING""",
            s.occurred_at, s.remote_addr, s.remote_port, s.tls_protocol, s.cipher,
            s.negotiated_group, s.client_groups, s.client_verify, s.client_s_dn,
            s.server_name, s.session_reused, s.http_status, s.request_time,
            s.bytes_sent, s.request_line, s.pqc_enabled, s.kem_label,
            s.log_source, s.log_offset, s.raw_line,
        )
        if result.endswith(" 1"):
            inserted += 1
    return inserted


async def record_event(conn: asyncpg.Connection, event_type: str, summary: str,
                       *, severity: str = "info",
                       detail: Optional[Dict[str, Any]] = None) -> None:
    """Append to tls_events."""
    await conn.execute(
        """INSERT INTO tls_events (event_type, severity, summary, detail)
           VALUES ($1, $2, $3, $4::jsonb)""",
        event_type, severity, summary, json.dumps(detail or {}),
    )


async def collect_once(pool: asyncpg.Pool,
                       settings: Optional[TlsSettings] = None) -> int:
    """
    One collection cycle. Returns the number of new sessions recorded.

    Returns 0 when the module is disabled, the log is absent, or nothing new has
    been written — all of which are ordinary states, not errors.
    """
    settings = settings or get_tls_settings()
    if not settings.enabled:
        return 0

    reader = NginxLogReader(settings.access_log)
    if not os.path.isfile(settings.access_log):
        return 0

    async with pool.acquire() as conn:
        offset = await _read_offset(conn, settings.access_log)
        raw_lines, new_offset = reader.read_from(offset)
        if not raw_lines:
            if new_offset != offset:
                await _write_offset(conn, settings.access_log, new_offset)
            return 0

        parsed = [
            session for position, line in raw_lines
            if (session := parse_log_line(line, log_source=settings.access_log,
                                          offset=position)) is not None
        ]
        skipped = len(raw_lines) - len(parsed)
        if skipped:
            logger.debug("Skipped %d unparseable log line(s)", skipped)

        inserted = await insert_sessions(conn, parsed) if parsed else 0
        await _write_offset(conn, settings.access_log, new_offset)

    if inserted:
        logger.info("Recorded %d TLS session(s) from %s", inserted, settings.access_log)
    return inserted


async def collect_loop() -> None:
    """Background task registered by main.py. Never raises."""
    from core.database import get_pool

    settings = get_tls_settings()
    if not settings.enabled:
        logger.info("TLS collector not started (QUANSEC_TLS_ENABLED=false)")
        return

    pool = await get_pool()
    interval = settings.poll_interval
    logger.info("TLS collector started - tailing %s every %ss",
                settings.access_log, interval)

    consecutive_errors = 0
    warned_missing = False

    while True:
        try:
            if not os.path.isfile(settings.access_log):
                if not warned_missing:
                    logger.warning(
                        "TLS access log %s does not exist yet - start the data "
                        "plane with scripts/start-pqc-tls.sh", settings.access_log
                    )
                    warned_missing = True
            else:
                warned_missing = False
                await collect_once(pool, settings)
            consecutive_errors = 0
        except asyncio.CancelledError:
            logger.info("TLS collector stopping")
            raise
        except Exception as exc:            # noqa: BLE001 - a collector must not die
            consecutive_errors += 1
            if consecutive_errors <= _QUIET_AFTER:
                logger.error("TLS collector error: %s", exc)
            elif consecutive_errors == _QUIET_AFTER + 1:
                logger.error("TLS collector still failing; suppressing further errors")

        await asyncio.sleep(interval)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _clean(value: Any) -> Optional[str]:
    """Normalise an NGINX log field. '-' and '' both mean 'not present'."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
