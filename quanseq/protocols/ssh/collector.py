"""
protocols/ssh/collector.py — polls active SSH connections and detects
their key-exchange algorithm, classifying each as PQC (hybrid ML-KEM)
or classical.

Mirrors the IPsec collector pattern: a background task polls every few
seconds, writes connection state into the ssh_connections table, and
lets the API serve it.

Detection strategy:
  1. `ss -tnp` / `who` gives us active sshd sessions (pids, peers).
  2. For the negotiated KEX we read sshd's own logging. When sshd is
     started with `LogLevel DEBUG1`, each connection logs a line like:
        "kex: algorithm: mlkem768x25519-sha256"
     We tail the auth log and map the most recent KEX per connection.
  3. If we can't read a live KEX (log rotated, permission), we fall back
     to the server's *configured* KexAlgorithms from sshd_config so the
     dashboard still reflects the enforced policy.
"""

import asyncio
import logging
import re
import subprocess
from datetime import datetime, timezone

import asyncpg
from core.config import settings

logger = logging.getLogger("quanseq.ssh.collector")

POLL_INTERVAL = settings.SSH_POLL_INTERVAL

# Map known sshd ports to the KEX they enforce.
# 2222 = QUANSEQ PQC sshd (mlkem768x25519). 22 = classical system sshd.
SSH_PORT_KEX = {
    "2222": "mlkem768x25519-sha256",
    "22": "curve25519-sha256",
}

# KEX names that carry a post-quantum KEM. Hybrid names combine a
# classical curve with an ML-KEM (or NTRU Prime) share.
PQC_KEX = {
    "mlkem768x25519-sha256": ("ML-KEM-768 + X25519", "ML-KEM-768", True),
    "mlkem1024x25519-sha256": ("ML-KEM-1024 + X25519", "ML-KEM-1024", True),
    "sntrup761x25519-sha512@openssh.com": ("NTRU Prime + X25519", "sntrup761", True),
    "sntrup761x25519-sha512": ("NTRU Prime + X25519", "sntrup761", True),
}

CLASSICAL_KEX = {
    "curve25519-sha256": ("X25519 (classical)", "X25519", False),
    "curve25519-sha256@libssh.org": ("X25519 (classical)", "X25519", False),
    "ecdh-sha2-nistp256": ("ECDH P-256", "ECDH-P256", False),
    "ecdh-sha2-nistp384": ("ECDH P-384", "ECDH-P384", False),
    "diffie-hellman-group14-sha256": ("DH Group 14", "DH-2048", False),
}

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS ssh_connections (
    id           SERIAL PRIMARY KEY,
    session_key  TEXT UNIQUE NOT NULL,
    local_host   TEXT,
    remote_host  TEXT,
    remote_user  TEXT,
    kex_algorithm TEXT,
    kem_label    TEXT,
    pqc_enabled  BOOLEAN DEFAULT FALSE,
    state        TEXT DEFAULT 'ACTIVE',
    bytes_sent   BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    established_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen    TIMESTAMPTZ DEFAULT NOW()
);
"""


def _classify(kex: str):
    if kex in PQC_KEX:
        label, kem, pqc = PQC_KEX[kex]
    elif kex in CLASSICAL_KEX:
        label, kem, pqc = CLASSICAL_KEX[kex]
    else:
        label, kem, pqc = (kex, kex, "mlkem" in kex.lower() or "sntrup" in kex.lower())
    return label, kem, pqc


def _live_kex_by_peer() -> dict:
    """
    Parse recent sshd DEBUG1 logs to map "ip:port" -> kex algorithm.
    Works when sshd LogLevel is DEBUG1 and journald is readable.
    """
    mapping = {}
    try:
        out = subprocess.run(
            [
                "journalctl",
                "-u",
                "ssh",
                "-u",
                "sshd",
                "-u",
                "quanseq-pqc-sshd.service",
                "--since",
                "-10min",
                "--no-pager",
            ],
            capture_output=True, text=True, timeout=6,
        ).stdout
        cur_peer = None
        for line in out.splitlines():
            m = re.search(r"Connection from (\S+) port (\d+)", line)
            if m:
                cur_peer = f"{m.group(1)}:{m.group(2)}"
            k = re.search(r"kex: algorithm: (\S+)", line)
            if k and cur_peer:
                mapping[cur_peer] = k.group(1)
    except Exception:
        pass
    return mapping



def _read_bytes_by_peer() -> dict:
    """Map 'peer_ip:port' -> (bytes_sent, bytes_received) from ss -ti."""
    result = {}
    try:
        out = subprocess.run(
            ["ss", "-tin", "state", "established"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        lines = out.splitlines()
        cur_peer = None
        for line in lines:
            if line and not line[0].isspace() and ":" in line:
                parts = line.split()
                if len(parts) >= 4:
                    cur_peer = parts[3]
            m_sent = re.search(r"bytes_sent:(\d+)", line)
            m_recv = re.search(r"bytes_received:(\d+)", line)
            if cur_peer and (m_sent or m_recv):
                sent = int(m_sent.group(1)) if m_sent else 0
                recv = int(m_recv.group(1)) if m_recv else 0
                result[cur_peer] = (sent, recv)
    except Exception as e:
        logger.debug(f"ss -ti parse failed: {e}")
    return result

def _active_sessions() -> list[dict]:
    """List active SSH sessions on ports 22/2222, inbound or outbound.
    Tags each with the SSH port so we can map port -> KEX policy."""
    sessions = []
    try:
        out = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for line in out.splitlines():
            if line.startswith("Recv-Q") or "Local Address" in line:
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[2]
            peer = parts[3]
            local_port = local.rsplit(":", 1)[-1]
            peer_port = peer.rsplit(":", 1)[-1]
            ssh_port = None
            if peer_port in SSH_PORT_KEX:
                ssh_port = peer_port
            elif local_port in SSH_PORT_KEX:
                ssh_port = local_port
            if ssh_port is None:
                continue
            sessions.append({"local": local, "peer": peer, "ssh_port": ssh_port})
    except Exception as e:
        logger.debug(f"ss parse failed: {e}")
    return sessions


async def collect_once(pool: asyncpg.Pool):
    kex_map = _live_kex_by_peer()
    bytes_map = _read_bytes_by_peer()
    sessions = _active_sessions()

    async with pool.acquire() as conn:
        await conn.execute(CREATE_TABLE)

        seen_keys = []
        for s in sessions:
            peer = s["peer"]
            # Never report a port-to-policy guess as negotiated evidence. If
            # journald has no matching VERBOSE event, the honest value is
            # unknown even when the daemon configuration advertises PQC.
            kex = kex_map.get(peer) or "unknown"
            label, kem, pqc = _classify(kex)
            session_key = f"{s['local']}->{peer}"
            seen_keys.append(session_key)

            sent, recv = bytes_map.get(peer, (0, 0))
            await conn.execute(
                """
                INSERT INTO ssh_connections
                    (session_key, local_host, remote_host, kex_algorithm, kem_label, pqc_enabled, state, bytes_sent, bytes_received, last_seen)
                VALUES ($1,$2,$3,$4,$5,$6,'ACTIVE',$7,$8,NOW())
                ON CONFLICT (session_key) DO UPDATE SET
                    kex_algorithm = EXCLUDED.kex_algorithm,
                    kem_label = EXCLUDED.kem_label,
                    pqc_enabled = EXCLUDED.pqc_enabled,
                    state = 'ACTIVE',
                    bytes_sent = EXCLUDED.bytes_sent,
                    bytes_received = EXCLUDED.bytes_received,
                    last_seen = NOW()
                """,
                session_key, s["local"], peer, kex, kem, pqc, sent, recv,
            )

        # Mark connections not seen this cycle as CLOSED
        if seen_keys:
            await conn.execute(
                "UPDATE ssh_connections SET state='CLOSED' WHERE session_key <> ALL($1::text[]) AND state='ACTIVE'",
                seen_keys,
            )
        else:
            await conn.execute("UPDATE ssh_connections SET state='CLOSED' WHERE state='ACTIVE'")

        pqc_count = sum(1 for s in sessions if _classify(kex_map.get(s["peer"]) or "unknown")[2])
        logger.info(f"SSH poll: {len(sessions)} sessions, {pqc_count} PQC-enabled")


async def ssh_collector_task(pool: asyncpg.Pool):
    logger.info("SSH collector starting — polling every %ds", POLL_INTERVAL)
    while True:
        try:
            await collect_once(pool)
        except Exception as e:
            logger.error(f"SSH collect error: {e}")
        await asyncio.sleep(POLL_INTERVAL)


async def collect_loop():
    """No-arg entry point matching the IPsec collector pattern.
    Gets the DB pool internally so main.py can call it like ipsec_collect_loop()."""
    from core.database import get_pool
    pool = await get_pool()
    logger.info("SSH collector starting — polling every %ds", POLL_INTERVAL)
    while True:
        try:
            await collect_once(pool)
        except Exception as e:
            logger.error(f"SSH collect error: {e}")
        await asyncio.sleep(POLL_INTERVAL)
