"""
events.py — real-time IPsec lifecycle event capture via VICI event subscription.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import asyncpg
import redis.asyncio as aioredis

from core.config import settings
from core.database import get_pool

logger = logging.getLogger("quansec.ipsec.events")

INSERT_EVENT = """
INSERT INTO ipsec_events (tunnel_name, event_type, detail)
VALUES ($1, $2, $3)
"""


def _decode(val):
    if isinstance(val, bytes):
        return val.decode(errors="replace")
    if isinstance(val, dict):
        return {_decode(k): _decode(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_decode(i) for i in val]
    return val


def _classify_ike_event(msg: dict):
    up = msg.get("up") == "yes"
    ike_name = None
    ike_data = {}
    for k, v in msg.items():
        if isinstance(v, dict) and ("state" in v or "local-host" in v):
            ike_name = k
            ike_data = v
            break
    if not ike_name:
        ike_name = "unknown"
    state = ike_data.get("state", "").upper()
    if up:
        event_type = "ESTABLISHED" if state == "ESTABLISHED" else "IKE_SA_INIT"
    else:
        event_type = "DOWN"
    dh = ike_data.get("dh-group", "")
    detail = {
        "stage": event_type,
        "local_host": ike_data.get("local-host"),
        "remote_host": ike_data.get("remote-host"),
        "encr_alg": ike_data.get("encr-alg", ""),
        "integ_alg": ike_data.get("integ-alg", ""),
        "key_exchange": dh,
        "pqc": "ml_kem" in dh.lower() or "kyber" in dh.lower(),
    }
    return ike_name, event_type, detail


def _classify_child_event(msg: dict):
    up = msg.get("up") == "yes"
    ike_name = None
    ike_data = {}
    for k, v in msg.items():
        if isinstance(v, dict) and ("child-sas" in v or "local-host" in v):
            ike_name = k
            ike_data = v
            break
    child_name = "net"
    esp = ""
    child_sas = ike_data.get("child-sas", {}) if ike_data else {}
    for cname, cdata in child_sas.items():
        child_name = cname
        if isinstance(cdata, dict):
            esp = f"{cdata.get('encr-alg','')}-{cdata.get('encr-keysize','')}"
        break
    name = f"{ike_name}/{child_name}" if ike_name else child_name
    event_type = "CHILD_UP" if up else "CHILD_DOWN"
    detail = {
        "stage": event_type,
        "esp_proposal": esp,
        "data_channel": "installed" if up else "removed",
    }
    return name, event_type, detail


async def _store_event(pool, redis, tunnel_name, event_type, detail):
    async with pool.acquire() as conn:
        await conn.execute(INSERT_EVENT, tunnel_name, event_type, json.dumps(detail))
    logger.info(f"Lifecycle event: {tunnel_name} -> {event_type}")
    if redis:
        payload = {
            "protocol": "ipsec",
            "kind": "lifecycle",
            "tunnel": tunnel_name,
            "event": event_type,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await redis.publish("quansec:live", json.dumps(payload))
        except Exception:
            pass


def _listen_blocking(socket_path, event_queue, loop):
    import socket as _socket
    import vici
    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.connect(socket_path)
        session = vici.Session(sock)
    except Exception as e:
        logger.warning(f"Event listener could not connect to VICI: {e}")
        return
    events = ["ike-updown", "child-updown", "ike-rekey", "child-rekey"]
    logger.info(f"Subscribed to VICI events: {events}")
    try:
        for label, message in session.listen(events):
            label = label.decode() if isinstance(label, bytes) else label
            decoded = _decode(dict(message))
            asyncio.run_coroutine_threadsafe(
                event_queue.put((label, decoded)), loop
            )
    except Exception as e:
        logger.error(f"Event listener loop error: {e}")


async def event_listen_loop():
    logger.info("IPsec lifecycle event listener starting")
    pool = await get_pool()
    try:
        redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    except Exception:
        redis = None
    event_queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    async def run_listener():
        while True:
            await loop.run_in_executor(
                None, _listen_blocking, settings.VICI_SOCKET, event_queue, loop
            )
            logger.warning("Event listener disconnected, retrying in 5s")
            await asyncio.sleep(5)

    listener_task = asyncio.create_task(run_listener())
    try:
        while True:
            label, message = await event_queue.get()
            try:
                if label in ("ike-updown", "ike-rekey"):
                    name, etype, detail = _classify_ike_event(message)
                elif label in ("child-updown", "child-rekey"):
                    name, etype, detail = _classify_child_event(message)
                else:
                    continue
                await _store_event(pool, redis, name, etype, detail)
            except Exception as e:
                logger.error(f"Failed to process event {label}: {e}")
    except asyncio.CancelledError:
        listener_task.cancel()
        raise
