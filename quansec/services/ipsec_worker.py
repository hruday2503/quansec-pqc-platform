"""Dedicated, fail-closed StrongSwan telemetry worker."""

import asyncio
import os

from protocols.ipsec.collector import collect_loop
from protocols.ipsec.events import event_listen_loop
from protocols.ipsec.vici_client import ViciClient
from services.runtime import run_worker


def require_vici() -> None:
    socket_path = os.environ.get("VICI_SOCKET", "/var/run/charon.vici")
    if not os.path.exists(socket_path):
        raise RuntimeError(f"real StrongSwan VICI socket is missing: {socket_path}")
    client = ViciClient(socket_path)
    if not client.connect():
        raise RuntimeError(f"cannot connect to StrongSwan VICI socket: {socket_path}")
    version = client.version()
    client.close()
    if not version:
        raise RuntimeError("StrongSwan VICI answered without daemon version data")


async def main() -> None:
    await asyncio.to_thread(require_vici)
    await run_worker(
        "ipsec-collector",
        [
            ("ipsec-poll", collect_loop),
            ("ipsec-events", event_listen_loop),
            ("ipsec-vici-watchdog", dependency_watchdog),
        ],
    )


async def dependency_watchdog() -> None:
    while True:
        await asyncio.sleep(15)
        await asyncio.to_thread(require_vici)


if __name__ == "__main__":
    asyncio.run(main())
