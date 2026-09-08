"""Dedicated, fail-closed host SSH telemetry worker."""

import asyncio
import os
import shutil
import subprocess

from protocols.ssh.collector import collect_loop
from protocols.ssh.ztaudit import zt_collect_loop
from services.runtime import run_worker


def require_host_ssh_telemetry() -> None:
    auth_log = os.environ.get("QUANSEQ_ZT_LOG", "/host/var/log/auth.log")
    sshd_config = os.environ.get("SSHD_CONFIG", "/opt/openssh-pqc/etc/sshd_config")
    sshd_binary = os.environ.get("SSHD_CONFIG_BINARY", "/opt/openssh-pqc/sbin/sshd")
    if not os.path.isfile(auth_log) or not os.access(auth_log, os.R_OK):
        raise RuntimeError(f"real host SSH audit log is not readable: {auth_log}")
    if not os.path.isdir("/run/log/journal"):
        raise RuntimeError("real host journald directory is not mounted at /run/log/journal")
    if not os.path.isfile(sshd_binary) or not os.path.isfile(sshd_config):
        raise RuntimeError("real /opt/openssh-pqc binary/configuration is not mounted")
    # The host systemd unit validates sshd_config with ExecStartPre.
    # Do not execute a host-linked binary inside a container with a
    # potentially incompatible libc. Verify the live listener instead.
    if not shutil.which("ss"):
        raise RuntimeError("ss is required to inspect real host TCP sessions")
    check = subprocess.run(["ss", "-Hltn"], capture_output=True, text=True, timeout=5)
    if check.returncode:
        raise RuntimeError(f"cannot inspect host network namespace: {check.stderr.strip()}")

    ssh_port = os.environ.get("PQC_SSH_PORT", "2222")
    if f":{ssh_port}" not in check.stdout:
        raise RuntimeError(f"real PQC sshd is not listening on port {ssh_port}")


async def main() -> None:
    await asyncio.to_thread(require_host_ssh_telemetry)
    await run_worker(
        "ssh-collector",
        [
            ("ssh-sessions", collect_loop),
            ("ssh-zero-trust", zt_collect_loop),
            ("ssh-host-watchdog", dependency_watchdog),
        ],
    )


async def dependency_watchdog() -> None:
    while True:
        await asyncio.sleep(15)
        await asyncio.to_thread(require_host_ssh_telemetry)


if __name__ == "__main__":
    asyncio.run(main())
