"""Dedicated, fail-closed host SSH telemetry worker."""

import asyncio
import os
import shutil
import subprocess

from protocols.ssh.collector import collect_loop
from protocols.ssh.ztaudit import zt_collect_loop
from services.runtime import run_worker


def require_host_ssh_telemetry() -> None:
    auth_log = os.environ.get("QUANSEC_ZT_LOG", "/host/var/log/auth.log")
    sshd_config = os.environ.get("SSHD_CONFIG", "/opt/openssh-pqc/etc/sshd_config")
    sshd_binary = os.environ.get("SSHD_CONFIG_BINARY", "/opt/openssh-pqc/sbin/sshd")
    if not os.path.isfile(auth_log) or not os.access(auth_log, os.R_OK):
        raise RuntimeError(f"real host SSH audit log is not readable: {auth_log}")
    if not os.path.isdir("/run/log/journal"):
        raise RuntimeError("real host journald directory is not mounted at /run/log/journal")
    if not os.path.isfile(sshd_binary) or not os.path.isfile(sshd_config):
        raise RuntimeError("real /opt/openssh-pqc binary/configuration is not mounted")
    validation = subprocess.run(
        [sshd_binary, "-t", "-f", sshd_config], capture_output=True, text=True, timeout=5
    )
    if validation.returncode:
        raise RuntimeError(f"real PQC sshd configuration is invalid: {validation.stderr.strip()}")
    if not shutil.which("ss"):
        raise RuntimeError("ss is required to inspect real host TCP sessions")
    check = subprocess.run(["ss", "-Htn"], capture_output=True, text=True, timeout=5)
    if check.returncode:
        raise RuntimeError(f"cannot inspect host network namespace: {check.stderr.strip()}")


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
