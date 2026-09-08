# Phase 1: real core-module containers

This deployment separates the backend into four failure domains:

| Service | Responsibility | Real dependency | Failure behaviour |
|---|---|---|---|
| `api` | Authenticated read/write HTTP and WebSocket API | PostgreSQL, Redis | exits if PostgreSQL is unavailable |
| `ipsec-collector` | VICI polling and lifecycle events | real `/var/run/charon.vici` | exits at startup or within 15 seconds if VICI is unavailable |
| `ssh-collector` | host TCP sessions and certificate-auth audit | host network namespace, real auth log, PQC OpenSSH files | exits at startup or within 15 seconds if telemetry disappears |
| `policy-engine` | IPsec/SSH policy API and alert evaluation | restricted host-controller socket and both real daemons | refuses to start if either target is unavailable |

PostgreSQL, Redis, the one-shot migration job, and an NGINX gateway are support
services. The gateway keeps the existing public URL on port 8000 while routing
the policy paths to the independent policy engine.

## Why the host controller exists

A container cannot safely run `sudo swanctl`, kill a host sshd, or receive the
Docker socket. The root host agent accepts only these structured operations:

- `apply_ipsec` with one of `classical`, `pqc-level3`, `pqc-level5`;
- `apply_ssh` with one of `classical`, `pqc-hybrid`;
- `status`.

It has no general command endpoint. It preserves the existing StrongSwan
identities, addresses, traffic selectors, and PSK; only proposal lines change.
For SSH it changes only `KexAlgorithms`. Both configurations are validated and
restored if reload fails. The old `/tmp/quanseq` simulation paths are gone.

## Prerequisites

Task 1 deliberately does not pretend that missing cryptographic software is a
working deployment. Before all four services can be healthy, the Ubuntu host
must have:

1. the project's matching StrongSwan 5.9.14 + `liboqs.so.9` runtime, including
   `swanctl` and `/var/run/charon.vici`;
2. the separate PQC OpenSSH runtime under `/opt/openssh-pqc`;
3. a real `/etc/swanctl/swanctl.conf` and
   `/opt/openssh-pqc/etc/sshd_config`;
4. `/var/log/auth.log` readable by the SSH collector bind mount.

The repository does not record the exact liboqs source tag/commit used by the
prebuilt plugin. Pinning and rebuilding that supply chain is Phase 1 Task 2;
do not silently substitute a different StrongSwan/liboqs architecture here.

## Install the restricted host services

From the repository root:

```bash
chmod +x deploy/install-host-agent.sh
./deploy/install-host-agent.sh
sudo systemctl enable --now quanseq-pqc-sshd.service
sudo systemctl status quanseq-policy-agent quanseq-pqc-sshd --no-pager
```

The PQC sshd unit will fail closed until `/opt/openssh-pqc` is genuinely
installed and its configuration passes `sshd -t`.

## Configure and start containers

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
python3 -c 'import secrets; print(secrets.token_hex(48))'
```

Put the first output in `POSTGRES_PASSWORD` and the second in `JWT_SECRET`, then:

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=100 ipsec-collector ssh-collector policy-engine
curl -fsS http://127.0.0.1:8000/health
```

If the real StrongSwan or PQC OpenSSH prerequisite is missing, the relevant
container exits/restarts and names the missing dependency. That is intentional:
red is truthful; a green simulated policy is not.

## Independent recovery proof

```bash
docker compose restart ipsec-collector
docker compose ps
docker compose restart ssh-collector
docker compose ps
docker compose restart policy-engine
docker compose ps
```

Each command replaces only that module. PostgreSQL state and the other modules
remain running. To prove fail-closed behaviour, stop StrongSwan on a disposable
lab VM and confirm only `ipsec-collector` becomes unhealthy/restarts; restore
StrongSwan and the collector recovers under its restart policy.

## Verification

```bash
python3 -m unittest quanseq/tests/test_container_boundaries.py
python3 -m compileall -q quanseq
docker compose config --quiet
```
