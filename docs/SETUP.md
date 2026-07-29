# Setup — end to end

From a bare Ubuntu machine to a live post-quantum IPsec tunnel and PQC SSH
session visible in the dashboard.

- [0. Choose your path](#0-choose-your-path)
- [1. Prerequisites](#1-prerequisites)
- [2. Backend](#2-backend)
- [3. Frontend](#3-frontend)
- [4. IPsec data plane — StrongSwan with ML-KEM](#4-ipsec-data-plane--strongswan-with-ml-kem)
- [5. SSH data plane — OpenSSH with PQC key exchange](#5-ssh-data-plane--openssh-with-pqc-key-exchange)
- [6. Zero Trust — the certificate authority](#6-zero-trust--the-certificate-authority)
- [7. Two-VM lab topology](#7-two-vm-lab-topology)
- [8. Single-host alternative — network namespaces](#8-single-host-alternative--network-namespaces)
- [9. Privilege configuration](#9-privilege-configuration)
- [10. Verification checklist](#10-verification-checklist)
- [11. Troubleshooting](#11-troubleshooting)

---

## 0. Choose your path

| Goal | Sections | Time | Needs root |
|---|---|---|---|
| **Dev mode** — API + UI, no crypto daemons | 1 → 3 | ~15 min | only for Postgres/Redis install |
| **SSH PQC only** | 1 → 3, 5, 6 | ~1 h | yes |
| **Full lab** — IPsec + SSH across two VMs | all | ~3 h | yes |

Dev mode is fully functional as an application: every endpoint responds, the
portals render, policy applies return `dev_mode: true` and write to `/tmp`. The
dashboard simply shows zero tunnels and zero sessions, because there are none.

---

## 1. Prerequisites

Ubuntu 22.04 or 24.04. Other distributions work but the package names below and
the `/usr/libexec/ipsec/` paths differ.

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv python3-dev \
    postgresql postgresql-contrib libpq-dev \
    redis-server \
    build-essential libssl-dev git curl
```

Node.js 20+ for the frontend:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node --version    # v20.x or later
```

Clone:

```bash
git clone https://github.com/hruday2503/quansec-pqc-platform.git
cd quansec-pqc-platform
```

---

## 2. Backend

### 2.1 The one-shot script

`quansec/setup_backend.sh` performs the entire backend bring-up. Read it before
running it — it installs packages, creates a database role, and writes `.env`.

```bash
cd quansec
chmod +x setup_backend.sh
./setup_backend.sh
```

Nine steps, in order:

| Step | What it does |
|---|---|
| 1 | Verifies (installs if absent) PostgreSQL, Redis, Python 3 |
| 2 | Starts both services, waits for `pg_isready` and a Redis `PONG` |
| 3 | Creates role `quansec_user` and database `quansec_db`, grants schema privileges, verifies the connection |
| 4 | Writes `.env` if absent, generating `JWT_SECRET` with `secrets.token_hex(32)`. An existing `.env` is preserved. |
| 5 | Creates `.venv` |
| 6 | `pip install -r requirements.txt` |
| 7 | Applies `migrations/*.sql` in `ls -1v` order via `psql` |
| 8 | Runs `seed_admin.py` to create/reset `admin@quansec.io` |
| 9 | Lists created tables and sets a Redis verification key |

It ends by printing the database details and admin credentials.

### 2.2 Manual path

If you would rather not run a script that calls `sudo`:

```bash
# Database
sudo -u postgres bash provision_postgres.sh

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configuration
cp .env.example .env
python3 -c "import secrets; print('JWT_SECRET=' + secrets.token_hex(32))"   # paste into .env
$EDITOR .env

# Migrations run automatically on startup, but you can pre-apply them:
for f in migrations/*.sql; do
    PGPASSWORD=quansec_secret psql -h localhost -U quansec_user -d quansec_db -f "$f"
done

# Admin user
ADMIN_PASSWORD='<a strong password>' python seed_admin.py
```

### 2.3 Environment reference

Every variable has a default in `core/config.py`, so the app boots with no `.env`.
`.env.example` documents the full set.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql://quansec_user:CHANGE_ME@localhost:5432/quansec` | asyncpg DSN |
| `REDIS_URL` | `redis://localhost:6379` | Pub/sub bus |
| `JWT_SECRET` | `change-this-in-production` | **Must be changed.** HS256 signing key |
| `JWT_ALGORITHM` | `HS256` | |
| `JWT_EXPIRE_HOURS` | `24` | Session token lifetime |
| `VICI_SOCKET` | `/var/run/charon.vici` | StrongSwan control socket |
| `IPSEC_POLL_INTERVAL` | `5` | Seconds between VICI polls |
| `SSH_AUTH_LOG` | `/var/log/auth.log` | |
| `SSHD_CONFIG` | `/etc/ssh/sshd_config` | Fallback KEX source |
| `SSH_POLL_INTERVAL` | `5` | Declared in config; the SSH collector uses its own `POLL_INTERVAL = 5` |
| `NGINX_ACCESS_LOG`, `TLS_POLL_INTERVAL` | | Reserved for the TLS module |
| `WG_INTERFACE`, `VPN_POLL_INTERVAL` | | Reserved for the VPN module |

Read directly from the environment rather than `Settings`:

| Variable | Read by | Purpose |
|---|---|---|
| `QUANSEC_CA_KEY` | `protocols/ssh/ca.py` | CA private key path (default `~/quansec-ca/quansec_ca`) |
| `QUANSEC_ZT_LOG` | `protocols/ssh/ztaudit.py` | Auth log to parse |
| `QUANSEC_ZT_REMOTE` | `protocols/ssh/ztaudit.py` | `user@host` to pull the log from over PQC ssh |
| `QUANSEC_ZT_KEY`, `QUANSEC_ZT_CERT` | `protocols/ssh/ztaudit.py` | Credentials for that pull |
| `ADMIN_PASSWORD` | `seed_admin.py` | Seeded admin password |

### 2.4 Run

```bash
cd quansec              # ← required: imports are core.*, protocols.*
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Expected startup log:

```
QUANSEC starting up...
Running migration: 001_users.sql
… 006_metrics_scoring.sql
Database ready
IPsec collector started
IPsec lifecycle event listener started
SSH collector started
```

`--reload` restarts on every file change, which also restarts every collector.
Do not use it in production.

Production:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

**One worker only.** Each worker would run its own copy of all five collectors,
producing duplicate writes and duplicate `quansec:live` publishes. Scaling
horizontally requires splitting collectors into a separate process first — see
[OPERATIONS.md](OPERATIONS.md#scaling).

---

## 3. Frontend

```bash
cd quansec-ui
npm install
echo "NEXT_PUBLIC_QUANSEC_API=http://localhost:8000" > .env.local
npm run dev
```

<http://localhost:3000> → landing page → pick IPsec or SSH → log in.

Production build:

```bash
npm run build
npm run start          # defaults to port 3000
```

`NEXT_PUBLIC_QUANSEC_API` is inlined at **build** time. Changing it after
`npm run build` requires a rebuild.

**CORS.** `main.py` allows only `http://localhost:3000` and
`https://localhost:443`. Serving the UI from any other origin means editing
`allow_origins` in `main.py`.

---

## 4. IPsec data plane — StrongSwan with ML-KEM

This is the longest part of the setup. Distribution StrongSwan packages did not
ship ML-KEM for the target release, so the platform includes a plugin that
registers ML-KEM-768 and ML-KEM-1024 as IKE key-exchange methods backed by
**liboqs**.

### 4.1 What the plugin does

`quansec/compiled-backup/ml_kem_source/` contains:

| File | Role |
|---|---|
| `ml_kem_plugin.c` | Registers the plugin as `ml-kem`, providing `KE` features `1050` and `1051` |
| `ml_kem_ke.c` | Implements StrongSwan's `key_exchange_t` interface over `OQS_KEM_keypair` / `OQS_KEM_encaps` / `OQS_KEM_decaps` |
| `Makefile.am` | Links `-loqs` from `/usr/local/lib` |

```c
#define ML_KEM_768  1050
#define ML_KEM_1024 1051

static plugin_feature_t features[] = {
    PLUGIN_REGISTER(KE, ml_kem_ke_create),
        PLUGIN_PROVIDE(KE, ML_KEM_768),
        PLUGIN_PROVIDE(KE, ML_KEM_1024),
};
```

`1050` and `1051` are in IANA's **private use** range for IKEv2 transform IDs.
That is why `charon.accept_private_algs = yes` is mandatory — without it charon
refuses to negotiate a method it has no IANA registration for. Both peers must
use the same numbers, which they do because they run the same plugin.

The KEM half of the exchange maps cleanly onto StrongSwan's Diffie-Hellman
abstraction: the initiator's `get_public_key` returns the ML-KEM public key, the
responder's `set_public_key` encapsulates against it and returns the ciphertext
as its own "public key", and the initiator decapsulates. Both sides end with the
same shared secret.

### 4.2 Build liboqs

```bash
sudo apt install -y cmake ninja-build libssl-dev

git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install

# Make the runtime linker aware of /usr/local/lib
sudo cp ~/quansec-pqc-platform/quansec/strongswan-configs/liboqs.conf \
        /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig
ldconfig -p | grep liboqs      # must print liboqs.so
```

### 4.3 Build StrongSwan with the plugin

```bash
sudo apt install -y libgmp-dev pkg-config libtool autoconf automake gettext

wget https://download.strongswan.org/strongswan-5.9.14.tar.bz2
tar xf strongswan-5.9.14.tar.bz2
cd strongswan-5.9.14

# Drop the plugin into the source tree
cp -r ~/quansec-pqc-platform/quansec/compiled-backup/ml_kem_source src/libstrongswan/plugins/ml_kem

# Register it with the build system
#   configure.ac : ARG_ENABL_SET([ml-kem], [enable the ML-KEM plugin.])
#                  ADD_PLUGIN([ml-kem], [s charon])
#                  AM_CONDITIONAL(USE_ML_KEM, test x$ml_kem = xtrue)
#                  AC_CONFIG_FILES: src/libstrongswan/plugins/ml_kem/Makefile
#   src/libstrongswan/Makefile.am : add the ml_kem SUBDIR + plugin LIBADD block

./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc \
    --enable-openssl --enable-swanctl --enable-systemd --enable-ml-kem
make -j$(nproc)
sudo make install
```

If the build is troublesome, `quansec/compiled-backup/` also carries the
pre-built `libstrongswan-ml-kem.so` and a matching `libstrongswan.so.0.0.0`.
They are ABI-tied to the StrongSwan version they were built against — copying
them onto a different build will fail to load.

### 4.4 Configure charon

Three drop-ins, all provided in `quansec/strongswan-configs/`:

```bash
sudo cp quansec/strongswan-configs/ml-kem.conf       /etc/strongswan.d/charon/ml-kem.conf
sudo cp quansec/strongswan-configs/private-algs.conf /etc/strongswan.d/private-algs.conf
```

```
# ml-kem.conf — load the plugin
ml-kem { load = yes }

# private-algs.conf — permit private-range transform IDs 1050/1051
charon { accept_private_algs = yes }
```

Confirm the plugin loaded:

```bash
sudo systemctl restart strongswan
sudo swanctl --stats | grep -i "ml-kem"
# or
journalctl -u strongswan | grep -i "loaded plugins"
```

`ml-kem` must appear in the plugin list. If it does not, the tunnel will fail
with `NO_PROPOSAL_CHOSEN`.

### 4.5 Tunnel configuration

`quansec/two-vm-configs/vm-a-swanctl.conf` (initiator) and
`vm-b/swanctl/swanctl.conf` (responder) are a matched pair:

```
connections {
    pqc-tunnel {
        version = 2                                # IKEv2 — PQC requires it
        proposals = aes256-sha256-mlkem1024        # pure ML-KEM-1024 key exchange
        local_addrs  = 192.168.1.6                 # VM A
        remote_addrs = 192.168.1.7                 # VM B
        local  { auth = psk; id = vm-a }
        remote { auth = psk; id = vm-b }
        children {
            net {
                esp_proposals = aes256-sha256
                local_ts  = 192.168.1.6/32
                remote_ts = 192.168.1.7/32
                start_action = trap                # VM A: bring up on first packet
            }                                      # VM B uses start_action = none
        }
    }
}
secrets {
    ike-1 { id-1 = vm-a; id-2 = vm-b; secret = <your PSK> }
}
```

Notes that matter:

- `proposals = aes256-sha256-mlkem1024` is a **pure** PQC key exchange — no
  `ecp384+mlkem1024` hybrid. It is the strongest possible statement and it
  proves the plugin negotiates standalone. `quansec/strongswan/swanctl.conf`
  contains the hybrid `ecp384+mlkem1024` form (RFC 9370 additional key exchange)
  as an alternative template.
- PSK authentication keeps the lab reproducible. Production should use
  `auth = pubkey` with X.509 — see the template in `quansec/strongswan/swanctl.conf`.
  Note that authentication remains classical either way; PQC here protects key
  *establishment*, which is what harvest-now-decrypt-later attacks target.
- `start_action = trap` on one side only. Both sides trapping causes a
  simultaneous-initiation collision.
- **Replace the PSK.** `vm-b/swanctl/swanctl.conf` ships with the placeholder
  `YOUR_IPSEC_PSK_HERE`; the VM A template contains a committed development
  value. Both must be changed to a shared high-entropy secret before use.

Install and load:

```bash
sudo cp quansec/two-vm-configs/vm-a-swanctl.conf /etc/swanctl/swanctl.conf   # on VM A
sudo cp vm-b/swanctl/swanctl.conf                /etc/swanctl/swanctl.conf   # on VM B
sudo chmod 600 /etc/swanctl/swanctl.conf
sudo swanctl --load-all
```

Bring the tunnel up and confirm the negotiated method:

```bash
ping -c 3 192.168.1.7          # from VM A — trap triggers on first packet
sudo swanctl --list-sas
# pqc-tunnel: ESTABLISHED … IKE proposal: AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ML_KEM_1024
```

`ML_KEM_1024` in that line is the ground truth the entire platform reports on.

### 4.6 VICI socket permissions

The backend must be able to read `/var/run/charon.vici`. Running uvicorn as root
is the simplest lab answer and the wrong production answer. Prefer:

```bash
sudo groupadd -f vici
sudo usermod -aG vici $USER
# /etc/strongswan.d/charon/vici.conf
#   vici { socket = unix:///var/run/charon.vici }
sudo chgrp vici /var/run/charon.vici
sudo chmod 660  /var/run/charon.vici
```

The socket is recreated on every charon restart, so make this a systemd
`ExecStartPost` or a udev rule rather than a one-off command.

---

## 5. SSH data plane — OpenSSH with PQC key exchange

### 5.1 Why a separate build on port 2222

The system sshd on port 22 stays untouched. The PQC daemon installs to
`/opt/openssh-pqc` and listens on 2222. Three reasons:

1. A broken PQC sshd cannot lock you out of the machine.
2. It creates a live A/B: port 22 is the classical control, 2222 the PQC
   treatment. The collector's `SSH_PORT_KEX` map encodes exactly that.
3. Zero Trust settings (certificate-only, no passwords) apply to the PQC daemon
   without changing system-wide SSH policy.

### 5.2 Build

OpenSSH 9.9+ ships `mlkem768x25519-sha256`. Earlier versions have
`sntrup761x25519-sha512@openssh.com`, which the collector also classifies as PQC.

```bash
sudo apt install -y libssl-dev zlib1g-dev libpam0g-dev

wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.0p1.tar.gz
tar xf openssh-10.0p1.tar.gz && cd openssh-10.0p1

./configure --prefix=/opt/openssh-pqc \
            --sysconfdir=/opt/openssh-pqc/etc \
            --with-pam --with-ssl-dir=/usr
make -j$(nproc)
sudo make install

/opt/openssh-pqc/sbin/sshd -T -f /dev/null | grep kexalgorithms | tr ',' '\n' | grep mlkem
# mlkem768x25519-sha256
```

If that grep is empty, the build does not support ML-KEM and the SSH module will
only ever report classical.

### 5.3 Configure

`vm-b/openssh-pqc/sshd_config` is the reference:

```
Port 2222
HostKey /opt/openssh-pqc/etc/ssh_host_ed25519_key
HostKey /opt/openssh-pqc/etc/ssh_host_rsa_key

KexAlgorithms mlkem768x25519-sha256      # PQC hybrid ONLY — classical refused

LogLevel VERBOSE                          # REQUIRED: emits "kex: algorithm: …"
SyslogFacility AUTH

PermitRootLogin no
Subsystem sftp /opt/openssh-pqc/libexec/sftp-server
PidFile /opt/openssh-pqc/var/sshd-pqc.pid

# Zero Trust
TrustedUserCAKeys /opt/openssh-pqc/etc/quansec_ca.pub
PubkeyAuthentication yes
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PasswordAuthentication no
```

Two lines carry the most weight:

- **`KexAlgorithms mlkem768x25519-sha256`** — a single algorithm with no
  fallback. This is *fail-closed* expressed in configuration: a client that
  cannot do hybrid ML-KEM is refused rather than downgraded. A downgrade attack
  has nothing to downgrade to.
- **`LogLevel VERBOSE`** — without it sshd never logs
  `kex: algorithm: mlkem768x25519-sha256`, `_live_kex_by_peer()` returns an empty
  map, and the collector silently drops to port-implied detection. Everything
  still works; it just stops being evidence of what was actually negotiated.

Deploy:

```bash
sudo mkdir -p /opt/openssh-pqc/etc /opt/openssh-pqc/var
sudo cp vm-b/openssh-pqc/sshd_config /opt/openssh-pqc/etc/sshd_config
sudo ssh-keygen -t ed25519 -f /opt/openssh-pqc/etc/ssh_host_ed25519_key -N ''
sudo ssh-keygen -t rsa -b 4096 -f /opt/openssh-pqc/etc/ssh_host_rsa_key -N ''

sudo /opt/openssh-pqc/sbin/sshd -t -f /opt/openssh-pqc/etc/sshd_config   # validate
bash vm-b/scripts/start-pqc-ssh.sh                                       # start
sudo ss -tlnp | grep 2222
```

Connect and confirm:

```bash
/opt/openssh-pqc/bin/ssh -p 2222 -v user@192.168.1.7 2>&1 | grep "kex:"
# debug1: kex: algorithm: mlkem768x25519-sha256
```

Within 5 seconds the session appears in `GET /api/ssh/connections` with
`pqc_enabled: true` and `kem_label: "ML-KEM-768"`.

**Make it a service.** `start-pqc-ssh.sh` runs sshd in the foreground with no
supervision. For anything beyond a demo, write a systemd unit:

```ini
[Unit]
Description=QUANSEC PQC OpenSSH
After=network.target
[Service]
ExecStart=/opt/openssh-pqc/sbin/sshd -D -f /opt/openssh-pqc/etc/sshd_config
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

---

## 6. Zero Trust — the certificate authority

The SSH module replaces "a public key in `authorized_keys` forever" with
"a short-lived certificate signed by a CA". Five properties follow: identity is
cryptographic, access is time-bound, principals are scoped, revocation is
serial-based, and every authentication is auditable.

### 6.1 Create the CA

```bash
mkdir -p ~/quansec-ca && chmod 700 ~/quansec-ca
ssh-keygen -t ed25519 -f ~/quansec-ca/quansec_ca -C "QUANSEC CA" -N ''
chmod 600 ~/quansec-ca/quansec_ca
```

The backend finds it via `QUANSEC_CA_KEY` (default `~/quansec-ca/quansec_ca`).
`.gitignore` already excludes `quansec_ca*`, `*_key`, and `*-cert.pub`.

### 6.2 Trust it on the server

```bash
sudo cp ~/quansec-ca/quansec_ca.pub /opt/openssh-pqc/etc/quansec_ca.pub
# sshd_config already has: TrustedUserCAKeys /opt/openssh-pqc/etc/quansec_ca.pub
sudo pkill -f "openssh-pqc.*2222" && bash vm-b/scripts/start-pqc-ssh.sh
```

### 6.3 Issue a certificate

The user generates their own key pair. **The private key never leaves them** —
`POST /api/ssh/ca/issue` accepts only a public key and rejects anything matching
`PRIVATE KEY`.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/alice -N ''

TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
        -d "username=admin@quansec.io&password=$ADMIN_PASSWORD" \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:8000/api/ssh/ca/issue \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"public_key\": \"$(cat ~/.ssh/alice.pub)\",
       \"identity\": \"alice@quansec.io\",
       \"principals\": \"hd6441\",
       \"valid_hours\": 8}" | python3 -m json.tool
```

Save the returned `certificate` next to the private key and connect:

```bash
/opt/openssh-pqc/bin/ssh -i ~/.ssh/alice \
    -o CertificateFile=~/.ssh/alice-cert.pub \
    -p 2222 hd6441@192.168.1.7
```

Server-side this logs a line the ZT collector parses, and within 8 seconds it
appears in `GET /api/ssh/zt/events` with identity, serial, CA fingerprint and
source IP.

Issuance is `require_admin`. Serials are allocated as `MAX(serial) + 1` from
`issued_certs`, which is not concurrency-safe under simultaneous issuance — see
[SECURITY.md](SECURITY.md).

### 6.4 Revocation

Certificate revocation uses an OpenSSH KRL. The platform records serials in
`issued_certs` and exposes them via `GET /api/ssh/ca/issued`, but does not yet
generate or distribute the KRL. Until it does, revocation is manual:

```bash
ssh-keygen -k -f /opt/openssh-pqc/etc/quansec.krl -u -s ~/quansec-ca/quansec_ca.pub -z <serial>
# add to sshd_config:  RevokedKeys /opt/openssh-pqc/etc/quansec.krl
```

Short validity windows (default 8 h) are the primary containment mechanism.

---

## 7. Two-VM lab topology

```
        ┌──────────────────────────────┐        ┌──────────────────────────────┐
        │  VM A — 192.168.1.6          │        │  VM B — 192.168.1.7          │
        │  control plane + initiator   │        │  responder + PQC SSH server  │
        │                              │        │                              │
        │  QUANSEC backend      :8000  │        │  StrongSwan charon           │
        │  QUANSEC UI           :3000  │        │    swanctl.conf (id vm-b)    │
        │  PostgreSQL           :5432  │        │    start_action = none       │
        │  Redis                :6379  │        │                              │
        │  StrongSwan charon           │        │  OpenSSH PQC          :2222  │
        │    swanctl.conf (id vm-a)    │        │    mlkem768x25519-sha256     │
        │    start_action = trap       │        │    TrustedUserCAKeys         │
        │  QUANSEC CA (~/quansec-ca)   │        │    PasswordAuthentication no │
        └──────────────┬───────────────┘        └──────────────┬───────────────┘
                       │                                       │
                       └──────── IPsec ESP tunnel ─────────────┘
                            IKEv2 · pure ML-KEM-1024
                       ─────── PQC SSH :2222 ──────────────────
                            hybrid X25519 + ML-KEM-768
```

Setup order:

| # | VM | Action | Section |
|---|---|---|---|
| 1 | A | Backend + frontend | 2, 3 |
| 2 | A & B | liboqs, StrongSwan + ml-kem plugin | 4.2–4.4 |
| 3 | A | `two-vm-configs/vm-a-swanctl.conf` → `/etc/swanctl/`, set PSK | 4.5 |
| 4 | B | `vm-b/swanctl/swanctl.conf` → `/etc/swanctl/`, same PSK | 4.5 |
| 5 | A | `swanctl --load-all`, `ping 192.168.1.7`, `swanctl --list-sas` | 4.5 |
| 6 | B | OpenSSH PQC build + config | 5 |
| 7 | A | Create the CA, copy the public key to B | 6.1–6.2 |
| 8 | A | Issue a cert, connect to B on 2222 | 6.3 |
| 9 | A | Point `QUANSEC_ZT_REMOTE` at B so the ZT collector pulls B's auth log | below |

The ZT collector runs on VM A but the certificate authentications happen on VM B.
Pull them across the PQC channel:

```bash
# in quansec/.env on VM A
QUANSEC_ZT_REMOTE=hd6441@192.168.1.7
QUANSEC_ZT_KEY=/home/USER/.ssh/quansec_zt
QUANSEC_ZT_CERT=/home/USER/.ssh/quansec_zt-cert.pub
```

This requires a passwordless-sudo entry on VM B for
`tail -n 400 /var/log/auth.log` by the ZT user. Scope it narrowly.

Change the IP addresses to match your network in three places: both
`swanctl.conf` files and the `_read_current_addrs()` fallback in
`protocols/ipsec/policy.py` (which parses the live `swanctl.conf` first and only
falls back to hardcoded `192.168.1.6/.7` if that read fails).

---

## 8. Single-host alternative — network namespaces

`quansec/launch_ns_tunnel.sh` runs two charon daemons on one machine in separate
network namespaces — a real IKEv2 negotiation over a veth pair, with no second VM.

Create the namespaces first (not done by the script):

```bash
sudo ip netns add ns-left
sudo ip netns add ns-right
sudo ip link add veth-l type veth peer name veth-r
sudo ip link set veth-l netns ns-left
sudo ip link set veth-r netns ns-right
sudo ip netns exec ns-left  ip addr add 10.10.0.1/24 dev veth-l
sudo ip netns exec ns-right ip addr add 10.10.0.2/24 dev veth-r
sudo ip netns exec ns-left  ip link set veth-l up
sudo ip netns exec ns-right ip link set veth-r up
sudo mkdir -p /etc/ns-left/swanctl /etc/ns-right/swanctl /var/run/ns-left /var/run/ns-right
# write strongswan.conf + swanctl.conf per namespace, pointing at the per-ns paths
```

Then:

```bash
sudo bash quansec/launch_ns_tunnel.sh
sudo ip netns exec ns-left ping -c 5 10.10.0.2      # trap brings the tunnel up
```

The script's trick is `unshare --mount` plus a bind mount of a per-namespace
pidfile onto `/var/run/charon.pid`. charon hardcodes that path, so two instances
would otherwise fight over one file. Each namespace also gets its own VICI socket
under `/var/run/ns-*/charon.vici`, chmod'ed inside the same mount namespace so
the host can reach it.

Point the backend at one of them:

```bash
VICI_SOCKET=/var/run/ns-left/charon.vici
```

`chmod 777` on the socket is convenient for a lab and unacceptable anywhere else.

---

## 9. Privilege configuration

Both policy engines mutate system configuration and restart daemons. Without
privilege they fall back to dev mode rather than failing — which means a policy
apply can silently do nothing to the live system. Check `dev_mode` in the
response.

### IPsec

`POST /api/ipsec/policies/apply` writes `/etc/swanctl/swanctl.conf` directly (as
the backend user) and then runs `sudo swanctl --load-all`.

```bash
sudo chown $USER /etc/swanctl/swanctl.conf
sudo chmod 600 /etc/swanctl/swanctl.conf
```

```
# /etc/sudoers.d/quansec-ipsec   (visudo -f)
quansec ALL=(root) NOPASSWD: /usr/sbin/swanctl --load-all
```

### SSH

`POST /api/ssh/policies/apply` uses `sudo tee`, `sudo sshd -t`, `sudo pkill` and
`sudo sshd`.

```
# /etc/sudoers.d/quansec-ssh
quansec ALL=(root) NOPASSWD: /usr/bin/tee /opt/openssh-pqc/etc/sshd_config
quansec ALL=(root) NOPASSWD: /opt/openssh-pqc/sbin/sshd -t -f /opt/openssh-pqc/etc/sshd_config
quansec ALL=(root) NOPASSWD: /opt/openssh-pqc/sbin/sshd -f /opt/openssh-pqc/etc/sshd_config
quansec ALL=(root) NOPASSWD: /usr/bin/pkill -f /opt/openssh-pqc/sbin/sshd*
```

Grant these to a dedicated service account, never to a login user. Each line is
a full root-equivalent primitive if the argument can be influenced — the `tee`
rule in particular is only safe because the path is fixed.

### Reading journald

```bash
sudo usermod -aG systemd-journal quansec
```

Without it, `journalctl -u ssh` returns nothing and KEX detection degrades.

---

## 10. Verification checklist

```bash
# ── Backend ────────────────────────────────────────────────────────────────
curl -s localhost:8000/health | python3 -m json.tool
# status "ok", database "connected", five collectors listed

# ── Auth ───────────────────────────────────────────────────────────────────
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login \
        -d "username=admin@quansec.io&password=$ADMIN_PASSWORD" \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s localhost:8000/api/auth/me -H "Authorization: Bearer $TOKEN"

# ── IPsec ──────────────────────────────────────────────────────────────────
sudo swanctl --list-sas | grep -i ml_kem            # ground truth
curl -s localhost:8000/api/ipsec/stats  -H "Authorization: Bearer $TOKEN"
curl -s localhost:8000/api/ipsec/tunnels -H "Authorization: Bearer $TOKEN"
# pqc_enabled true, pqc_kem "ML-KEM-1024", pqc_coverage 100.0

# ── SSH ────────────────────────────────────────────────────────────────────
curl -s localhost:8000/api/ssh/stats -H "Authorization: Bearer $TOKEN"
# kex_algorithm mlkem768x25519-sha256, kem_label ML-KEM-768

# ── Zero Trust ─────────────────────────────────────────────────────────────
curl -s localhost:8000/api/ssh/zt/status -H "Authorization: Bearer $TOKEN"

# ── Scoring ────────────────────────────────────────────────────────────────
curl -s localhost:8000/api/scoring/overall -H "Authorization: Bearer $TOKEN"
# a fully PQC estate scores in the 90s with grade A

# ── Telemetry ──────────────────────────────────────────────────────────────
curl -s localhost:8000/metrics | grep quansec_
curl -s "localhost:8000/api/siem/events?format=cef" -H "Authorization: Bearer $TOKEN"

# ── Live push ──────────────────────────────────────────────────────────────
websocat ws://localhost:8000/api/ws/live        # then bounce the tunnel
```

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: core` | uvicorn started outside `quansec/` | `cd quansec` first |
| `StrongSwan VICI socket not available` every 5 s | charon down, or socket unreadable | `systemctl status strongswan`; check permissions (§4.6) |
| Tunnel `NO_PROPOSAL_CHOSEN` | ml-kem plugin not loaded, or `accept_private_algs` missing | `swanctl --stats \| grep ml-kem`; install both drop-ins (§4.4) |
| Tunnel up but `pqc_enabled: false` | The negotiated proposal genuinely lacks a PQC KEM | `swanctl --list-sas` — if it shows `ECP_384`, the peer downgraded |
| SSH sessions show `kex_algorithm: unknown` | `LogLevel VERBOSE` missing, or journald unreadable | Set it in `sshd_config`; add the user to `systemd-journal` |
| SSH shows classical for a port-2222 session | journald read failed, fell back to configured KEX | Same as above; check `journalctl -u ssh --since -5min` |
| Policy apply returns `dev_mode: true` | `/etc/swanctl` or the PQC sshd_config is absent | Install the daemon, or accept dev mode for a demo |
| Policy apply → 500 "Cannot write swanctl.conf" | Backend lacks write permission | §9 |
| WebSocket connects then goes quiet | Redis down, or nothing published yet | `redis-cli ping`; `redis-cli SUBSCRIBE quansec:live` |
| No Zero Trust events | Wrong log path, or authentications happen on the other VM | Set `QUANSEC_ZT_LOG`, or `QUANSEC_ZT_REMOTE` (§7) |
| `/api/auth/login` → 401 with correct password | Admin never seeded, or hash mismatch | `ADMIN_PASSWORD=… python seed_admin.py` |
| UI shows CORS errors | Origin not in `allow_origins` | Edit `main.py`, or serve on `localhost:3000` |
| Migrations log errors on startup | Expected on re-run; all statements are idempotent | Only investigate if a table is genuinely missing |

---

*See also:* [ARCHITECTURE.md](ARCHITECTURE.md) · [OPERATIONS.md](OPERATIONS.md) · [SECURITY.md](SECURITY.md) · [protocols/IPSEC.md](protocols/IPSEC.md) · [protocols/SSH.md](protocols/SSH.md)
