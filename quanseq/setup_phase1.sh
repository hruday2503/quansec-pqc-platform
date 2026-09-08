#!/bin/bash
# =============================================================================
# QUANSEQ — Phase 1 (IPsec) setup script
# Run this top to bottom on Ubuntu 22.04 / 24.04
# =============================================================================
set -e

echo "=== 1. System dependencies ==="
sudo apt update
sudo apt install -y \
    strongswan strongswan-pki libcharon-extra-plugins \
    strongswan-swanctl strongswan-plugin-kernel-netlink \
    python3 python3-pip python3-venv python3-dev \
    libpq-dev postgresql postgresql-contrib \
    redis-server \
    build-essential libssl-dev

echo "=== 2. Start services ==="
sudo systemctl enable --now postgresql
sudo systemctl enable --now redis-server
sudo systemctl enable --now strongswan-starter

echo "=== 3. PostgreSQL setup ==="
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='quanseq'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE quanseq;"

sudo -u postgres psql -c "
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'quanseq_user') THEN
        CREATE USER quanseq_user WITH PASSWORD 'quanseq_pass';
    END IF;
END
\$\$;
GRANT ALL PRIVILEGES ON DATABASE quanseq TO quanseq_user;
" 
sudo -u postgres psql -d quanseq -c "GRANT ALL ON SCHEMA public TO quanseq_user;"

echo "=== 4. Python environment ==="
cd ~/quanseq
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "=== 5. Run DB migrations ==="
# Migrations run automatically on FastAPI startup via lifespan,
# but you can also run them manually:
# psql -U quanseq_user -d quanseq -f migrations/001_initial.sql

echo "=== 6. StrongSwan: check VICI socket ==="
# After strongswan starts, the socket should appear at:
ls -la /var/run/charon.vici 2>/dev/null && echo "VICI socket OK" || echo "VICI socket not yet available — start strongswan first"

# Check if ml-kem (Kyber) plugin is available
sudo ipsec statusall 2>/dev/null | grep -i kyber && echo "Kyber plugin loaded" || \
    echo "Note: Kyber plugin may not be in apt packages — see compile instructions below"

echo "=== 7. Start QUANSEQ ==="
echo "Run: source .venv/bin/activate && uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
echo ""
echo "API docs: http://localhost:8000/docs"
echo "Health:   http://localhost:8000/health"
echo "Tunnels:  http://localhost:8000/api/ipsec/tunnels"
echo "Stats:    http://localhost:8000/api/ipsec/stats"

# =============================================================================
# OPTIONAL: Compile StrongSwan with Kyber/ML-KEM support
# The apt version may not include the ml-kem plugin yet.
# If `proposals = aes256gcm128-prfsha384-ecp384+mlkem1024` is rejected,
# do this:
# =============================================================================
# sudo apt remove strongswan* -y
# sudo apt install -y build-essential libssl-dev libgmp-dev pkg-config \
#     libtool autoconf automake gettext
#
# # Download Open Quantum Safe liboqs
# git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
# cd liboqs && mkdir build && cd build
# cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
# make -j$(nproc) && sudo make install
#
# # Build StrongSwan with OQS plugin
# wget https://download.strongswan.org/strongswan-5.9.14.tar.bz2
# tar xf strongswan-5.9.14.tar.bz2 && cd strongswan-5.9.14
# ./configure --prefix=/usr/local \
#     --enable-openssl \
#     --enable-oqs \
#     --enable-swanctl \
#     --enable-systemd \
#     --with-ipseclibdir=/usr/local/lib/ipsec
# make -j$(nproc) && sudo make install
