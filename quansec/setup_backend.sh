#!/usr/bin/env bash
# =============================================================================
# QUANSEC Backend Setup — PostgreSQL + Redis + Python Env + Migrations + Seed
# =============================================================================
# Usage:
#   chmod +x setup_backend.sh
#   ./setup_backend.sh
#
# What this does:
#   1. Installs system deps (PostgreSQL, Redis) if missing
#   2. Creates the quansec_user and quansec_db in PostgreSQL
#   3. Verifies Redis is running
#   4. Sets up Python virtual environment
#   5. Installs Python dependencies
#   6. Creates .env file if it doesn't exist
#   7. Runs all SQL migrations
#   8. Seeds the admin user
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# ── Config (from .env or defaults) ───────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    source <(grep -v '^#' "$ENV_FILE" | grep '=' | sed 's/^/export /')
fi

DB_USER="${DB_USER:-quansec_user}"
DB_PASS="${DB_PASS:-quansec_secret}"
DB_NAME="${DB_NAME:-quansec_db}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@QuanSec2024!}"

# Extract from DATABASE_URL if set
if [ -n "${DATABASE_URL:-}" ]; then
    DB_USER=$(echo "$DATABASE_URL" | sed -n 's|postgresql://\([^:]*\):.*|\1|p')
    DB_PASS=$(echo "$DATABASE_URL" | sed -n 's|postgresql://[^:]*:\([^@]*\)@.*|\1|p')
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):.*|\1|p')
    DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\(.*\)|\1|p')
fi

# =============================================================================
echo -e "\n${BOLD}${CYAN}"
echo "  ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗███████╗███████╗ ██████╗"
echo "  ██╔═══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔════╝"
echo "  ██║   ██║██║   ██║███████║██╔██╗ ██║███████╗█████╗  ██║"
echo "  ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║╚════██║██╔══╝  ██║"
echo "  ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████║███████╗╚██████╗"
echo "   ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝"
echo -e "${RESET}"
echo "  Post-Quantum Cryptography Platform — Backend Setup"
echo "  ─────────────────────────────────────────────────"
echo ""

# =============================================================================
step "STEP 1: Checking System Dependencies"
# =============================================================================

# PostgreSQL
if ! command -v psql &>/dev/null; then
    warn "PostgreSQL client not found. Installing..."
    sudo apt-get update -qq && sudo apt-get install -y -qq postgresql postgresql-client
    sudo systemctl enable --now postgresql
    success "PostgreSQL installed"
else
    success "PostgreSQL client found: $(psql --version)"
fi

# Redis
if ! command -v redis-cli &>/dev/null; then
    warn "Redis not found. Installing..."
    sudo apt-get install -y -qq redis-server
    sudo systemctl enable --now redis-server
    success "Redis installed"
else
    success "Redis found: $(redis-cli --version)"
fi

# Python 3
if ! command -v python3 &>/dev/null; then
    error "Python 3 is required but not found. Install with: sudo apt install python3 python3-pip python3-venv"
fi
success "Python: $(python3 --version)"

# =============================================================================
step "STEP 2: Starting Services"
# =============================================================================

# Start PostgreSQL
if ! systemctl is-active --quiet postgresql; then
    info "Starting PostgreSQL..."
    sudo systemctl start postgresql
    sleep 2
fi
if pg_isready -h "$DB_HOST" -p "$DB_PORT" -q; then
    success "PostgreSQL is running on $DB_HOST:$DB_PORT"
else
    error "PostgreSQL is not ready at $DB_HOST:$DB_PORT"
fi

# Start Redis
REDIS_SERVICE=""
for svc in redis redis-server redis.service; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        REDIS_SERVICE="$svc"
        break
    fi
done

if [ -z "$REDIS_SERVICE" ]; then
    info "Starting Redis..."
    sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null || true
    sleep 1
fi

if redis-cli ping 2>/dev/null | grep -q PONG; then
    success "Redis is running and responding to PING"
else
    error "Redis is not responding. Check: sudo systemctl status redis-server"
fi

# =============================================================================
step "STEP 3: Setting Up PostgreSQL Database"
# =============================================================================

info "Creating role '${DB_USER}' if it doesn't exist..."
sudo -u postgres psql -v ON_ERROR_STOP=0 <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Created role ${DB_USER}';
    ELSE
        ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASS}';
        RAISE NOTICE 'Updated password for ${DB_USER}';
    END IF;
END
\$\$;
EOF

info "Creating database '${DB_NAME}' if it doesn't exist..."
sudo -u postgres psql -v ON_ERROR_STOP=0 -c "
    SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')
" | grep -q "CREATE DATABASE" && \
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" 2>/dev/null || \
    sudo -u postgres psql -c "ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};" 2>/dev/null || true

# Grant all privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null
sudo -u postgres psql -d "${DB_NAME}" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" 2>/dev/null

# Test the connection
if PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" &>/dev/null; then
    success "Database connection verified: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
else
    error "Cannot connect to database. Check pg_hba.conf or credentials."
fi

# =============================================================================
step "STEP 4: Configuring .env File"
# =============================================================================

if [ ! -f "$ENV_FILE" ]; then
    warn ".env not found — creating from template..."
    cat > "$ENV_FILE" <<ENVEOF
# QUANSEC Backend Environment — auto-generated by setup_backend.sh
DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
JWT_ALGORITHM=HS256
JWT_EXPIRE_HOURS=24
ADMIN_PASSWORD=${ADMIN_PASSWORD}
VICI_SOCKET=/var/run/charon.vici
IPSEC_POLL_INTERVAL=5
NGINX_ACCESS_LOG=/var/log/nginx/access.log
TLS_POLL_INTERVAL=3
SSH_AUTH_LOG=/var/log/auth.log
SSHD_CONFIG=/etc/ssh/sshd_config
SSH_POLL_INTERVAL=5
WG_INTERFACE=wg0
VPN_POLL_INTERVAL=5
APP_ENV=development
LOG_LEVEL=INFO
ENVEOF
    success ".env file created"
else
    success ".env file already exists — preserving it"
fi

# Update DATABASE_URL in .env to ensure it's correct
grep -q "^DATABASE_URL=" "$ENV_FILE" || \
    echo "DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}" >> "$ENV_FILE"

# =============================================================================
step "STEP 5: Setting Up Python Virtual Environment"
# =============================================================================

VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    success "Virtual environment created"
else
    success "Virtual environment already exists"
fi

source "$VENV_DIR/bin/activate"
info "Python in use: $(which python)"

# =============================================================================
step "STEP 6: Installing Python Dependencies"
# =============================================================================

pip install --upgrade pip --quiet

# Check if requirements changed
REQ_FILE="$SCRIPT_DIR/requirements.txt"
if [ -f "$REQ_FILE" ]; then
    info "Installing from requirements.txt..."
    pip install -r "$REQ_FILE" --quiet
    success "Python packages installed"
else
    warn "requirements.txt not found, installing core packages..."
    pip install --quiet \
        "fastapi==0.115.0" \
        "uvicorn[standard]==0.30.6" \
        "asyncpg==0.29.0" \
        "psycopg2-binary==2.9.9" \
        "redis==5.0.8" \
        "pydantic==2.8.2" \
        "python-jose[cryptography]==3.3.0" \
        "passlib[bcrypt]==1.7.4" \
        "python-dotenv==1.0.1" \
        "httpx==0.27.2"
    success "Core packages installed"
fi

# Ensure email-validator is available (for EmailStr in pydantic)
pip install --quiet "email-validator>=2.0" 2>/dev/null || true

# =============================================================================
step "STEP 7: Running Database Migrations"
# =============================================================================

MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
if [ ! -d "$MIGRATIONS_DIR" ]; then
    error "No migrations/ directory found at $MIGRATIONS_DIR"
fi

MIGRATION_FILES=$(ls -1v "$MIGRATIONS_DIR"/*.sql 2>/dev/null || true)
if [ -z "$MIGRATION_FILES" ]; then
    error "No .sql files found in $MIGRATIONS_DIR"
fi

info "Running migrations in order..."
for sql_file in $MIGRATION_FILES; do
    filename=$(basename "$sql_file")
    info "  ↳ $filename"
    PGPASSWORD="$DB_PASS" psql \
        -h "$DB_HOST" -p "$DB_PORT" \
        -U "$DB_USER" -d "$DB_NAME" \
        -v ON_ERROR_STOP=0 \
        -f "$sql_file" \
        --quiet 2>&1 | grep -v "^$" | grep -v "NOTICE" || true
done
success "All migrations applied"

# =============================================================================
step "STEP 8: Seeding Admin User"
# =============================================================================

info "Running seed_admin.py..."
ADMIN_PASSWORD="$ADMIN_PASSWORD" python seed_admin.py
success "Admin user seeded"

# =============================================================================
step "STEP 9: Verification"
# =============================================================================

info "Verifying database tables..."
TABLE_COUNT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "
    SELECT COUNT(*) FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
" | tr -d ' ')

if [ "$TABLE_COUNT" -gt 0 ]; then
    success "Found ${TABLE_COUNT} tables in database"
    PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    "
else
    warn "No tables found — check migration output above"
fi

info "Verifying Redis..."
redis-cli ping
redis-cli set quansec:setup:verified "$(date -Iseconds)" EX 86400 >/dev/null
success "Redis key set successfully"

# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  ✅  QUANSEC Backend Setup Complete!${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}Database${RESET}"
echo "    Host     : ${DB_HOST}:${DB_PORT}"
echo "    Database : ${DB_NAME}"
echo "    User     : ${DB_USER}"
echo ""
echo -e "  ${BOLD}Redis${RESET}"
echo "    URL      : redis://localhost:6379/0"
echo ""
echo -e "  ${BOLD}Admin Credentials${RESET}"
echo "    Email    : admin@quansec.io"
echo "    Password : ${ADMIN_PASSWORD}"
echo ""
echo -e "  ${BOLD}Next Steps${RESET}"
echo "    1. Activate venv   : source .venv/bin/activate"
echo "    2. Start backend   : uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
echo "    3. API docs        : http://localhost:8000/docs"
echo "    4. Health check    : http://localhost:8000/health"
echo ""
echo -e "  ${YELLOW}⚠  Change ADMIN_PASSWORD and JWT_SECRET in .env before deploying!${RESET}"
echo ""
