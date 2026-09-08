#!/usr/bin/env bash
# =============================================================================
# QUANSEQ PostgreSQL Provisioning — Run with sudo
# =============================================================================
# This script must be run as a user with NOPASSWD sudo rights OR
# directly from a terminal where sudo works interactively.
#
# Usage:
#   sudo bash provision_postgres.sh
# OR:
#   su - postgres -c "psql -f /tmp/quanseq_provision.sql"
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }

DB_USER="quanseq_user"
DB_PASS="quanseq_secret"
DB_NAME="quanseq_db"

info "Provisioning PostgreSQL as 'postgres' superuser..."

# This script is designed to be run with sudo -u postgres
# or as a postgres superuser
psql -v ON_ERROR_STOP=0 <<EOF
-- Create the application user
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

-- Create the database
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER} ENCODING UTF8'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
EOF

# Grant schema-level permissions
psql -d "${DB_NAME}" -v ON_ERROR_STOP=0 <<EOF
GRANT ALL ON SCHEMA public TO ${DB_USER};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${DB_USER};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${DB_USER};
EOF

success "PostgreSQL provisioning complete!"
success "  User     : ${DB_USER}"
success "  Database : ${DB_NAME}"
echo ""
echo "Test with: PGPASSWORD=${DB_PASS} psql -h localhost -U ${DB_USER} -d ${DB_NAME} -c 'SELECT 1;'"
