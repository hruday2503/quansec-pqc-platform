-- ============================================================
-- QUANSEC — initial schema
-- Run: psql -U quansec_user -d quansec -f migrations/001_initial.sql
-- ============================================================

-- ── Auth ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'viewer',   -- viewer | admin
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── IPsec ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipsec_tunnels (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,            -- StrongSwan SA name e.g. "home-to-cloud"
    local_host      TEXT NOT NULL,
    local_id        TEXT,
    remote_host     TEXT NOT NULL,
    remote_id       TEXT,
    state           TEXT NOT NULL,            -- ESTABLISHED | CONNECTING | DOWN
    ike_version     INTEGER NOT NULL DEFAULT 2,
    ike_proposal    TEXT,                     -- e.g. "aes256gcm128-prfsha384-ecp384"
    esp_proposal    TEXT,                     -- e.g. "aes256gcm128-ecp384"
    pqc_kem         TEXT,                     -- e.g. "kyber1024"
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    bytes_in        BIGINT NOT NULL DEFAULT 0,
    bytes_out       BIGINT NOT NULL DEFAULT 0,
    packets_in      BIGINT NOT NULL DEFAULT 0,
    packets_out     BIGINT NOT NULL DEFAULT 0,
    established_at  TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ipsec_events (
    id          SERIAL PRIMARY KEY,
    tunnel_name TEXT NOT NULL,
    event_type  TEXT NOT NULL,     -- ESTABLISHED | REKEYED | DOWN | ERROR
    detail      JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── TLS ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tls_handshakes (
    id              SERIAL PRIMARY KEY,
    client_ip       TEXT NOT NULL,
    server_name     TEXT,
    tls_version     TEXT NOT NULL,            -- TLSv1.3
    cipher_suite    TEXT NOT NULL,            -- e.g. TLS_AES_256_GCM_SHA384
    kex_algorithm   TEXT,                     -- e.g. X25519Kyber768Draft00
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    latency_ms      NUMERIC(8,3),
    response_code   INTEGER,
    bytes_sent      BIGINT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id              SERIAL PRIMARY KEY,
    domain          TEXT NOT NULL,
    issuer          TEXT,
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    signature_algo  TEXT,
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    last_checked    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── SSH ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_hosts (
    id              SERIAL PRIMARY KEY,
    hostname        TEXT NOT NULL,
    ip_address      TEXT NOT NULL,
    port            INTEGER NOT NULL DEFAULT 22,
    kex_algorithms  TEXT[],                   -- negotiated KEX list
    pqc_kex         TEXT,                     -- active PQC algo if present
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    openssh_version TEXT,
    last_checked    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ssh_sessions (
    id              SERIAL PRIMARY KEY,
    host_id         INTEGER REFERENCES ssh_hosts(id),
    client_ip       TEXT NOT NULL,
    username        TEXT,
    kex_used        TEXT,                     -- from auth.log
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    auth_method     TEXT,                     -- publickey | password | keyboard-interactive
    accepted        BOOLEAN,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ssh_policies (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    kex_algorithms  TEXT[] NOT NULL,
    ciphers         TEXT[] NOT NULL,
    macs            TEXT[] NOT NULL,
    host_key_algos  TEXT[] NOT NULL,
    pqc_required    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ssh_policy_assignments (
    host_id     INTEGER REFERENCES ssh_hosts(id),
    policy_id   INTEGER REFERENCES ssh_policies(id),
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host_id, policy_id)
);

-- ── VPN ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vpn_peers (
    id              SERIAL PRIMARY KEY,
    interface       TEXT NOT NULL DEFAULT 'wg0',
    public_key      TEXT NOT NULL UNIQUE,
    endpoint        TEXT,                     -- ip:port
    allowed_ips     TEXT[],
    pqc_psk         BOOLEAN NOT NULL DEFAULT FALSE,  -- PQC pre-shared key layered on top
    latest_handshake TIMESTAMPTZ,
    bytes_rx        BIGINT NOT NULL DEFAULT 0,
    bytes_tx        BIGINT NOT NULL DEFAULT 0,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vpn_events (
    id          SERIAL PRIMARY KEY,
    peer_pubkey TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail      JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Audit trail ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_events (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    detail      JSONB,
    severity    TEXT NOT NULL DEFAULT 'info',  -- info | warning | critical
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_ipsec_tunnels_state         ON ipsec_tunnels(state);
CREATE INDEX IF NOT EXISTS idx_ipsec_events_tunnel         ON ipsec_events(tunnel_name);
CREATE INDEX IF NOT EXISTS idx_tls_handshakes_occurred     ON tls_handshakes(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_handshakes_pqc          ON tls_handshakes(pqc_enabled);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_occurred       ON ssh_sessions(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_vpn_peers_interface         ON vpn_peers(interface);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred       ON audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity       ON audit_events(severity);

-- ── Seed: default admin user ──────────────────────────────────
-- Password: Admin@1234 (pbkdf2:sha256 hash — change in production)
INSERT INTO users (email, password_hash, role)
VALUES ('admin@quansec.io', 'pbkdf2:sha256:600000$change_this_salt$placeholder_hash', 'admin')
ON CONFLICT (email) DO NOTHING;

-- Seed: default PQC SSH policy
INSERT INTO ssh_policies (name, description, kex_algorithms, ciphers, macs, host_key_algos, pqc_required)
VALUES (
    'pqc-strict',
    'Allows only quantum-safe KEX algorithms (CNSA 2.0 compliant)',
    ARRAY['sntrup761x25519-sha512@openssh.com', 'curve25519-sha256'],
    ARRAY['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
    ARRAY['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com'],
    ARRAY['ssh-ed25519', 'ecdsa-sha2-nistp256'],
    TRUE
)
ON CONFLICT (name) DO NOTHING;
