-- migrations/004_ssh.sql
-- SSH session monitoring and ZTA audit log.

CREATE TABLE IF NOT EXISTS ssh_connections (
    id              SERIAL PRIMARY KEY,
    session_key     TEXT NOT NULL UNIQUE,
    local_host      TEXT NOT NULL DEFAULT 'localhost',
    remote_host     TEXT NOT NULL DEFAULT '',
    remote_user     TEXT,
    kex_algorithm   TEXT,
    kem_label       TEXT,
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    state           TEXT NOT NULL DEFAULT 'ACTIVE'
                      CHECK (state IN ('ACTIVE', 'CLOSED')),
    bytes_sent      BIGINT NOT NULL DEFAULT 0,
    bytes_received  BIGINT NOT NULL DEFAULT 0,
    established_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ssh_conn_state  ON ssh_connections(state);
CREATE INDEX IF NOT EXISTS idx_ssh_conn_pqc    ON ssh_connections(pqc_enabled);
CREATE INDEX IF NOT EXISTS idx_ssh_conn_seen   ON ssh_connections(last_seen DESC);

-- ── SSH certificate audit ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_cert_audit (
    id              BIGSERIAL PRIMARY KEY,
    serial          BIGINT,
    key_id          TEXT,
    principals      TEXT[],
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    algorithm       TEXT,
    valid_after     TIMESTAMPTZ,
    valid_before    TIMESTAMPTZ,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ssh_cert_issued ON ssh_cert_audit(issued_at DESC);

-- ── Zero Trust SSH audit ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS zt_ssh_audit (
    id              BIGSERIAL PRIMARY KEY,
    session_key     TEXT,
    remote_user     TEXT,
    remote_host     TEXT,
    kex_algorithm   TEXT,
    kem_label       TEXT,
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    trust_score     FLOAT,
    risk_flags      TEXT[],
    decision        TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_zt_audit_time    ON zt_ssh_audit(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_zt_audit_session ON zt_ssh_audit(session_key);
