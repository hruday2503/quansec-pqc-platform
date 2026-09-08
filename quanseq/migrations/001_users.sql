-- migrations/001_users.sql
-- Users table for JWT authentication and RBAC.

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'operator'
                    CHECK (role IN ('admin', 'operator')),
    portal        TEXT NOT NULL DEFAULT 'main',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ── Audit events ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    detail      TEXT,
    severity    TEXT NOT NULL DEFAULT 'info'
                  CHECK (severity IN ('info', 'warning', 'critical')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_user    ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_action  ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_time    ON audit_events(occurred_at DESC);
