-- migrations/005_siem_alerts_policies.sql
-- SIEM events, alert rules, alert firings, fail-mode, and policy tables.

-- ── SIEM events ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS siem_events (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info'
                  CHECK (severity IN ('info', 'warning', 'critical')),
    detail      JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_siem_source   ON siem_events(source);
CREATE INDEX IF NOT EXISTS idx_siem_severity ON siem_events(severity);
CREATE INDEX IF NOT EXISTS idx_siem_time     ON siem_events(occurred_at DESC);

-- ── Alert rules ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    protocol    TEXT NOT NULL,
    metric      TEXT NOT NULL,
    operator    TEXT NOT NULL,
    threshold   FLOAT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'warning',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Alert firings ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_firings (
    id          BIGSERIAL PRIMARY KEY,
    rule_id     INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
    rule_name   TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    value       FLOAT NOT NULL,
    threshold   FLOAT NOT NULL,
    detail      TEXT,
    fired_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_alert_firings_rule  ON alert_firings(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_firings_fired ON alert_firings(fired_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_firings_acked ON alert_firings(acknowledged);

-- ── Fail-mode policies ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fail_mode_policies (
    id          SERIAL PRIMARY KEY,
    protocol    TEXT NOT NULL UNIQUE,
    mode        TEXT NOT NULL DEFAULT 'fail-secure'
                  CHECK (mode IN ('fail-secure', 'fail-open')),
    description TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO fail_mode_policies (protocol, mode, description) VALUES
    ('ipsec', 'fail-secure', 'Block all traffic if IPsec SA cannot be established with PQC KEM'),
    ('ssh',   'fail-secure', 'Reject SSH sessions if hybrid KEX negotiation fails'),
    ('tls',   'fail-secure', 'Drop TLS connections that cannot negotiate PQC cipher suite'),
    ('vpn',   'fail-open',   'Allow VPN traffic with classical crypto as fallback')
ON CONFLICT (protocol) DO NOTHING;

-- ── IPsec policies ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipsec_policies (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    ike_version INTEGER NOT NULL DEFAULT 2,
    ike_proposal TEXT,
    esp_proposal TEXT,
    pqc_kem     TEXT,
    require_pqc BOOLEAN NOT NULL DEFAULT TRUE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── SSH policies ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_policies (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    require_pqc_kex BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_kex     TEXT[] NOT NULL DEFAULT ARRAY['mlkem768x25519-sha256'],
    require_cert    BOOLEAN NOT NULL DEFAULT FALSE,
    max_session_ttl INTEGER NOT NULL DEFAULT 3600,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ssh_policies (name, require_pqc_kex, allowed_kex, require_cert, max_session_ttl) VALUES
    ('default-pqc', TRUE, ARRAY['mlkem768x25519-sha256', 'sntrup761x25519-sha512@openssh.com'], FALSE, 3600)
ON CONFLICT (name) DO NOTHING;
