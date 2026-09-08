-- migrations/006_metrics_scoring.sql
-- Time-series metrics and PQC risk scoring.

-- ── Protocol metrics snapshots ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS protocol_metrics (
    id              BIGSERIAL PRIMARY KEY,
    protocol        TEXT NOT NULL,
    metric_name     TEXT NOT NULL,
    value           FLOAT NOT NULL,
    unit            TEXT,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_metrics_protocol ON protocol_metrics(protocol);
CREATE INDEX IF NOT EXISTS idx_metrics_name     ON protocol_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_time     ON protocol_metrics(captured_at DESC);

-- ── PQC risk scoring ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pqc_scores (
    id              SERIAL PRIMARY KEY,
    protocol        TEXT NOT NULL UNIQUE,
    score           FLOAT NOT NULL DEFAULT 0.0
                      CHECK (score >= 0 AND score <= 100),
    grade           TEXT,
    risk_level      TEXT NOT NULL DEFAULT 'high'
                      CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    detail          JSONB,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO pqc_scores (protocol, score, grade, risk_level) VALUES
    ('ipsec', 0.0, 'F', 'critical'),
    ('ssh',   0.0, 'F', 'critical'),
    ('tls',   0.0, 'F', 'critical'),
    ('vpn',   0.0, 'F', 'critical')
ON CONFLICT (protocol) DO NOTHING;
