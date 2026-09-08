-- migrations/003_ipsec.sql
-- IPsec tunnel state and lifecycle events from StrongSwan VICI.

CREATE TABLE IF NOT EXISTS ipsec_tunnels (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    local_host      TEXT NOT NULL DEFAULT '',
    local_id        TEXT,
    remote_host     TEXT NOT NULL DEFAULT '',
    remote_id       TEXT,
    state           TEXT NOT NULL DEFAULT 'DOWN',
    ike_version     INTEGER NOT NULL DEFAULT 2,
    ike_proposal    TEXT,
    esp_proposal    TEXT,
    pqc_kem         TEXT,
    pqc_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    bytes_in        BIGINT NOT NULL DEFAULT 0,
    bytes_out       BIGINT NOT NULL DEFAULT 0,
    packets_in      BIGINT NOT NULL DEFAULT 0,
    packets_out     BIGINT NOT NULL DEFAULT 0,
    established_at  TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ipsec_tunnels_state ON ipsec_tunnels(state);
CREATE INDEX IF NOT EXISTS idx_ipsec_tunnels_pqc   ON ipsec_tunnels(pqc_enabled);
CREATE INDEX IF NOT EXISTS idx_ipsec_tunnels_seen  ON ipsec_tunnels(last_seen DESC);

-- ── IPsec lifecycle events ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipsec_events (
    id          BIGSERIAL PRIMARY KEY,
    tunnel_name TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    detail      JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ipsec_events_tunnel ON ipsec_events(tunnel_name);
CREATE INDEX IF NOT EXISTS idx_ipsec_events_type   ON ipsec_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ipsec_events_time   ON ipsec_events(occurred_at DESC);
