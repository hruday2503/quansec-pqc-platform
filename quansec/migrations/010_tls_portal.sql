-- migrations/010_tls_portal.sql
-- TLS portal: policy history and rollback, TLS-specific alerts, WebSocket
-- tickets, and the session columns the portal reports on.
--
-- run_migrations() re-executes every .sql file on each startup, so everything
-- here is additive and idempotent. No column is dropped or renamed: the
-- collector, router and models in protocols/tls/ read the 007 names, and
-- renaming would break them for no gain. Where this file adds a column whose
-- spec name differs from the stored name, the mapping is done in the API layer
-- and noted below.
--
-- Existing IPsec and SSH data is untouched by design — nothing here references
-- their tables.

-- ── tls_sessions: portal reporting columns ───────────────────────────────────
-- Names already present under a different spelling, mapped in models.py:
--     client_ip        -> remote_addr   (007)
--     tls_version      -> tls_protocol  (007)
--     bytes_sent       -> bytes_sent    (007, unchanged)
--
-- Everything below is genuinely new. All are nullable or defaulted, so the
-- rows the collector has already written stay valid and are simply reported as
-- "not recorded" rather than being back-filled with invented values.

ALTER TABLE tls_sessions
    -- Stable identifier for one connection, derived by the collector from
    -- $connection and $connection_requests. Distinct from `id`, which is a
    -- per-log-line surrogate: several requests share one connection.
    ADD COLUMN IF NOT EXISTS connection_id TEXT,

    -- Whether THIS handshake negotiated the hybrid group, per $ssl_curve.
    -- Deliberately separate from pqc_enabled (007), which the collector derives
    -- from the group name. NULL means the log did not report a group, which is
    -- not the same as classical — a resumed session performs no key exchange.
    ADD COLUMN IF NOT EXISTS hybrid_negotiated BOOLEAN,

    -- The SERVER certificate's signature algorithm. Filled from the
    -- certificate inventory, never from the handshake: hybrid key exchange
    -- does not change how the certificate was signed.
    ADD COLUMN IF NOT EXISTS certificate_signature_algorithm TEXT,

    -- Whether the listener that served this session required a client
    -- certificate. Config-derived, and marked as such in evidence_source.
    ADD COLUMN IF NOT EXISTS mtls_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Result of mTLS client-certificate verification ($ssl_client_verify).
    -- NULL when mTLS was not in force. NOT the same as server-certificate
    -- verification, which only a client-side probe can establish.
    ADD COLUMN IF NOT EXISTS client_certificate_verified BOOLEAN,

    -- Connection lifetime. started_at is the first log line for the
    -- connection, last_seen the most recent; request_count counts lines.
    ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS request_count INTEGER NOT NULL DEFAULT 1,

    -- Where this row's facts came from. The portal shows it so a reader can
    -- tell a logged observation from a probe result without trusting the UI.
    ADD COLUMN IF NOT EXISTS evidence_source TEXT NOT NULL DEFAULT 'nginx_access_log';

-- Guard the vocabulary rather than leaving it free text. Added separately so a
-- re-run does not fail on an existing constraint.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tls_sessions_evidence_source_chk') THEN
        ALTER TABLE tls_sessions ADD CONSTRAINT tls_sessions_evidence_source_chk
            CHECK (evidence_source IN ('nginx_access_log', 'openssl_probe', 'dataplane_echo'));
    END IF;
END $$;

-- Back-fill the lifetime columns from what 007 already recorded. This is a
-- restatement of existing data, not an invention: occurred_at is the line's
-- own timestamp.
UPDATE tls_sessions
   SET started_at = COALESCE(started_at, occurred_at),
       last_seen  = COALESCE(last_seen, occurred_at)
 WHERE started_at IS NULL OR last_seen IS NULL;

-- hybrid_negotiated is derivable from the recorded group, so back-fill it from
-- negotiated_group alone. Rows with no group stay NULL — "not reported".
UPDATE tls_sessions
   SET hybrid_negotiated = (negotiated_group ILIKE '%MLKEM%')
 WHERE hybrid_negotiated IS NULL AND negotiated_group IS NOT NULL
                                AND negotiated_group <> '';

CREATE INDEX IF NOT EXISTS idx_tls_sessions_connection ON tls_sessions(connection_id);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_last_seen  ON tls_sessions(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_hybrid     ON tls_sessions(hybrid_negotiated);

-- ── Policy history and rollback ──────────────────────────────────────────────
-- tls_policy_state (007) holds what is running now. This holds every
-- transition, so a rollback has something to roll back TO and an auditor can
-- see who changed what and whether it stuck.
--
-- previous_config is the full text of the nginx.conf that was live before this
-- apply. Storing the file rather than a diff is what makes rollback a restore
-- instead of a re-render, which matters when the renderer itself is the bug.
CREATE TABLE IF NOT EXISTS tls_policy_history (
    id                BIGSERIAL PRIMARY KEY,
    policy_name       TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,

    -- The rendered config this row applied, and the one it replaced. NULL
    -- previous_* means this was the first policy ever applied.
    configuration      TEXT NOT NULL,
    previous_policy    TEXT,
    previous_config    TEXT,
    previous_hash      TEXT,

    applied_by        TEXT NOT NULL,
    applied_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- How the apply ended. 'rolled_back' means validation or the health probe
    -- failed and the previous config was restored automatically.
    rollback_status   TEXT NOT NULL DEFAULT 'applied'
                        CHECK (rollback_status IN ('applied', 'rolled_back',
                                                   'rollback_failed', 'superseded')),
    rollback_reason   TEXT,
    health_probe_passed BOOLEAN,
    validated         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_tls_policy_hist_time ON tls_policy_history(applied_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_policy_hist_name ON tls_policy_history(policy_name);

-- ── TLS alerts ───────────────────────────────────────────────────────────────
-- Separate from the shared `alerts` table so TLS evidence keeps its own
-- vocabulary and acknowledgement trail. Every alert names the evidence that
-- raised it; none is raised from configuration alone.
CREATE TABLE IF NOT EXISTS tls_alerts (
    id            BIGSERIAL PRIMARY KEY,
    alert_type    TEXT NOT NULL
                    CHECK (alert_type IN (
                        'transport_unreachable',
                        'stale_telemetry',
                        'classical_group_negotiated',
                        'unknown_group_negotiated',
                        'obsolete_protocol_negotiated',
                        'weak_cipher_negotiated',
                        'hybrid_probe_failed',
                        'classical_client_accepted',
                        'certificate_expired',
                        'certificate_expiring',
                        'certificate_verification_failed',
                        'mtls_verification_failed',
                        'policy_reload_failed',
                        'policy_rolled_back',
                        'api_key_abuse',
                        'refresh_token_reuse')),
    severity      TEXT NOT NULL DEFAULT 'warning'
                    CHECK (severity IN ('info', 'warning', 'critical')),
    summary       TEXT NOT NULL,

    -- What raised it. session_id points at the observation; detail carries the
    -- probe output, log line or counter that justifies the alert.
    session_id    BIGINT REFERENCES tls_sessions(id) ON DELETE SET NULL,
    detail        JSONB,

    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Acknowledgement is audited: who, when, and why.
    acknowledged     BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by  TEXT,
    acknowledged_at  TIMESTAMPTZ,
    acknowledgement_note TEXT,

    -- Lets the alert engine avoid re-raising the same condition every cycle
    -- while still recording that it is ongoing.
    dedupe_key    TEXT
);

CREATE INDEX IF NOT EXISTS idx_tls_alerts_time   ON tls_alerts(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_alerts_ack    ON tls_alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_tls_alerts_type   ON tls_alerts(alert_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_alerts_dedupe
    ON tls_alerts(dedupe_key) WHERE acknowledged = FALSE AND dedupe_key IS NOT NULL;

-- ── WebSocket tickets ────────────────────────────────────────────────────────
-- A short-lived, single-use ticket exchanged for a live-events socket.
--
-- The socket cannot read an Authorization header during the handshake, and a
-- long-lived JWT in the query string would be written to every proxy and
-- access log it passes through — including the NGINX log this very module
-- collects. A ticket is minted by an already-authenticated request, is valid
-- for seconds, and is burned on first use, so a logged URL leaks nothing
-- reusable.
--
-- Only the SHA-256 hash is stored, for the same reason api_keys stores a hash.
CREATE TABLE IF NOT EXISTS ws_tickets (
    id          BIGSERIAL PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    portal      TEXT,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    ip_address  TEXT
);

CREATE INDEX IF NOT EXISTS idx_ws_tickets_expiry ON ws_tickets(expires_at);

-- ── api_keys: portal columns ─────────────────────────────────────────────────
-- 009 already added protocol, scopes and expires_at. `created_by` in the spec
-- is the existing user_id foreign key; adding a second owner column would
-- create two sources of truth, so it is not added here.
--
-- What is missing is a record of WHY a key stopped working, which the portal
-- must distinguish: revoked by a person, or simply expired.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS revoked_by TEXT,
    ADD COLUMN IF NOT EXISTS revoke_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_api_keys_protocol ON api_keys(protocol);
CREATE INDEX IF NOT EXISTS idx_api_keys_expiry   ON api_keys(expires_at);
