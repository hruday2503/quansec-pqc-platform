-- migrations/007_tls.sql
-- TLS module: sessions observed in NGINX logs, lifecycle events, policy state,
-- and enforcement probe results.
--
-- The TLS data plane is NGINX linked against OpenSSL 3.5.7, configured
-- fail-closed on X25519MLKEM768. Everything in these tables originates from
-- something that actually happened: a line in the NGINX access log, an action
-- the policy engine took, or a handshake an OpenSSL client attempted.
--
-- Nothing here may be populated from configuration. A group is recorded because
-- NGINX logged it; enforcement is recorded because a classical client was
-- refused. See protocols/tls/service.py for how status is derived from these.

-- ── Superseding the Python-transport schema ──────────────────────────────────
-- run_migrations() re-executes every .sql file on each startup, so nothing here
-- may be destructive on a second run.
--
-- tls_hybrid_evidence recorded only hybrid verification attempts. It is fully
-- replaced by tls_probe_results, which records the whole positive/negative
-- matrix, so an unconditional drop is safe: no new table reuses the name.
DROP TABLE IF EXISTS tls_hybrid_evidence;

-- tls_sessions exists under both schemas, so it needs a guarded drop. The old
-- Python-transport shape is identified by its `server_host` column, which the
-- NGINX-log shape does not have. This fires exactly once, on the first startup
-- after the upgrade, and is a no-op every time after that.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tls_sessions' AND column_name = 'server_host'
    ) THEN
        RAISE NOTICE 'Dropping pre-NGINX tls_sessions (Python-transport schema)';
        DROP TABLE tls_sessions;
    END IF;
END $$;

-- ── Observed TLS sessions ─────────────────────────────────────────────────────
-- One row per NGINX access-log line. Written only by protocols/tls/collector.py.
CREATE TABLE IF NOT EXISTS tls_sessions (
    id               BIGSERIAL PRIMARY KEY,

    -- Straight from the log line.
    occurred_at      TIMESTAMPTZ NOT NULL,
    remote_addr      TEXT,
    remote_port      TEXT,
    tls_protocol     TEXT,
    cipher           TEXT,

    -- $ssl_curve: the group NGINX actually negotiated. NULL when the log field
    -- was empty (a resumed session performs no key exchange). NULL means
    -- "not reported", never "classical" — the UI must not conflate them.
    negotiated_group TEXT,
    -- $ssl_curves: groups the client offered. Best-effort; may be empty.
    client_groups    TEXT,

    client_verify    TEXT,          -- $ssl_client_verify: NONE | SUCCESS | FAILED
    client_s_dn      TEXT,          -- present only under mTLS
    server_name      TEXT,          -- $ssl_server_name (SNI)
    session_reused   BOOLEAN NOT NULL DEFAULT FALSE,

    http_status      INTEGER,
    request_time     DOUBLE PRECISION,
    bytes_sent       BIGINT,
    request_line     TEXT,

    -- Derived, but only from the recorded group name — never from config.
    pqc_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    kem_label        TEXT,

    -- Provenance: byte offset in the source log, so a row can be traced back to
    -- the exact line and the collector can prove it never invented one.
    log_source       TEXT NOT NULL,
    log_offset       BIGINT NOT NULL,
    raw_line         TEXT NOT NULL,

    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (log_source, log_offset)
);

CREATE INDEX IF NOT EXISTS idx_tls_sessions_time     ON tls_sessions(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_group    ON tls_sessions(negotiated_group);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_pqc      ON tls_sessions(pqc_enabled);
CREATE INDEX IF NOT EXISTS idx_tls_sessions_protocol ON tls_sessions(tls_protocol);

-- ── Lifecycle and policy events ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tls_events (
    id           BIGSERIAL PRIMARY KEY,
    event_type   TEXT NOT NULL
                   CHECK (event_type IN ('service_start', 'service_stop', 'service_reload',
                                         'config_validated', 'config_rejected',
                                         'policy_applied', 'probe_run',
                                         'enforcement_verified', 'enforcement_regressed',
                                         'collector_error')),
    severity     TEXT NOT NULL DEFAULT 'info'
                   CHECK (severity IN ('info', 'warning', 'critical')),
    summary      TEXT NOT NULL,
    detail       JSONB,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_events_time ON tls_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_events_type ON tls_events(event_type);

-- ── Policy state ──────────────────────────────────────────────────────────────
-- What the running NGINX is actually configured to do. config_sha256 is the
-- hash of the rendered nginx.conf, so status reporting can tell whether the
-- file on disk is the one the running process loaded.
CREATE TABLE IF NOT EXISTS tls_policy_state (
    id             BIGSERIAL PRIMARY KEY,
    policy_name    TEXT NOT NULL,
    ssl_protocols  TEXT NOT NULL,
    groups         TEXT NOT NULL,
    ciphersuites   TEXT,
    mtls_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    early_data     BOOLEAN NOT NULL DEFAULT FALSE,
    listen_addr    TEXT NOT NULL,
    config_path    TEXT NOT NULL,
    config_sha256  TEXT NOT NULL,
    validated      BOOLEAN NOT NULL DEFAULT FALSE,   -- nginx -t passed
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    applied_by     TEXT,
    applied_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_policy_applied ON tls_policy_state(applied_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_policy_active  ON tls_policy_state(active);

-- ── Enforcement probe results ─────────────────────────────────────────────────
-- The positive hybrid handshake and every negative test. A negative probe
-- "passes" when the handshake FAILS: that is what proves fail-closed
-- enforcement. expected_outcome makes the assertion explicit in the data.
CREATE TABLE IF NOT EXISTS tls_probe_results (
    id               BIGSERIAL PRIMARY KEY,
    probe_type       TEXT NOT NULL
                       CHECK (probe_type IN ('positive_hybrid',
                                             'negative_x25519',
                                             'negative_prime256v1',
                                             'negative_tls12',
                                             'negative_aes128',
                                             'negative_invalid_ca',
                                             'negative_missing_client_cert')),
    expected_outcome TEXT NOT NULL CHECK (expected_outcome IN ('connect', 'reject')),
    actual_outcome   TEXT NOT NULL CHECK (actual_outcome IN ('connect', 'reject', 'error')),
    passed           BOOLEAN NOT NULL,

    target_host      TEXT NOT NULL,
    target_port      INTEGER NOT NULL,
    negotiated_group TEXT,
    negotiated_cipher TEXT,
    tls_protocol     TEXT,
    verify_result    TEXT,

    -- Which binary produced this. Must be the runtime OpenSSL 3.5.7, not the
    -- system 3.0.13 — recorded so a reader can check rather than trust.
    openssl_binary   TEXT NOT NULL,
    openssl_version  TEXT,
    command          TEXT NOT NULL,
    exit_code        INTEGER,
    stdout_excerpt   TEXT,
    evidence_path    TEXT,

    run_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_probe_time   ON tls_probe_results(run_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_probe_type   ON tls_probe_results(probe_type);
CREATE INDEX IF NOT EXISTS idx_tls_probe_passed ON tls_probe_results(passed);

-- ── Certificate inventory ─────────────────────────────────────────────────────
-- Certificate authentication is reported SEPARATELY from key establishment.
-- X25519MLKEM768 makes the key exchange hybrid post-quantum; an RSA or ECDSA
-- certificate leaves authentication classical. pqc_signature is set from a
-- signature-OID lookup so it becomes true only when an ML-DSA certificate is
-- genuinely in use.
CREATE TABLE IF NOT EXISTS tls_certificates (
    id                   SERIAL PRIMARY KEY,
    server_name          TEXT NOT NULL,
    subject              TEXT,
    issuer               TEXT,
    serial_number        TEXT,
    signature_algorithm  TEXT,
    public_key_algorithm TEXT,
    key_size             INTEGER,
    pqc_signature        BOOLEAN NOT NULL DEFAULT FALSE,
    chain_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    not_before           TIMESTAMPTZ,
    not_after            TIMESTAMPTZ,
    last_checked         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_name, serial_number)
);

CREATE INDEX IF NOT EXISTS idx_tls_certs_expiry ON tls_certificates(not_after);
