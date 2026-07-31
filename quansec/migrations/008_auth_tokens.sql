-- migrations/008_auth_tokens.sql
-- Refresh-token families, rotation and theft detection.
--
-- WHY A TABLE AND NOT A STATELESS TOKEN
-- ------------------------------------
-- Access tokens are stateless JWTs and cannot be withdrawn before they expire;
-- that is why they live for 15 minutes. Revocation therefore has to bite at the
-- refresh layer, which means refresh tokens must be stored server-side. What is
-- stored is a SHA-256 hash, never the token: a dump of this table must not let
-- the reader authenticate as anybody.
--
-- FAMILIES
-- --------
-- Every login opens a family. Each refresh rotates the current token and links
-- the new one to its parent, so a family is a chain:
--
--     login -> t1 -> t2 -> t3        (t1, t2 rotated; t3 current)
--
-- A rotated token is single-use. If t2 is presented again after t3 exists, the
-- only explanations are theft or a cloned client, and neither is safe to serve,
-- so the whole family is revoked at once (RFC 6819 §5.2.2.3, OAuth 2.1 §6.1).
-- That is what `family_id` exists for: it makes "revoke everything descended
-- from this login" a single UPDATE rather than a recursive walk.

-- ── Refresh tokens ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    -- Surrogate key. The value the client holds is never stored, so rows are
    -- addressed by this and by `token_id`.
    id           BIGSERIAL PRIMARY KEY,

    -- Public identifier for this token, recorded in audit events so a session
    -- can be traced without ever writing the secret down.
    token_id     UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),

    -- All tokens descended from one login share this. Revoking a family means
    -- UPDATE ... WHERE family_id = $1.
    family_id    UUID NOT NULL,

    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- SHA-256 of the raw token, hex. UNIQUE both enforces "one row per token"
    -- and gives the lookup index used on every refresh.
    --
    -- SHA-256 rather than a password hash on purpose: this is a 256-bit random
    -- value, not a low-entropy secret, so there is nothing for Argon2 to defend
    -- against and a per-request KDF would only add latency to the hot path.
    token_hash   TEXT NOT NULL UNIQUE,

    -- Rotation chain. parent_id is the token this one replaced; replaced_by is
    -- the token that replaced this one. Both NULL for a current, first-issued
    -- token. `replaced_by IS NOT NULL` is precisely the reuse-detection trigger.
    parent_id    BIGINT REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    replaced_by  BIGINT REFERENCES refresh_tokens(id) ON DELETE SET NULL,

    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,

    -- Set on logout, revoke-all, or family revocation after a reuse. A token is
    -- valid only while this is NULL and expires_at is in the future.
    revoked_at   TIMESTAMPTZ,
    revoked_reason TEXT
        CHECK (revoked_reason IS NULL OR revoked_reason IN
               ('logout', 'rotated', 'revoke_all', 'reuse_detected',
                'password_change', 'admin_revoked', 'expired_cleanup')),

    -- Optional session metadata. Truncated by the application; useful for "sign
    -- out this device" and for making a stolen-token report intelligible.
    user_agent   TEXT,
    ip_address   INET,
    device_label TEXT
);

-- Hot path: look a presented token up by hash on every refresh.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash   ON refresh_tokens(token_hash);
-- Family revocation and "list my sessions".
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id);
-- Expiry sweep.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at)
    WHERE revoked_at IS NULL;

-- ── Audit metadata ───────────────────────────────────────────────────────────
-- audit_events (migration 001) already carries user_id, action, resource,
-- detail and severity. Authentication forensics also needs to answer "from
-- where", so add the network context. ADD COLUMN IF NOT EXISTS keeps this
-- re-runnable and leaves every existing row and every existing INSERT valid.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS ip_address INET;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Auth events are queried as a stream far more often than the rest of the
-- audit log, and always newest-first.
CREATE INDEX IF NOT EXISTS idx_audit_events_auth ON audit_events(occurred_at DESC)
    WHERE resource = 'auth';

-- ── Login throttling ─────────────────────────────────────────────────────────
-- Redis is the primary rate-limit store (see core/ratelimit.py). This table is
-- the durable fallback for when Redis is unreachable: losing the counter to a
-- cache restart must not silently disable brute-force protection.
CREATE TABLE IF NOT EXISTS auth_throttle (
    -- Hash of the subject being limited (IP, or IP+email). Hashed so the table
    -- does not become a list of who tried to log in from where.
    bucket_key   TEXT PRIMARY KEY,
    attempts     INTEGER NOT NULL DEFAULT 0,
    first_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_auth_throttle_last ON auth_throttle(last_at);
