-- migrations/009_api_key_scopes.sql
-- Move API keys onto the real scope vocabulary.
--
-- `api_keys.scopes` (migration 002) defaulted to ARRAY['read'] — a placeholder
-- from before scopes existed. It named nothing the authorization layer
-- understands, so it could not be enforced and was ignored.
--
-- Keys now carry scopes from core/scopes.py, which means a key can be NARROWED
-- to exactly what an integration needs (`tls:read` for a monitoring scraper)
-- instead of inheriting everything its owner can do.
--
-- A key is never allowed to exceed its owner: core/auth.py intersects the
-- stored scopes with the owner's current role scopes on every request, so
-- demoting a user immediately shrinks the reach of every key they created.

-- Existing rows: 'read' meant "whatever the owner can read". Translate it to
-- the three read scopes rather than dropping it, so keys in use keep working.
UPDATE api_keys
SET scopes = ARRAY['tls:read', 'ssh:read', 'ipsec:read']
WHERE scopes = ARRAY['read']
   OR scopes = ARRAY['read']::text[]
   OR scopes IS NULL
   OR cardinality(scopes) = 0;

-- Anything else non-conforming (e.g. a hand-inserted 'write') is also mapped to
-- read-only. Widening on migration would be a silent privilege grant; narrowing
-- is the safe direction, and the key can be reissued if more was intended.
UPDATE api_keys
SET scopes = ARRAY['tls:read', 'ssh:read', 'ipsec:read']
WHERE NOT (scopes <@ ARRAY['tls:read','tls:admin','ssh:read','ssh:admin',
                           'ipsec:read','ipsec:admin','system:admin']::text[]);

ALTER TABLE api_keys ALTER COLUMN scopes
    SET DEFAULT ARRAY['tls:read', 'ssh:read', 'ipsec:read']::text[];

-- Which protocol module a key was created for. Presentation only — enforcement
-- is by scope — but it lets each portal list the keys issued from it.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS protocol TEXT
    CHECK (protocol IS NULL OR protocol IN ('tls', 'ssh', 'ipsec', 'main'));

-- Optional expiry. NULL keeps the previous never-expires behaviour so no
-- existing key stops working when this migration runs.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_api_keys_protocol ON api_keys(protocol);
CREATE INDEX IF NOT EXISTS idx_api_keys_active   ON api_keys(user_id)
    WHERE revoked_at IS NULL;
