-- Add the opaque API-key table (first-class machine-to-machine credentials),
-- matching the canonical schema (identity/migrations/postgres.sql) and the pgx
-- stores' Migrate. Additive; the secret is never stored — only its hash + a
-- display prefix. FK cascades with the owning user.

CREATE TABLE IF NOT EXISTS identity_api_keys (
    id           VARCHAR(36)  PRIMARY KEY,
    user_id      VARCHAR(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    name         VARCHAR(256) NOT NULL DEFAULT '',
    prefix       VARCHAR(32)  NOT NULL DEFAULT '',
    key_hash     VARCHAR(128) NOT NULL,
    scopes       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_api_keys_hash ON identity_api_keys (key_hash);
CREATE INDEX IF NOT EXISTS ix_identity_api_keys_user ON identity_api_keys (user_id);
