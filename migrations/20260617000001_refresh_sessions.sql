-- Add the refresh-session table (multi-session refresh tokens: one row per
-- device/browser session), matching the canonical schema and the pgx stores'
-- Migrate. Additive; enables TokenService.WithSessionStore. The opaque token is
-- "<session_id>.<secret>"; only the secret's hash is stored.

CREATE TABLE IF NOT EXISTS identity_refresh_tokens (
    session_id   VARCHAR(36)  PRIMARY KEY,
    user_id      VARCHAR(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    token_hash   VARCHAR(128) NOT NULL,
    name         VARCHAR(256) NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_refresh_tokens_hash ON identity_refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS ix_identity_refresh_tokens_user ON identity_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS ix_identity_refresh_tokens_exp ON identity_refresh_tokens (expires_at);
