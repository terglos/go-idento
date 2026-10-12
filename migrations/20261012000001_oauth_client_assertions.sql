-- Used client-assertion ids for the embedded OAuth server's private_key_jwt
-- client authentication (RFC 7523): each (client_id, jti) is accepted once,
-- across every instance sharing the database. Rows expire with the assertion
-- and are removed by oauth.Server.PurgeExpired. Additive; matches the
-- canonical schema (identity/migrations/postgres.sql) and the pgx stores'
-- Migrate.
CREATE TABLE IF NOT EXISTS identity_oauth_assertions (
    client_id  VARCHAR(512) NOT NULL,
    jti        VARCHAR(256) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (client_id, jti)
);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_assertions_exp ON identity_oauth_assertions (expires_at);
