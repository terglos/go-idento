-- Tables for the embedded OAuth 2.1 authorization server (package oauth):
-- registered clients (DCR / pre-registered), single-use authorization codes,
-- remembered consents and grants (refresh-token families). Codes, consents and
-- grants cascade with the owning user. Additive; matches the canonical schema
-- (identity/migrations/postgres.sql) and the pgx stores' Migrate.
CREATE TABLE IF NOT EXISTS identity_oauth_clients (
    client_id                  VARCHAR(512) PRIMARY KEY,
    secret_hash                VARCHAR(128) NOT NULL DEFAULT '',
    name                       VARCHAR(256) NOT NULL DEFAULT '',
    redirect_uris              TEXT         NOT NULL DEFAULT '[]',
    token_endpoint_auth_method VARCHAR(32)  NOT NULL DEFAULT '',
    grant_types                TEXT         NOT NULL DEFAULT '[]',
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at               TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS identity_oauth_codes (
    code_hash      VARCHAR(128) PRIMARY KEY,
    client_id      VARCHAR(512) NOT NULL,
    user_id        VARCHAR(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    redirect_uri   TEXT         NOT NULL,
    scopes         TEXT         NOT NULL DEFAULT '',
    resource       TEXT         NOT NULL DEFAULT '',
    code_challenge VARCHAR(128) NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL,
    used_at        TIMESTAMPTZ,
    grant_id       VARCHAR(36)  NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_codes_user ON identity_oauth_codes (user_id);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_codes_exp ON identity_oauth_codes (expires_at);

CREATE TABLE IF NOT EXISTS identity_oauth_consents (
    user_id    VARCHAR(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    client_id  VARCHAR(512) NOT NULL,
    scopes     TEXT         NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS identity_oauth_grants (
    id              VARCHAR(36)  PRIMARY KEY,
    user_id         VARCHAR(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    client_id       VARCHAR(512) NOT NULL,
    scopes          TEXT         NOT NULL DEFAULT '',
    resource        TEXT         NOT NULL DEFAULT '',
    token_hash      VARCHAR(128) NOT NULL DEFAULT '',
    prev_token_hash VARCHAR(128) NOT NULL DEFAULT '',
    security_stamp  VARCHAR(64)  NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_grants_user ON identity_oauth_grants (user_id);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_grants_client ON identity_oauth_grants (client_id);
CREATE INDEX IF NOT EXISTS ix_identity_oauth_grants_exp ON identity_oauth_grants (expires_at);
