-- Schema for the sqlc-generated pgx store. Columns are NOT NULL with defaults so
-- sqlc emits plain Go types (string/bool/int) instead of pgtype wrappers;
-- lockout_end stays nullable (-> *time.Time via the override in sqlc.yaml).
CREATE TABLE IF NOT EXISTS identity_users (
    id                     varchar(36) PRIMARY KEY,
    user_name              varchar(256) NOT NULL DEFAULT '',
    normalized_user_name   varchar(256) NOT NULL DEFAULT '',
    email                  varchar(256) NOT NULL DEFAULT '',
    normalized_email       varchar(256) NOT NULL DEFAULT '',
    email_confirmed        boolean      NOT NULL DEFAULT false,
    password_hash          varchar(256) NOT NULL DEFAULT '',
    security_stamp         varchar(64)  NOT NULL DEFAULT '',
    concurrency_stamp      varchar(64)  NOT NULL DEFAULT '',
    phone_number           varchar(32)  NOT NULL DEFAULT '',
    phone_number_confirmed boolean      NOT NULL DEFAULT false,
    two_factor_enabled     boolean      NOT NULL DEFAULT false,
    lockout_end            timestamptz,
    lockout_enabled        boolean      NOT NULL DEFAULT false,
    access_failed_count    integer      NOT NULL DEFAULT 0,
    attributes             jsonb        NOT NULL DEFAULT '{}'::jsonb,
    is_anonymous           boolean      NOT NULL DEFAULT false,
    created_at             timestamptz  NOT NULL DEFAULT now(),
    updated_at             timestamptz  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_users_uname ON identity_users (normalized_user_name);
CREATE INDEX IF NOT EXISTS ix_identity_users_email ON identity_users (normalized_email);
CREATE INDEX IF NOT EXISTS ix_identity_users_guest ON identity_users (created_at) WHERE is_anonymous;

CREATE TABLE IF NOT EXISTS identity_roles (
    id                varchar(36) PRIMARY KEY,
    name              varchar(256) NOT NULL DEFAULT '',
    normalized_name   varchar(256) NOT NULL DEFAULT '',
    concurrency_stamp varchar(64)  NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_roles_name ON identity_roles (normalized_name);

CREATE TABLE IF NOT EXISTS identity_user_roles (
    user_id varchar(36) NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    role_id varchar(36) NOT NULL REFERENCES identity_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS identity_user_claims (
    id          bigserial PRIMARY KEY,
    user_id     varchar(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    claim_type  varchar(256) NOT NULL DEFAULT '',
    claim_value varchar(256) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_identity_user_claims_user ON identity_user_claims (user_id);

CREATE TABLE IF NOT EXISTS identity_role_claims (
    id          bigserial PRIMARY KEY,
    role_id     varchar(36)  NOT NULL REFERENCES identity_roles(id) ON DELETE CASCADE,
    claim_type  varchar(256) NOT NULL DEFAULT '',
    claim_value varchar(256) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_identity_role_claims_role ON identity_role_claims (role_id);

CREATE TABLE IF NOT EXISTS identity_user_logins (
    login_provider        varchar(128) NOT NULL,
    provider_key          varchar(128) NOT NULL,
    provider_display_name varchar(128) NOT NULL DEFAULT '',
    user_id               varchar(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    PRIMARY KEY (login_provider, provider_key)
);
CREATE INDEX IF NOT EXISTS ix_identity_user_logins_user ON identity_user_logins (user_id);

CREATE TABLE IF NOT EXISTS identity_user_tokens (
    user_id        varchar(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    login_provider varchar(128) NOT NULL,
    name           varchar(128) NOT NULL,
    value          text         NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, login_provider, name)
);

CREATE TABLE IF NOT EXISTS identity_api_keys (
    id           varchar(36)  PRIMARY KEY,
    user_id      varchar(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    name         varchar(256) NOT NULL DEFAULT '',
    prefix       varchar(32)  NOT NULL DEFAULT '',
    key_hash     varchar(128) NOT NULL,
    scopes       jsonb        NOT NULL DEFAULT '[]'::jsonb,
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_api_keys_hash ON identity_api_keys (key_hash);
CREATE INDEX IF NOT EXISTS ix_identity_api_keys_user ON identity_api_keys (user_id);

CREATE TABLE IF NOT EXISTS identity_refresh_tokens (
    session_id   varchar(36)  PRIMARY KEY,
    user_id      varchar(36)  NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    token_hash   varchar(128) NOT NULL,
    name         varchar(256) NOT NULL DEFAULT '',
    expires_at   timestamptz  NOT NULL,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_refresh_tokens_hash ON identity_refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS ix_identity_refresh_tokens_user ON identity_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS ix_identity_refresh_tokens_exp ON identity_refresh_tokens (expires_at);
