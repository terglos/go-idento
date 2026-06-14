-- Add the first-class guest (anonymous) identity column + its GC index, matching
-- the canonical schema (identity/migrations/postgres.sql) and the pgx stores'
-- Migrate. Additive and backward-compatible: existing rows default to false.

ALTER TABLE identity_users
    ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial index keyed on created_at so PurgeAnonymousUsers (delete guests older
-- than a cutoff) stays cheap.
CREATE INDEX IF NOT EXISTS ix_identity_users_guest
    ON identity_users (created_at) WHERE is_anonymous;
