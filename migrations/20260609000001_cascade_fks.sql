-- Add ON DELETE CASCADE foreign keys from the satellite tables to users/roles,
-- bringing databases created from the baseline in line with the canonical
-- schema (identity/migrations/postgres.sql) and the pgx stores' Migrate.
-- Orphan rows (references to since-deleted users/roles) are removed first so
-- the constraints can be validated.
--
-- Intended for databases created from the baseline migration. A database
-- created by pgxstore.Migrate/pgxsqlc.Migrate already has these FKs under
-- auto-generated names; running this there adds redundant (harmless) duplicate
-- constraints — skip it in that case.

DELETE FROM identity_user_roles ur WHERE NOT EXISTS (SELECT 1 FROM identity_users u WHERE u.id = ur.user_id);
DELETE FROM identity_user_roles ur WHERE NOT EXISTS (SELECT 1 FROM identity_roles r WHERE r.id = ur.role_id);
DELETE FROM identity_user_claims uc WHERE NOT EXISTS (SELECT 1 FROM identity_users u WHERE u.id = uc.user_id);
DELETE FROM identity_role_claims rc WHERE NOT EXISTS (SELECT 1 FROM identity_roles r WHERE r.id = rc.role_id);
DELETE FROM identity_user_logins ul WHERE NOT EXISTS (SELECT 1 FROM identity_users u WHERE u.id = ul.user_id);
DELETE FROM identity_user_tokens ut WHERE NOT EXISTS (SELECT 1 FROM identity_users u WHERE u.id = ut.user_id);

ALTER TABLE identity_user_roles
    ADD CONSTRAINT fk_identity_user_roles_user FOREIGN KEY (user_id) REFERENCES identity_users(id) ON DELETE CASCADE,
    ADD CONSTRAINT fk_identity_user_roles_role FOREIGN KEY (role_id) REFERENCES identity_roles(id) ON DELETE CASCADE;

ALTER TABLE identity_user_claims
    ADD CONSTRAINT fk_identity_user_claims_user FOREIGN KEY (user_id) REFERENCES identity_users(id) ON DELETE CASCADE;

ALTER TABLE identity_role_claims
    ADD CONSTRAINT fk_identity_role_claims_role FOREIGN KEY (role_id) REFERENCES identity_roles(id) ON DELETE CASCADE;

ALTER TABLE identity_user_logins
    ADD CONSTRAINT fk_identity_user_logins_user FOREIGN KEY (user_id) REFERENCES identity_users(id) ON DELETE CASCADE;

ALTER TABLE identity_user_tokens
    ADD CONSTRAINT fk_identity_user_tokens_user FOREIGN KEY (user_id) REFERENCES identity_users(id) ON DELETE CASCADE;
