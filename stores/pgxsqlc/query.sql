-- name: CreateUser :exec
INSERT INTO identity_users (
    id, user_name, normalized_user_name, email, normalized_email, email_confirmed,
    password_hash, security_stamp, concurrency_stamp, phone_number,
    phone_number_confirmed, two_factor_enabled, lockout_end, lockout_enabled,
    access_failed_count, attributes
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
);

-- name: UpdateUser :exec
UPDATE identity_users SET
    user_name=$2, normalized_user_name=$3, email=$4, normalized_email=$5,
    email_confirmed=$6, password_hash=$7, security_stamp=$8, concurrency_stamp=$9,
    phone_number=$10, phone_number_confirmed=$11, two_factor_enabled=$12,
    lockout_end=$13, lockout_enabled=$14, access_failed_count=$15, attributes=$16,
    updated_at=now()
WHERE id=$1;

-- name: DeleteUser :exec
DELETE FROM identity_users WHERE id=$1;

-- name: GetUserByID :one
SELECT * FROM identity_users WHERE id=$1;

-- name: GetUserByName :one
SELECT * FROM identity_users WHERE normalized_user_name=$1;

-- name: GetUserByEmail :one
SELECT * FROM identity_users WHERE normalized_email=$1;

-- name: GetRoleIDByName :one
SELECT id FROM identity_roles WHERE normalized_name=$1;

-- name: AddUserToRole :exec
INSERT INTO identity_user_roles (user_id, role_id) VALUES ($1, $2);

-- name: RemoveUserFromRole :exec
DELETE FROM identity_user_roles WHERE user_id=$1 AND role_id=$2;

-- name: GetUserRoles :many
SELECT r.name FROM identity_roles r
JOIN identity_user_roles ur ON ur.role_id = r.id
WHERE ur.user_id=$1;

-- name: IsUserInRole :one
SELECT EXISTS(
    SELECT 1 FROM identity_user_roles ur
    JOIN identity_roles r ON r.id = ur.role_id
    WHERE ur.user_id=$1 AND r.normalized_name=$2
);

-- name: GetUserClaims :many
SELECT claim_type, claim_value FROM identity_user_claims WHERE user_id=$1;

-- name: AddUserClaim :exec
INSERT INTO identity_user_claims (user_id, claim_type, claim_value) VALUES ($1,$2,$3);

-- name: DeleteUserClaim :exec
DELETE FROM identity_user_claims WHERE user_id=$1 AND claim_type=$2 AND claim_value=$3;

-- name: GetUserToken :one
SELECT value FROM identity_user_tokens
WHERE user_id=$1 AND login_provider=$2 AND name=$3;

-- name: UpsertUserToken :exec
INSERT INTO identity_user_tokens (user_id, login_provider, name, value)
VALUES ($1,$2,$3,$4)
ON CONFLICT (user_id, login_provider, name) DO UPDATE SET value=EXCLUDED.value;

-- name: DeleteUserToken :exec
DELETE FROM identity_user_tokens WHERE user_id=$1 AND login_provider=$2 AND name=$3;

-- name: AddUserLogin :exec
INSERT INTO identity_user_logins (login_provider, provider_key, provider_display_name, user_id)
VALUES ($1,$2,$3,$4);

-- name: RemoveUserLogin :exec
DELETE FROM identity_user_logins WHERE user_id=$1 AND login_provider=$2 AND provider_key=$3;

-- name: GetUserLogins :many
SELECT login_provider, provider_key, provider_display_name
FROM identity_user_logins WHERE user_id=$1;

-- name: GetUserIDByLogin :one
SELECT user_id FROM identity_user_logins WHERE login_provider=$1 AND provider_key=$2;

-- name: CreateRole :exec
INSERT INTO identity_roles (id, name, normalized_name, concurrency_stamp)
VALUES ($1,$2,$3,$4);

-- name: UpdateRole :exec
UPDATE identity_roles SET name=$2, normalized_name=$3, concurrency_stamp=$4 WHERE id=$1;

-- name: DeleteRole :exec
DELETE FROM identity_roles WHERE id=$1;

-- name: GetRoleByID :one
SELECT * FROM identity_roles WHERE id=$1;

-- name: GetRoleByName :one
SELECT * FROM identity_roles WHERE normalized_name=$1;

-- name: GetRoleClaims :many
SELECT claim_type, claim_value FROM identity_role_claims WHERE role_id=$1;

-- name: AddRoleClaim :exec
INSERT INTO identity_role_claims (role_id, claim_type, claim_value) VALUES ($1,$2,$3);

-- name: DeleteRoleClaim :exec
DELETE FROM identity_role_claims WHERE role_id=$1 AND claim_type=$2 AND claim_value=$3;
