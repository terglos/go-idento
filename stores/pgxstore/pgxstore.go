// Package pgxstore is a raw-SQL implementation of the identity stores on top of
// jackc/pgx (PostgreSQL), an alternative to the GORM store for teams who prefer
// hand-written SQL and a single high-performance driver. The query layout is
// sqlc-friendly: every statement is plain SQL, so it can be moved into sqlc
// without changing the schema.
package pgxstore

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
)

//go:embed schema.sql
var schema string

// UserStore implements identity.UserStore over pgx.
type UserStore struct{ db *pgxpool.Pool }

// RoleStore implements identity.RoleStore over pgx.
type RoleStore struct{ db *pgxpool.Pool }

// Compile-time interface conformance.
var (
	_ identity.DefaultUserStore = (*UserStore)(nil)
	_ identity.RoleStore        = (*RoleStore)(nil)
)

func NewUserStore(db *pgxpool.Pool) *UserStore { return &UserStore{db: db} }
func NewRoleStore(db *pgxpool.Pool) *RoleStore { return &RoleStore{db: db} }

// Migrate executes the embedded schema (idempotent: all statements use IF NOT EXISTS).
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, schema)
	return err
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrNotFound
	}
	return err
}

const userCols = `id, user_name, normalized_user_name, email, normalized_email,
	email_confirmed, password_hash, security_stamp, concurrency_stamp,
	phone_number, phone_number_confirmed, two_factor_enabled, lockout_end,
	lockout_enabled, access_failed_count, attributes, created_at, updated_at`

func scanUser(row pgx.Row) (*identity.User, error) {
	var u identity.User
	var attrs []byte
	err := row.Scan(&u.ID, &u.UserName, &u.NormalizedUserName, &u.Email, &u.NormalizedEmail,
		&u.EmailConfirmed, &u.PasswordHash, &u.SecurityStamp, &u.ConcurrencyStamp,
		&u.PhoneNumber, &u.PhoneNumberConfirmed, &u.TwoFactorEnabled, &u.LockoutEnd,
		&u.LockoutEnabled, &u.AccessFailedCount, &attrs, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &u.Attributes); err != nil {
			return nil, err
		}
	}
	return &u, nil
}

// marshalAttrs serializes Attributes to JSON for a jsonb parameter ('{}' when nil).
func marshalAttrs(a identity.Attributes) ([]byte, error) {
	if a == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(a)
}

// --- UserStore ---

func (s *UserStore) Create(ctx context.Context, u *identity.User) error {
	attrs, err := marshalAttrs(u.Attributes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO identity_users (`+userCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, now(), now())`,
		u.ID, u.UserName, u.NormalizedUserName, u.Email, u.NormalizedEmail,
		u.EmailConfirmed, u.PasswordHash, u.SecurityStamp, u.ConcurrencyStamp,
		u.PhoneNumber, u.PhoneNumberConfirmed, u.TwoFactorEnabled, u.LockoutEnd,
		u.LockoutEnabled, u.AccessFailedCount, attrs)
	return err
}

func (s *UserStore) Update(ctx context.Context, u *identity.User) error {
	attrs, err := marshalAttrs(u.Attributes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE identity_users SET
		user_name=$2, normalized_user_name=$3, email=$4, normalized_email=$5,
		email_confirmed=$6, password_hash=$7, security_stamp=$8, concurrency_stamp=$9,
		phone_number=$10, phone_number_confirmed=$11, two_factor_enabled=$12,
		lockout_end=$13, lockout_enabled=$14, access_failed_count=$15, attributes=$16, updated_at=now()
		WHERE id=$1`,
		u.ID, u.UserName, u.NormalizedUserName, u.Email, u.NormalizedEmail,
		u.EmailConfirmed, u.PasswordHash, u.SecurityStamp, u.ConcurrencyStamp,
		u.PhoneNumber, u.PhoneNumberConfirmed, u.TwoFactorEnabled, u.LockoutEnd,
		u.LockoutEnabled, u.AccessFailedCount, attrs)
	return err
}

func (s *UserStore) Delete(ctx context.Context, u *identity.User) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_users WHERE id=$1`, u.ID)
	return err
}

func (s *UserStore) FindByID(ctx context.Context, id string) (*identity.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM identity_users WHERE id=$1`, id))
}

func (s *UserStore) FindByName(ctx context.Context, n string) (*identity.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM identity_users WHERE normalized_user_name=$1`, n))
}

func (s *UserStore) FindByEmail(ctx context.Context, e string) (*identity.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM identity_users WHERE normalized_email=$1`, e))
}

func (s *UserStore) AddToRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identity_user_roles (user_id, role_id)
		SELECT $1, id FROM identity_roles WHERE normalized_name=$2`, u.ID, normalizedRoleName)
	return err
}

func (s *UserStore) RemoveFromRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_user_roles
		WHERE user_id=$1 AND role_id=(SELECT id FROM identity_roles WHERE normalized_name=$2)`,
		u.ID, normalizedRoleName)
	return err
}

func (s *UserStore) GetRoles(ctx context.Context, u *identity.User) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT r.name FROM identity_roles r
		JOIN identity_user_roles ur ON ur.role_id=r.id WHERE ur.user_id=$1`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (s *UserStore) IsInRole(ctx context.Context, u *identity.User, normalizedRoleName string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM identity_user_roles ur
		JOIN identity_roles r ON r.id=ur.role_id
		WHERE ur.user_id=$1 AND r.normalized_name=$2)`, u.ID, normalizedRoleName).Scan(&exists)
	return exists, err
}

func (s *UserStore) GetClaims(ctx context.Context, u *identity.User) ([]identity.Claim, error) {
	rows, err := s.db.Query(ctx, `SELECT claim_type, claim_value FROM identity_user_claims WHERE user_id=$1`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Claim
	for rows.Next() {
		var c identity.Claim
		if err := rows.Scan(&c.Type, &c.Value); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *UserStore) AddClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	batch := &pgx.Batch{}
	for _, c := range claims {
		batch.Queue(`INSERT INTO identity_user_claims (user_id, claim_type, claim_value) VALUES ($1,$2,$3)`,
			u.ID, c.Type, c.Value)
	}
	return s.db.SendBatch(ctx, batch).Close()
}

func (s *UserStore) RemoveClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	batch := &pgx.Batch{}
	for _, c := range claims {
		batch.Queue(`DELETE FROM identity_user_claims WHERE user_id=$1 AND claim_type=$2 AND claim_value=$3`,
			u.ID, c.Type, c.Value)
	}
	return s.db.SendBatch(ctx, batch).Close()
}

func (s *UserStore) GetToken(ctx context.Context, u *identity.User, loginProvider, name string) (string, error) {
	var v string
	err := s.db.QueryRow(ctx, `SELECT value FROM identity_user_tokens
		WHERE user_id=$1 AND login_provider=$2 AND name=$3`, u.ID, loginProvider, name).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *UserStore) SetToken(ctx context.Context, u *identity.User, loginProvider, name, value string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identity_user_tokens (user_id, login_provider, name, value)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (user_id, login_provider, name) DO UPDATE SET value=EXCLUDED.value`,
		u.ID, loginProvider, name, value)
	return err
}

func (s *UserStore) RemoveToken(ctx context.Context, u *identity.User, loginProvider, name string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_user_tokens
		WHERE user_id=$1 AND login_provider=$2 AND name=$3`, u.ID, loginProvider, name)
	return err
}

func (s *UserStore) AddLogin(ctx context.Context, u *identity.User, login identity.UserLoginInfo) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identity_user_logins
		(login_provider, provider_key, provider_display_name, user_id) VALUES ($1,$2,$3,$4)`,
		login.LoginProvider, login.ProviderKey, login.ProviderDisplayName, u.ID)
	return err
}

func (s *UserStore) RemoveLogin(ctx context.Context, u *identity.User, loginProvider, providerKey string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_user_logins
		WHERE user_id=$1 AND login_provider=$2 AND provider_key=$3`, u.ID, loginProvider, providerKey)
	return err
}

func (s *UserStore) GetLogins(ctx context.Context, u *identity.User) ([]identity.UserLoginInfo, error) {
	rows, err := s.db.Query(ctx, `SELECT login_provider, provider_key, provider_display_name
		FROM identity_user_logins WHERE user_id=$1`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.UserLoginInfo
	for rows.Next() {
		var l identity.UserLoginInfo
		if err := rows.Scan(&l.LoginProvider, &l.ProviderKey, &l.ProviderDisplayName); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *UserStore) FindByLogin(ctx context.Context, loginProvider, providerKey string) (*identity.User, error) {
	var uid string
	err := s.db.QueryRow(ctx, `SELECT user_id FROM identity_user_logins
		WHERE login_provider=$1 AND provider_key=$2`, loginProvider, providerKey).Scan(&uid)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, uid)
}

// --- RoleStore ---

func (s *RoleStore) Create(ctx context.Context, r *identity.Role) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identity_roles (id, name, normalized_name, concurrency_stamp)
		VALUES ($1,$2,$3,$4)`, r.ID, r.Name, r.NormalizedName, r.ConcurrencyStamp)
	return err
}

func (s *RoleStore) Update(ctx context.Context, r *identity.Role) error {
	_, err := s.db.Exec(ctx, `UPDATE identity_roles SET name=$2, normalized_name=$3, concurrency_stamp=$4
		WHERE id=$1`, r.ID, r.Name, r.NormalizedName, r.ConcurrencyStamp)
	return err
}

func (s *RoleStore) Delete(ctx context.Context, r *identity.Role) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_roles WHERE id=$1`, r.ID)
	return err
}

func (s *RoleStore) FindByID(ctx context.Context, id string) (*identity.Role, error) {
	return scanRole(s.db.QueryRow(ctx, `SELECT id, name, normalized_name, concurrency_stamp
		FROM identity_roles WHERE id=$1`, id))
}

func (s *RoleStore) FindByName(ctx context.Context, normalizedName string) (*identity.Role, error) {
	return scanRole(s.db.QueryRow(ctx, `SELECT id, name, normalized_name, concurrency_stamp
		FROM identity_roles WHERE normalized_name=$1`, normalizedName))
}

func scanRole(row pgx.Row) (*identity.Role, error) {
	var r identity.Role
	if err := row.Scan(&r.ID, &r.Name, &r.NormalizedName, &r.ConcurrencyStamp); err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) GetClaims(ctx context.Context, r *identity.Role) ([]identity.Claim, error) {
	rows, err := s.db.Query(ctx, `SELECT claim_type, claim_value FROM identity_role_claims WHERE role_id=$1`, r.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Claim
	for rows.Next() {
		var c identity.Claim
		if err := rows.Scan(&c.Type, &c.Value); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *RoleStore) AddClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	_, err := s.db.Exec(ctx, `INSERT INTO identity_role_claims (role_id, claim_type, claim_value)
		VALUES ($1,$2,$3)`, r.ID, c.Type, c.Value)
	return err
}

func (s *RoleStore) RemoveClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	_, err := s.db.Exec(ctx, `DELETE FROM identity_role_claims
		WHERE role_id=$1 AND claim_type=$2 AND claim_value=$3`, r.ID, c.Type, c.Value)
	return err
}
