// Package pgxstore is a raw-SQL implementation of the identity stores on top of
// jackc/pgx (PostgreSQL). It is fully configurable: the schema/namespace and
// every table name are resolved from an identity.Naming at construction, and all
// SQL (including joins) is built from that single source, so renames stay
// consistent. Defaults are the canonical identity_* names.
package pgxstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
)

// Option configures the physical layout (schema / table names) of a store.
type Option func(*identity.Naming)

// WithSchema places all tables in the given schema/namespace (e.g. "auth").
func WithSchema(schema string) Option {
	return func(n *identity.Naming) { n.Schema = schema }
}

// WithTablePrefix prepends a prefix to every table name (e.g. "app_").
func WithTablePrefix(prefix string) Option {
	return func(n *identity.Naming) { n.Tables = n.Tables.WithPrefix(prefix) }
}

// WithTableNames overrides the table names individually.
func WithTableNames(t identity.TableNames) Option {
	return func(n *identity.Naming) { n.Tables = t }
}

// WithNaming sets the full naming config at once.
func WithNaming(nm identity.Naming) Option {
	return func(n *identity.Naming) { *n = nm }
}

func resolve(opts ...Option) identity.Naming {
	n := identity.DefaultNaming()
	for _, o := range opts {
		o(&n)
	}
	return n
}

// UserStore implements identity.UserStore over pgx.
type UserStore struct {
	db *pgxpool.Pool
	q  queries
}

// RoleStore implements identity.RoleStore over pgx.
type RoleStore struct {
	db *pgxpool.Pool
	q  queries
}

// Compile-time interface conformance.
var (
	_ identity.DefaultUserStore                          = (*UserStore)(nil)
	_ identity.RoleStore                                 = (*RoleStore)(nil)
	_ identity.UserLister[identity.User, *identity.User] = (*UserStore)(nil)
)

// NewUserStore builds a user store; pass options to customize schema/table names.
func NewUserStore(db *pgxpool.Pool, opts ...Option) *UserStore {
	return &UserStore{db: db, q: buildQueries(resolve(opts...))}
}

// NewRoleStore builds a role store; pass the same options used for the user store.
func NewRoleStore(db *pgxpool.Pool, opts ...Option) *RoleStore {
	return &RoleStore{db: db, q: buildQueries(resolve(opts...))}
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

// queries holds every SQL statement, pre-built from the resolved Naming so the
// table identifiers (and joins) are always consistent.
type queries struct {
	createUser, updateUser, userExists, deleteUser string
	findUserByID, findUserByName, findUserByEmail  string
	countUsers, listUsers                          string
	addToRole, removeFromRole, getRoles, isInRole  string
	roleExistsByName                               string
	usersInRole, usersForClaim                     string
	getUserClaims, addUserClaim, removeUserClaim   string
	getToken, setToken, removeToken                string
	addLogin, removeLogin, getLogins, findByLogin  string
	createRole, updateRole, deleteRole, roleExists string
	findRoleByID, findRoleByName                   string
	getRoleClaims, addRoleClaim, removeRoleClaim   string
}

func buildQueries(n identity.Naming) queries {
	U := n.Qualify(n.Tables.Users)
	R := n.Qualify(n.Tables.Roles)
	UR := n.Qualify(n.Tables.UserRoles)
	UC := n.Qualify(n.Tables.UserClaims)
	RC := n.Qualify(n.Tables.RoleClaims)
	UL := n.Qualify(n.Tables.UserLogins)
	UT := n.Qualify(n.Tables.UserTokens)
	const where = `($1 = '' OR normalized_user_name LIKE '%'||$1||'%' OR normalized_email LIKE '%'||$1||'%')`
	return queries{
		createUser: fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, now(), now())`, U, userCols),
		updateUser: fmt.Sprintf(`UPDATE %s SET
			user_name=$2, normalized_user_name=$3, email=$4, normalized_email=$5,
			email_confirmed=$6, password_hash=$7, security_stamp=$8, concurrency_stamp=$9,
			phone_number=$10, phone_number_confirmed=$11, two_factor_enabled=$12,
			lockout_end=$13, lockout_enabled=$14, access_failed_count=$15, attributes=$16, updated_at=now()
			WHERE id=$1 AND concurrency_stamp=$17`, U),
		userExists:       fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE id=$1)`, U),
		deleteUser:       fmt.Sprintf(`DELETE FROM %s WHERE id=$1`, U),
		findUserByID:     fmt.Sprintf(`SELECT %s FROM %s WHERE id=$1`, userCols, U),
		findUserByName:   fmt.Sprintf(`SELECT %s FROM %s WHERE normalized_user_name=$1`, userCols, U),
		findUserByEmail:  fmt.Sprintf(`SELECT %s FROM %s WHERE normalized_email=$1`, userCols, U),
		countUsers:       fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s`, U, where),
		listUsers:        fmt.Sprintf(`SELECT %s FROM %s WHERE %s ORDER BY id LIMIT $2 OFFSET $3`, userCols, U, where),
		addToRole:        fmt.Sprintf(`INSERT INTO %s (user_id, role_id) SELECT $1, id FROM %s WHERE normalized_name=$2 ON CONFLICT (user_id, role_id) DO NOTHING`, UR, R),
		removeFromRole:   fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND role_id=(SELECT id FROM %s WHERE normalized_name=$2)`, UR, R),
		getRoles:         fmt.Sprintf(`SELECT r.name FROM %s r JOIN %s ur ON ur.role_id=r.id WHERE ur.user_id=$1`, R, UR),
		isInRole:         fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s ur JOIN %s r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.normalized_name=$2)`, UR, R),
		roleExistsByName: fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE normalized_name=$1)`, R),
		usersInRole:      fmt.Sprintf(`SELECT %s FROM %s WHERE id IN (SELECT user_id FROM %s WHERE role_id=(SELECT id FROM %s WHERE normalized_name=$1)) ORDER BY id`, userCols, U, UR, R),
		usersForClaim:    fmt.Sprintf(`SELECT %s FROM %s WHERE id IN (SELECT user_id FROM %s WHERE claim_type=$1 AND claim_value=$2) ORDER BY id`, userCols, U, UC),
		getUserClaims:    fmt.Sprintf(`SELECT claim_type, claim_value FROM %s WHERE user_id=$1`, UC),
		addUserClaim:     fmt.Sprintf(`INSERT INTO %s (user_id, claim_type, claim_value) VALUES ($1,$2,$3)`, UC),
		removeUserClaim:  fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND claim_type=$2 AND claim_value=$3`, UC),
		getToken:         fmt.Sprintf(`SELECT value FROM %s WHERE user_id=$1 AND login_provider=$2 AND name=$3`, UT),
		setToken:         fmt.Sprintf(`INSERT INTO %s (user_id, login_provider, name, value) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id, login_provider, name) DO UPDATE SET value=EXCLUDED.value`, UT),
		removeToken:      fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND login_provider=$2 AND name=$3`, UT),
		addLogin:         fmt.Sprintf(`INSERT INTO %s (login_provider, provider_key, provider_display_name, user_id) VALUES ($1,$2,$3,$4)`, UL),
		removeLogin:      fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND login_provider=$2 AND provider_key=$3`, UL),
		getLogins:        fmt.Sprintf(`SELECT login_provider, provider_key, provider_display_name FROM %s WHERE user_id=$1`, UL),
		findByLogin:      fmt.Sprintf(`SELECT user_id FROM %s WHERE login_provider=$1 AND provider_key=$2`, UL),
		createRole:       fmt.Sprintf(`INSERT INTO %s (id, name, normalized_name, concurrency_stamp) VALUES ($1,$2,$3,$4)`, R),
		updateRole:       fmt.Sprintf(`UPDATE %s SET name=$2, normalized_name=$3, concurrency_stamp=$4 WHERE id=$1 AND concurrency_stamp=$5`, R),
		deleteRole:       fmt.Sprintf(`DELETE FROM %s WHERE id=$1`, R),
		roleExists:       fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE id=$1)`, R),
		findRoleByID:     fmt.Sprintf(`SELECT id, name, normalized_name, concurrency_stamp FROM %s WHERE id=$1`, R),
		findRoleByName:   fmt.Sprintf(`SELECT id, name, normalized_name, concurrency_stamp FROM %s WHERE normalized_name=$1`, R),
		getRoleClaims:    fmt.Sprintf(`SELECT claim_type, claim_value FROM %s WHERE role_id=$1`, RC),
		addRoleClaim:     fmt.Sprintf(`INSERT INTO %s (role_id, claim_type, claim_value) VALUES ($1,$2,$3)`, RC),
		removeRoleClaim:  fmt.Sprintf(`DELETE FROM %s WHERE role_id=$1 AND claim_type=$2 AND claim_value=$3`, RC),
	}
}

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
	_, err = s.db.Exec(ctx, s.q.createUser,
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
	old := u.ConcurrencyStamp
	newStamp := identity.NewConcurrencyStamp()
	tag, err := s.db.Exec(ctx, s.q.updateUser,
		u.ID, u.UserName, u.NormalizedUserName, u.Email, u.NormalizedEmail,
		u.EmailConfirmed, u.PasswordHash, u.SecurityStamp, newStamp,
		u.PhoneNumber, u.PhoneNumberConfirmed, u.TwoFactorEnabled, u.LockoutEnd,
		u.LockoutEnabled, u.AccessFailedCount, attrs, old)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if e := s.db.QueryRow(ctx, s.q.userExists, u.ID).Scan(&exists); e == nil && !exists {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	u.ConcurrencyStamp = newStamp
	return nil
}

func (s *UserStore) Delete(ctx context.Context, u *identity.User) error {
	_, err := s.db.Exec(ctx, s.q.deleteUser, u.ID)
	return err
}

func (s *UserStore) FindByID(ctx context.Context, id string) (*identity.User, error) {
	return scanUser(s.db.QueryRow(ctx, s.q.findUserByID, id))
}

func (s *UserStore) FindByName(ctx context.Context, n string) (*identity.User, error) {
	return scanUser(s.db.QueryRow(ctx, s.q.findUserByName, n))
}

func (s *UserStore) FindByEmail(ctx context.Context, e string) (*identity.User, error) {
	if e == "" {
		return nil, identity.ErrNotFound // users without an email store ''
	}
	return scanUser(s.db.QueryRow(ctx, s.q.findUserByEmail, e))
}

// ListUsers implements identity.UserLister.
func (s *UserStore) ListUsers(ctx context.Context, f identity.ListFilter) ([]*identity.User, int64, error) {
	search := strings.ToUpper(f.Search)
	var total int64
	if err := s.db.QueryRow(ctx, s.q.countUsers, search).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, s.q.listUsers, search, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*identity.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *UserStore) AddToRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	tag, err := s.db.Exec(ctx, s.q.addToRole, u.ID, normalizedRoleName)
	if err != nil {
		return err
	}
	// 0 rows is ambiguous: ON CONFLICT swallowed an existing membership (fine,
	// idempotent) OR the INSERT..SELECT found no role. Disambiguate so a missing
	// role surfaces as ErrRoleNotFound instead of silently succeeding.
	if tag.RowsAffected() == 0 {
		var exists bool
		if e := s.db.QueryRow(ctx, s.q.roleExistsByName, normalizedRoleName).Scan(&exists); e == nil && !exists {
			return identity.ErrRoleNotFound
		}
	}
	return nil
}

func (s *UserStore) RemoveFromRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	_, err := s.db.Exec(ctx, s.q.removeFromRole, u.ID, normalizedRoleName)
	return err
}

func (s *UserStore) GetRoles(ctx context.Context, u *identity.User) ([]string, error) {
	rows, err := s.db.Query(ctx, s.q.getRoles, u.ID)
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
	err := s.db.QueryRow(ctx, s.q.isInRole, u.ID, normalizedRoleName).Scan(&exists)
	return exists, err
}

func (s *UserStore) scanUsers(rows pgx.Rows) ([]*identity.User, error) {
	defer rows.Close()
	var out []*identity.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *UserStore) GetUsersInRole(ctx context.Context, normalizedRoleName string) ([]*identity.User, error) {
	rows, err := s.db.Query(ctx, s.q.usersInRole, normalizedRoleName)
	if err != nil {
		return nil, err
	}
	return s.scanUsers(rows)
}

func (s *UserStore) GetUsersForClaim(ctx context.Context, claimType, claimValue string) ([]*identity.User, error) {
	rows, err := s.db.Query(ctx, s.q.usersForClaim, claimType, claimValue)
	if err != nil {
		return nil, err
	}
	return s.scanUsers(rows)
}

func (s *UserStore) GetClaims(ctx context.Context, u *identity.User) ([]identity.Claim, error) {
	rows, err := s.db.Query(ctx, s.q.getUserClaims, u.ID)
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
		batch.Queue(s.q.addUserClaim, u.ID, c.Type, c.Value)
	}
	return s.db.SendBatch(ctx, batch).Close()
}

func (s *UserStore) RemoveClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	batch := &pgx.Batch{}
	for _, c := range claims {
		batch.Queue(s.q.removeUserClaim, u.ID, c.Type, c.Value)
	}
	return s.db.SendBatch(ctx, batch).Close()
}

func (s *UserStore) GetToken(ctx context.Context, u *identity.User, loginProvider, name string) (string, error) {
	var v string
	err := s.db.QueryRow(ctx, s.q.getToken, u.ID, loginProvider, name).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *UserStore) SetToken(ctx context.Context, u *identity.User, loginProvider, name, value string) error {
	_, err := s.db.Exec(ctx, s.q.setToken, u.ID, loginProvider, name, value)
	return err
}

func (s *UserStore) RemoveToken(ctx context.Context, u *identity.User, loginProvider, name string) error {
	_, err := s.db.Exec(ctx, s.q.removeToken, u.ID, loginProvider, name)
	return err
}

func (s *UserStore) AddLogin(ctx context.Context, u *identity.User, login identity.UserLoginInfo) error {
	_, err := s.db.Exec(ctx, s.q.addLogin, login.LoginProvider, login.ProviderKey, login.ProviderDisplayName, u.ID)
	return err
}

func (s *UserStore) RemoveLogin(ctx context.Context, u *identity.User, loginProvider, providerKey string) error {
	_, err := s.db.Exec(ctx, s.q.removeLogin, u.ID, loginProvider, providerKey)
	return err
}

func (s *UserStore) GetLogins(ctx context.Context, u *identity.User) ([]identity.UserLoginInfo, error) {
	rows, err := s.db.Query(ctx, s.q.getLogins, u.ID)
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
	err := s.db.QueryRow(ctx, s.q.findByLogin, loginProvider, providerKey).Scan(&uid)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, uid)
}

// --- RoleStore ---

func (s *RoleStore) Create(ctx context.Context, r *identity.Role) error {
	_, err := s.db.Exec(ctx, s.q.createRole, r.ID, r.Name, r.NormalizedName, r.ConcurrencyStamp)
	return err
}

func (s *RoleStore) Update(ctx context.Context, r *identity.Role) error {
	old := r.ConcurrencyStamp
	newStamp := identity.NewConcurrencyStamp()
	tag, err := s.db.Exec(ctx, s.q.updateRole, r.ID, r.Name, r.NormalizedName, newStamp, old)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if e := s.db.QueryRow(ctx, s.q.roleExists, r.ID).Scan(&exists); e == nil && !exists {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	r.ConcurrencyStamp = newStamp
	return nil
}

func (s *RoleStore) Delete(ctx context.Context, r *identity.Role) error {
	_, err := s.db.Exec(ctx, s.q.deleteRole, r.ID)
	return err
}

func (s *RoleStore) FindByID(ctx context.Context, id string) (*identity.Role, error) {
	return scanRole(s.db.QueryRow(ctx, s.q.findRoleByID, id))
}

func (s *RoleStore) FindByName(ctx context.Context, normalizedName string) (*identity.Role, error) {
	return scanRole(s.db.QueryRow(ctx, s.q.findRoleByName, normalizedName))
}

func scanRole(row pgx.Row) (*identity.Role, error) {
	var r identity.Role
	if err := row.Scan(&r.ID, &r.Name, &r.NormalizedName, &r.ConcurrencyStamp); err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) GetClaims(ctx context.Context, r *identity.Role) ([]identity.Claim, error) {
	rows, err := s.db.Query(ctx, s.q.getRoleClaims, r.ID)
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
	_, err := s.db.Exec(ctx, s.q.addRoleClaim, r.ID, c.Type, c.Value)
	return err
}

func (s *RoleStore) RemoveClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	_, err := s.db.Exec(ctx, s.q.removeRoleClaim, r.ID, c.Type, c.Value)
	return err
}
