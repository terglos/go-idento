// Package gormstore provides a GORM-backed implementation of the identity
// UserStore and RoleStore, supporting Postgres, MySQL and SQLite from a single
// codebase via a single ORM. Schema/namespace and table names are configurable
// at construction (WithSchema/WithTablePrefix/WithTableNames); every query is
// scoped to the resolved table names, so renames stay consistent.
package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Option configures the physical layout (schema / table names) of a store.
type Option func(*identity.Naming)

// WithSchema places all tables in the given schema/namespace (Postgres/MySQL).
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

// tables holds the resolved (schema-qualified) physical table names.
type tables struct {
	users, roles, userRoles, userClaims, roleClaims, userLogins, userTokens, apiKeys string
}

func resolveTables(n identity.Naming) tables {
	return tables{
		users:      n.Qualify(n.Tables.Users),
		roles:      n.Qualify(n.Tables.Roles),
		userRoles:  n.Qualify(n.Tables.UserRoles),
		userClaims: n.Qualify(n.Tables.UserClaims),
		roleClaims: n.Qualify(n.Tables.RoleClaims),
		userLogins: n.Qualify(n.Tables.UserLogins),
		userTokens: n.Qualify(n.Tables.UserTokens),
		apiKeys:    n.Qualify(n.Tables.APIKeys),
	}
}

// deleteUserCascade removes the user and all its satellite rows in one
// transaction (portable across SQLite/MySQL/Postgres, where DB-level FKs may be
// off or absent).
func (t tables) deleteUserCascade(db *gorm.DB, userID string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		for _, table := range []string{t.userRoles, t.userClaims, t.userLogins, t.userTokens, t.apiKeys} {
			if err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE user_id = ?", table), userID).Error; err != nil {
				return err
			}
		}
		return tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE id = ?", t.users), userID).Error
	})
}

// purgeAnonymous cascade-deletes guest users created before the cutoff and
// returns how many were removed. Each user is removed via deleteUserCascade so
// satellites go too (portable regardless of DB-level FKs).
func (t tables) purgeAnonymous(db *gorm.DB, createdBefore time.Time) (int64, error) {
	var ids []string
	if err := db.Table(t.users).Where("is_anonymous = ? AND created_at < ?", true, createdBefore).
		Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := t.deleteUserCascade(db, id); err != nil {
			return 0, err
		}
	}
	return int64(len(ids)), nil
}

// UserStore implements identity.UserStore over GORM.
type UserStore struct {
	db *gorm.DB
	t  tables
}

// RoleStore implements identity.RoleStore over GORM.
type RoleStore struct {
	db *gorm.DB
	t  tables
}

func NewUserStore(db *gorm.DB, opts ...Option) *UserStore {
	return &UserStore{db: db, t: resolveTables(resolve(opts...))}
}
func NewRoleStore(db *gorm.DB, opts ...Option) *RoleStore {
	return &RoleStore{db: db, t: resolveTables(resolve(opts...))}
}

// Compile-time interface conformance.
var (
	_ identity.DefaultUserStore                               = (*UserStore)(nil)
	_ identity.RoleStore                                      = (*RoleStore)(nil)
	_ identity.UserLister[identity.User, *identity.User]      = (*UserStore)(nil)
	_ identity.AnonymousPurger[identity.User, *identity.User] = (*UserStore)(nil)
)

// Migrate creates/updates all identity tables for the resolved naming.
func Migrate(db *gorm.DB, opts ...Option) error {
	n := resolve(opts...)
	if err := n.Validate(); err != nil {
		return err
	}
	if n.Schema != "" {
		if err := db.Exec("CREATE SCHEMA IF NOT EXISTS " + n.Schema).Error; err != nil {
			return err
		}
	}
	t := resolveTables(n)
	steps := []struct {
		name  string
		model any
	}{
		{t.users, &identity.User{}}, {t.roles, &identity.Role{}}, {t.userRoles, &identity.UserRole{}},
		{t.userClaims, &identity.UserClaim{}}, {t.roleClaims, &identity.RoleClaim{}},
		{t.userLogins, &identity.UserLogin{}}, {t.userTokens, &identity.UserToken{}},
		{t.apiKeys, &identity.APIKey{}},
	}
	for _, s := range steps {
		if err := db.Table(s.name).AutoMigrate(s.model); err != nil {
			return err
		}
	}
	return nil
}

func mapNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return identity.ErrNotFound
	}
	return err
}

// --- UserStore ---

func (s *UserStore) Create(ctx context.Context, u *identity.User) error {
	return s.db.WithContext(ctx).Table(s.t.users).Create(u).Error
}

func (s *UserStore) Update(ctx context.Context, u *identity.User) error {
	old := u.ConcurrencyStamp
	u.ConcurrencyStamp = identity.NewConcurrencyStamp()
	res := s.db.WithContext(ctx).Table(s.t.users).
		Where("id = ? AND concurrency_stamp = ?", u.ID, old).Select("*").Updates(u)
	if res.Error != nil {
		u.ConcurrencyStamp = old
		return res.Error
	}
	if res.RowsAffected == 0 {
		u.ConcurrencyStamp = old
		var count int64
		s.db.WithContext(ctx).Table(s.t.users).Where("id = ?", u.ID).Count(&count)
		if count == 0 {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	return nil
}

func (s *UserStore) Delete(ctx context.Context, u *identity.User) error {
	return s.t.deleteUserCascade(s.db.WithContext(ctx), u.ID)
}

// PurgeAnonymousUsers implements identity.AnonymousPurger.
func (s *UserStore) PurgeAnonymousUsers(ctx context.Context, createdBefore time.Time) (int64, error) {
	return s.t.purgeAnonymous(s.db.WithContext(ctx), createdBefore)
}

func (s *UserStore) findUser(ctx context.Context, where string, arg any) (*identity.User, error) {
	var u identity.User
	if err := s.db.WithContext(ctx).Table(s.t.users).Where(where, arg).Take(&u).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

func (s *UserStore) FindByID(ctx context.Context, id string) (*identity.User, error) {
	return s.findUser(ctx, "id = ?", id)
}

func (s *UserStore) FindByName(ctx context.Context, normalizedUserName string) (*identity.User, error) {
	return s.findUser(ctx, "normalized_user_name = ?", normalizedUserName)
}

func (s *UserStore) FindByEmail(ctx context.Context, normalizedEmail string) (*identity.User, error) {
	if normalizedEmail == "" {
		return nil, identity.ErrNotFound // users without an email store ''
	}
	return s.findUser(ctx, "normalized_email = ?", normalizedEmail)
}

// ListUsers implements identity.UserLister.
func (s *UserStore) ListUsers(ctx context.Context, f identity.ListFilter) ([]*identity.User, int64, error) {
	filtered := func() *gorm.DB {
		q := s.db.WithContext(ctx).Table(s.t.users)
		if f.Search != "" {
			like := "%" + strings.ToUpper(f.Search) + "%"
			q = q.Where("normalized_user_name LIKE ? OR normalized_email LIKE ?", like, like)
		}
		return q
	}
	var total int64
	if err := filtered().Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var users []*identity.User
	if err := filtered().Order("id").Limit(f.Limit).Offset(f.Offset).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *UserStore) roleIDByName(ctx context.Context, normalizedRoleName string) (string, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).Table(s.t.roles).Where("normalized_name = ?", normalizedRoleName).Take(&r).Error; err != nil {
		return "", mapNotFound(err)
	}
	return r.ID, nil
}

func (s *UserStore) AddToRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if errors.Is(err, identity.ErrNotFound) {
		return identity.ErrRoleNotFound // store contract: typed error for a missing role
	}
	if err != nil {
		return err
	}
	// Idempotent: adding an existing membership is a no-op.
	return s.db.WithContext(ctx).Table(s.t.userRoles).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&identity.UserRole{UserID: u.ID, RoleID: rid}).Error
}

func (s *UserStore) RemoveFromRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if errors.Is(err, identity.ErrNotFound) {
		return nil // store contract: removing from a nonexistent role is a no-op
	}
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Table(s.t.userRoles).
		Where("user_id = ? AND role_id = ?", u.ID, rid).Delete(&identity.UserRole{}).Error
}

func (s *UserStore) GetRoles(ctx context.Context, u *identity.User) ([]string, error) {
	var names []string
	sql := fmt.Sprintf(`SELECT r.name FROM %s r JOIN %s ur ON ur.role_id = r.id WHERE ur.user_id = ?`, s.t.roles, s.t.userRoles)
	err := s.db.WithContext(ctx).Raw(sql, u.ID).Scan(&names).Error
	return names, err
}

func (s *UserStore) IsInRole(ctx context.Context, u *identity.User, normalizedRoleName string) (bool, error) {
	var count int64
	sql := fmt.Sprintf(`SELECT count(*) FROM %s ur JOIN %s r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.normalized_name = ?`, s.t.userRoles, s.t.roles)
	err := s.db.WithContext(ctx).Raw(sql, u.ID, normalizedRoleName).Scan(&count).Error
	return count > 0, err
}

func (s *UserStore) GetUsersInRole(ctx context.Context, normalizedRoleName string) ([]*identity.User, error) {
	var ids []string
	sql := fmt.Sprintf(`SELECT ur.user_id FROM %s ur JOIN %s r ON r.id = ur.role_id WHERE r.normalized_name = ?`, s.t.userRoles, s.t.roles)
	if err := s.db.WithContext(ctx).Raw(sql, normalizedRoleName).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return s.usersByIDs(ctx, ids)
}

func (s *UserStore) GetUsersForClaim(ctx context.Context, claimType, claimValue string) ([]*identity.User, error) {
	var ids []string
	sql := fmt.Sprintf(`SELECT user_id FROM %s WHERE claim_type = ? AND claim_value = ?`, s.t.userClaims)
	if err := s.db.WithContext(ctx).Raw(sql, claimType, claimValue).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return s.usersByIDs(ctx, ids)
}

// usersByIDs loads full user rows (applying the Attributes serializer) for a set
// of ids, ordered by id for determinism.
func (s *UserStore) usersByIDs(ctx context.Context, ids []string) ([]*identity.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var users []identity.User
	if err := s.db.WithContext(ctx).Table(s.t.users).Where("id IN ?", ids).Order("id").Find(&users).Error; err != nil {
		return nil, err
	}
	out := make([]*identity.User, len(users))
	for i := range users {
		out[i] = &users[i]
	}
	return out, nil
}

func (s *UserStore) GetClaims(ctx context.Context, u *identity.User) ([]identity.Claim, error) {
	var rows []identity.UserClaim
	if err := s.db.WithContext(ctx).Table(s.t.userClaims).Where("user_id = ?", u.ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	claims := make([]identity.Claim, len(rows))
	for i, r := range rows {
		claims[i] = identity.Claim{Type: r.ClaimType, Value: r.ClaimValue}
	}
	return claims, nil
}

func (s *UserStore) AddClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	rows := make([]identity.UserClaim, len(claims))
	for i, c := range claims {
		rows[i] = identity.UserClaim{UserID: u.ID, ClaimType: c.Type, ClaimValue: c.Value}
	}
	return s.db.WithContext(ctx).Table(s.t.userClaims).Create(&rows).Error
}

func (s *UserStore) RemoveClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, c := range claims {
			if err := tx.Table(s.t.userClaims).
				Where("user_id = ? AND claim_type = ? AND claim_value = ?", u.ID, c.Type, c.Value).
				Delete(&identity.UserClaim{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *UserStore) GetToken(ctx context.Context, u *identity.User, loginProvider, name string) (string, error) {
	var t identity.UserToken
	err := s.db.WithContext(ctx).Table(s.t.userTokens).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.ID, loginProvider, name).Take(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return t.Value, nil
}

func (s *UserStore) SetToken(ctx context.Context, u *identity.User, loginProvider, name, value string) error {
	tok := identity.UserToken{UserID: u.ID, LoginProvider: loginProvider, Name: name, Value: value}
	return s.db.WithContext(ctx).Table(s.t.userTokens).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "login_provider"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&tok).Error
}

func (s *UserStore) RemoveToken(ctx context.Context, u *identity.User, loginProvider, name string) error {
	return s.db.WithContext(ctx).Table(s.t.userTokens).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.ID, loginProvider, name).
		Delete(&identity.UserToken{}).Error
}

func (s *UserStore) AddLogin(ctx context.Context, u *identity.User, login identity.UserLoginInfo) error {
	return s.db.WithContext(ctx).Table(s.t.userLogins).Create(&identity.UserLogin{
		LoginProvider:       login.LoginProvider,
		ProviderKey:         login.ProviderKey,
		ProviderDisplayName: login.ProviderDisplayName,
		UserID:              u.ID,
	}).Error
}

func (s *UserStore) RemoveLogin(ctx context.Context, u *identity.User, loginProvider, providerKey string) error {
	return s.db.WithContext(ctx).Table(s.t.userLogins).
		Where("user_id = ? AND login_provider = ? AND provider_key = ?", u.ID, loginProvider, providerKey).
		Delete(&identity.UserLogin{}).Error
}

func (s *UserStore) GetLogins(ctx context.Context, u *identity.User) ([]identity.UserLoginInfo, error) {
	var rows []identity.UserLogin
	if err := s.db.WithContext(ctx).Table(s.t.userLogins).Where("user_id = ?", u.ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]identity.UserLoginInfo, len(rows))
	for i, r := range rows {
		out[i] = identity.UserLoginInfo{LoginProvider: r.LoginProvider, ProviderKey: r.ProviderKey, ProviderDisplayName: r.ProviderDisplayName}
	}
	return out, nil
}

func (s *UserStore) FindByLogin(ctx context.Context, loginProvider, providerKey string) (*identity.User, error) {
	var login identity.UserLogin
	if err := s.db.WithContext(ctx).Table(s.t.userLogins).
		Where("login_provider = ? AND provider_key = ?", loginProvider, providerKey).Take(&login).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, login.UserID)
}

// --- RoleStore ---

func (s *RoleStore) Create(ctx context.Context, r *identity.Role) error {
	return s.db.WithContext(ctx).Table(s.t.roles).Create(r).Error
}

func (s *RoleStore) Update(ctx context.Context, r *identity.Role) error {
	old := r.ConcurrencyStamp
	r.ConcurrencyStamp = identity.NewConcurrencyStamp()
	res := s.db.WithContext(ctx).Table(s.t.roles).
		Where("id = ? AND concurrency_stamp = ?", r.ID, old).
		Select("name", "normalized_name", "concurrency_stamp").Updates(r)
	if res.Error != nil {
		r.ConcurrencyStamp = old
		return res.Error
	}
	if res.RowsAffected == 0 {
		r.ConcurrencyStamp = old
		var count int64
		s.db.WithContext(ctx).Table(s.t.roles).Where("id = ?", r.ID).Count(&count)
		if count == 0 {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	return nil
}

func (s *RoleStore) Delete(ctx context.Context, r *identity.Role) error {
	return s.db.WithContext(ctx).Table(s.t.roles).Where("id = ?", r.ID).Delete(&identity.Role{}).Error
}

func (s *RoleStore) FindByID(ctx context.Context, id string) (*identity.Role, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).Table(s.t.roles).Where("id = ?", id).Take(&r).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) FindByName(ctx context.Context, normalizedName string) (*identity.Role, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).Table(s.t.roles).Where("normalized_name = ?", normalizedName).Take(&r).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) GetClaims(ctx context.Context, r *identity.Role) ([]identity.Claim, error) {
	var rows []identity.RoleClaim
	if err := s.db.WithContext(ctx).Table(s.t.roleClaims).Where("role_id = ?", r.ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	claims := make([]identity.Claim, len(rows))
	for i, row := range rows {
		claims[i] = identity.Claim{Type: row.ClaimType, Value: row.ClaimValue}
	}
	return claims, nil
}

func (s *RoleStore) AddClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	return s.db.WithContext(ctx).Table(s.t.roleClaims).
		Create(&identity.RoleClaim{RoleID: r.ID, ClaimType: c.Type, ClaimValue: c.Value}).Error
}

func (s *RoleStore) RemoveClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	return s.db.WithContext(ctx).Table(s.t.roleClaims).
		Where("role_id = ? AND claim_type = ? AND claim_value = ?", r.ID, c.Type, c.Value).
		Delete(&identity.RoleClaim{}).Error
}
