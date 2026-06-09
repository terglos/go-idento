package gormstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GenericUserStore is a GORM user store for a custom user type T that embeds
// identity.User (and therefore satisfies identity.UserModel via Base()). It is
// what enables the generic UserManagerOf[T] to persist custom columns on the
// user row. Schema/table names are configurable via the same options as the
// concrete store.
type GenericUserStore[T any, PT identity.Ptr[T]] struct {
	db *gorm.DB
	t  tables
}

// Compile-time check that the generic store satisfies the full user store (and
// the optional lister) for a representative type, so a new interface method is
// caught here as well as on the concrete store.
var (
	_ identity.UserStore[identity.User, *identity.User]  = (*GenericUserStore[identity.User, *identity.User])(nil)
	_ identity.UserLister[identity.User, *identity.User] = (*GenericUserStore[identity.User, *identity.User])(nil)
)

// NewUserStoreOf builds a generic user store for T.
func NewUserStoreOf[T any, PT identity.Ptr[T]](db *gorm.DB, opts ...Option) *GenericUserStore[T, PT] {
	return &GenericUserStore[T, PT]{db: db, t: resolveTables(resolve(opts...))}
}

// MigrateOf creates/updates the custom user table plus the shared satellite
// tables (roles, claims, tokens, logins), honoring schema/prefix options.
func MigrateOf[T any](db *gorm.DB, opts ...Option) error {
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
	if err := db.Table(t.users).AutoMigrate(new(T)); err != nil {
		return err
	}
	steps := []struct {
		name  string
		model any
	}{
		{t.roles, &identity.Role{}}, {t.userRoles, &identity.UserRole{}},
		{t.userClaims, &identity.UserClaim{}}, {t.roleClaims, &identity.RoleClaim{}},
		{t.userLogins, &identity.UserLogin{}}, {t.userTokens, &identity.UserToken{}},
	}
	for _, s := range steps {
		if err := db.Table(s.name).AutoMigrate(s.model); err != nil {
			return err
		}
	}
	return nil
}

func (s *GenericUserStore[T, PT]) Create(ctx context.Context, u PT) error {
	return s.db.WithContext(ctx).Table(s.t.users).Create(u).Error
}

func (s *GenericUserStore[T, PT]) Update(ctx context.Context, u PT) error {
	b := u.Base()
	old := b.ConcurrencyStamp
	b.ConcurrencyStamp = identity.NewConcurrencyStamp()
	res := s.db.WithContext(ctx).Table(s.t.users).
		Where("id = ? AND concurrency_stamp = ?", b.ID, old).Select("*").Updates(u)
	if res.Error != nil {
		b.ConcurrencyStamp = old
		return res.Error
	}
	if res.RowsAffected == 0 {
		b.ConcurrencyStamp = old
		var count int64
		s.db.WithContext(ctx).Table(s.t.users).Where("id = ?", b.ID).Count(&count)
		if count == 0 {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	return nil
}

func (s *GenericUserStore[T, PT]) Delete(ctx context.Context, u PT) error {
	return s.t.deleteUserCascade(s.db.WithContext(ctx), u.Base().ID)
}

func (s *GenericUserStore[T, PT]) find(ctx context.Context, where string, arg any) (PT, error) {
	var x T
	if err := s.db.WithContext(ctx).Table(s.t.users).Where(where, arg).Take(&x).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return PT(&x), nil
}

func (s *GenericUserStore[T, PT]) FindByID(ctx context.Context, id string) (PT, error) {
	return s.find(ctx, "id = ?", id)
}

func (s *GenericUserStore[T, PT]) FindByName(ctx context.Context, n string) (PT, error) {
	return s.find(ctx, "normalized_user_name = ?", n)
}

func (s *GenericUserStore[T, PT]) FindByEmail(ctx context.Context, e string) (PT, error) {
	return s.find(ctx, "normalized_email = ?", e)
}

// ListUsers implements identity.UserLister for the custom user type.
func (s *GenericUserStore[T, PT]) ListUsers(ctx context.Context, f identity.ListFilter) ([]PT, int64, error) {
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
	var rows []T
	if err := filtered().Order("id").Limit(f.Limit).Offset(f.Offset).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	page := make([]PT, len(rows))
	for i := range rows {
		page[i] = PT(&rows[i])
	}
	return page, total, nil
}

// Satellite operations key off the base user id and reuse the shared tables.

func (s *GenericUserStore[T, PT]) roleIDByName(ctx context.Context, name string) (string, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).Table(s.t.roles).Where("normalized_name = ?", name).Take(&r).Error; err != nil {
		return "", mapNotFound(err)
	}
	return r.ID, nil
}

func (s *GenericUserStore[T, PT]) AddToRole(ctx context.Context, u PT, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Table(s.t.userRoles).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&identity.UserRole{UserID: u.Base().ID, RoleID: rid}).Error
}

func (s *GenericUserStore[T, PT]) RemoveFromRole(ctx context.Context, u PT, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Table(s.t.userRoles).
		Where("user_id = ? AND role_id = ?", u.Base().ID, rid).Delete(&identity.UserRole{}).Error
}

func (s *GenericUserStore[T, PT]) GetRoles(ctx context.Context, u PT) ([]string, error) {
	var names []string
	sql := fmt.Sprintf(`SELECT r.name FROM %s r JOIN %s ur ON ur.role_id = r.id WHERE ur.user_id = ?`, s.t.roles, s.t.userRoles)
	err := s.db.WithContext(ctx).Raw(sql, u.Base().ID).Scan(&names).Error
	return names, err
}

func (s *GenericUserStore[T, PT]) IsInRole(ctx context.Context, u PT, normalizedRoleName string) (bool, error) {
	var count int64
	sql := fmt.Sprintf(`SELECT count(*) FROM %s ur JOIN %s r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.normalized_name = ?`, s.t.userRoles, s.t.roles)
	err := s.db.WithContext(ctx).Raw(sql, u.Base().ID, normalizedRoleName).Scan(&count).Error
	return count > 0, err
}

func (s *GenericUserStore[T, PT]) GetUsersInRole(ctx context.Context, normalizedRoleName string) ([]PT, error) {
	var ids []string
	sql := fmt.Sprintf(`SELECT ur.user_id FROM %s ur JOIN %s r ON r.id = ur.role_id WHERE r.normalized_name = ?`, s.t.userRoles, s.t.roles)
	if err := s.db.WithContext(ctx).Raw(sql, normalizedRoleName).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return s.usersByIDs(ctx, ids)
}

func (s *GenericUserStore[T, PT]) GetUsersForClaim(ctx context.Context, claimType, claimValue string) ([]PT, error) {
	var ids []string
	sql := fmt.Sprintf(`SELECT user_id FROM %s WHERE claim_type = ? AND claim_value = ?`, s.t.userClaims)
	if err := s.db.WithContext(ctx).Raw(sql, claimType, claimValue).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return s.usersByIDs(ctx, ids)
}

func (s *GenericUserStore[T, PT]) usersByIDs(ctx context.Context, ids []string) ([]PT, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []T
	if err := s.db.WithContext(ctx).Table(s.t.users).Where("id IN ?", ids).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]PT, len(rows))
	for i := range rows {
		out[i] = PT(&rows[i])
	}
	return out, nil
}

func (s *GenericUserStore[T, PT]) GetClaims(ctx context.Context, u PT) ([]identity.Claim, error) {
	var rows []identity.UserClaim
	if err := s.db.WithContext(ctx).Table(s.t.userClaims).Where("user_id = ?", u.Base().ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	claims := make([]identity.Claim, len(rows))
	for i, r := range rows {
		claims[i] = identity.Claim{Type: r.ClaimType, Value: r.ClaimValue}
	}
	return claims, nil
}

func (s *GenericUserStore[T, PT]) AddClaims(ctx context.Context, u PT, claims []identity.Claim) error {
	rows := make([]identity.UserClaim, len(claims))
	for i, c := range claims {
		rows[i] = identity.UserClaim{UserID: u.Base().ID, ClaimType: c.Type, ClaimValue: c.Value}
	}
	return s.db.WithContext(ctx).Table(s.t.userClaims).Create(&rows).Error
}

func (s *GenericUserStore[T, PT]) RemoveClaims(ctx context.Context, u PT, claims []identity.Claim) error {
	id := u.Base().ID
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, c := range claims {
			if err := tx.Table(s.t.userClaims).
				Where("user_id = ? AND claim_type = ? AND claim_value = ?", id, c.Type, c.Value).
				Delete(&identity.UserClaim{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *GenericUserStore[T, PT]) GetToken(ctx context.Context, u PT, loginProvider, name string) (string, error) {
	var t identity.UserToken
	err := s.db.WithContext(ctx).Table(s.t.userTokens).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.Base().ID, loginProvider, name).Take(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return t.Value, nil
}

func (s *GenericUserStore[T, PT]) SetToken(ctx context.Context, u PT, loginProvider, name, value string) error {
	return s.db.WithContext(ctx).Table(s.t.userTokens).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "login_provider"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&identity.UserToken{
		UserID: u.Base().ID, LoginProvider: loginProvider, Name: name, Value: value,
	}).Error
}

func (s *GenericUserStore[T, PT]) RemoveToken(ctx context.Context, u PT, loginProvider, name string) error {
	return s.db.WithContext(ctx).Table(s.t.userTokens).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.Base().ID, loginProvider, name).
		Delete(&identity.UserToken{}).Error
}

func (s *GenericUserStore[T, PT]) AddLogin(ctx context.Context, u PT, login identity.UserLoginInfo) error {
	return s.db.WithContext(ctx).Table(s.t.userLogins).Create(&identity.UserLogin{
		LoginProvider: login.LoginProvider, ProviderKey: login.ProviderKey,
		ProviderDisplayName: login.ProviderDisplayName, UserID: u.Base().ID,
	}).Error
}

func (s *GenericUserStore[T, PT]) RemoveLogin(ctx context.Context, u PT, loginProvider, providerKey string) error {
	return s.db.WithContext(ctx).Table(s.t.userLogins).
		Where("user_id = ? AND login_provider = ? AND provider_key = ?", u.Base().ID, loginProvider, providerKey).
		Delete(&identity.UserLogin{}).Error
}

func (s *GenericUserStore[T, PT]) GetLogins(ctx context.Context, u PT) ([]identity.UserLoginInfo, error) {
	var rows []identity.UserLogin
	if err := s.db.WithContext(ctx).Table(s.t.userLogins).Where("user_id = ?", u.Base().ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]identity.UserLoginInfo, len(rows))
	for i, r := range rows {
		out[i] = identity.UserLoginInfo{LoginProvider: r.LoginProvider, ProviderKey: r.ProviderKey, ProviderDisplayName: r.ProviderDisplayName}
	}
	return out, nil
}

func (s *GenericUserStore[T, PT]) FindByLogin(ctx context.Context, loginProvider, providerKey string) (PT, error) {
	var login identity.UserLogin
	if err := s.db.WithContext(ctx).Table(s.t.userLogins).
		Where("login_provider = ? AND provider_key = ?", loginProvider, providerKey).Take(&login).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, login.UserID)
}
