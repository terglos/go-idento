package gormstore

import (
	"context"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
)

// GenericUserStore is a GORM user store for a custom user type T that embeds
// identity.User (and therefore satisfies identity.UserModel via Base()). It is
// what enables the generic UserManagerOf[T] to persist custom columns on the
// user row.
//
// Because the embedded *User promotes TableName() ("identity_users"), the custom
// type maps to the same users table with the extra fields as additional columns.
type GenericUserStore[T any, PT identity.Ptr[T]] struct{ db *gorm.DB }

// NewUserStoreOf builds a generic user store for T.
func NewUserStoreOf[T any, PT identity.Ptr[T]](db *gorm.DB) *GenericUserStore[T, PT] {
	return &GenericUserStore[T, PT]{db: db}
}

// MigrateOf creates/updates the custom user table plus the shared satellite
// tables (roles, claims, tokens, logins).
func MigrateOf[T any](db *gorm.DB) error {
	return db.AutoMigrate(
		new(T), &identity.Role{}, &identity.UserRole{},
		&identity.UserClaim{}, &identity.RoleClaim{},
		&identity.UserLogin{}, &identity.UserToken{},
	)
}

func (s *GenericUserStore[T, PT]) Create(ctx context.Context, u PT) error {
	return s.db.WithContext(ctx).Create(u).Error
}

func (s *GenericUserStore[T, PT]) Update(ctx context.Context, u PT) error {
	b := u.Base()
	old := b.ConcurrencyStamp
	b.ConcurrencyStamp = identity.NewConcurrencyStamp()
	res := s.db.WithContext(ctx).Model(u).Where("concurrency_stamp = ?", old).Select("*").Updates(u)
	if res.Error != nil {
		b.ConcurrencyStamp = old
		return res.Error
	}
	if res.RowsAffected == 0 {
		b.ConcurrencyStamp = old
		var count int64
		s.db.WithContext(ctx).Model(u).Where("id = ?", b.ID).Count(&count)
		if count == 0 {
			return identity.ErrNotFound
		}
		return identity.ErrConcurrencyFailure
	}
	return nil
}

func (s *GenericUserStore[T, PT]) Delete(ctx context.Context, u PT) error {
	return s.db.WithContext(ctx).Delete(u).Error
}

func (s *GenericUserStore[T, PT]) find(ctx context.Context, where string, arg any) (PT, error) {
	var x T
	if err := s.db.WithContext(ctx).First(&x, where, arg).Error; err != nil {
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

// Satellite operations key off the base user id and reuse the shared tables.

func (s *GenericUserStore[T, PT]) roleIDByName(ctx context.Context, name string) (string, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).First(&r, "normalized_name = ?", name).Error; err != nil {
		return "", mapNotFound(err)
	}
	return r.ID, nil
}

func (s *GenericUserStore[T, PT]) AddToRole(ctx context.Context, u PT, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Create(&identity.UserRole{UserID: u.Base().ID, RoleID: rid}).Error
}

func (s *GenericUserStore[T, PT]) RemoveFromRole(ctx context.Context, u PT, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", u.Base().ID, rid).
		Delete(&identity.UserRole{}).Error
}

func (s *GenericUserStore[T, PT]) GetRoles(ctx context.Context, u PT) ([]string, error) {
	var names []string
	err := s.db.WithContext(ctx).Model(&identity.Role{}).
		Joins("JOIN identity_user_roles ur ON ur.role_id = identity_roles.id").
		Where("ur.user_id = ?", u.Base().ID).
		Pluck("identity_roles.name", &names).Error
	return names, err
}

func (s *GenericUserStore[T, PT]) IsInRole(ctx context.Context, u PT, normalizedRoleName string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&identity.UserRole{}).
		Joins("JOIN identity_roles r ON r.id = identity_user_roles.role_id").
		Where("identity_user_roles.user_id = ? AND r.normalized_name = ?", u.Base().ID, normalizedRoleName).
		Count(&count).Error
	return count > 0, err
}

func (s *GenericUserStore[T, PT]) GetClaims(ctx context.Context, u PT) ([]identity.Claim, error) {
	var rows []identity.UserClaim
	if err := s.db.WithContext(ctx).Where("user_id = ?", u.Base().ID).Find(&rows).Error; err != nil {
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
	return s.db.WithContext(ctx).Create(&rows).Error
}

func (s *GenericUserStore[T, PT]) RemoveClaims(ctx context.Context, u PT, claims []identity.Claim) error {
	id := u.Base().ID
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, c := range claims {
			if err := tx.Where("user_id = ? AND claim_type = ? AND claim_value = ?", id, c.Type, c.Value).
				Delete(&identity.UserClaim{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *GenericUserStore[T, PT]) GetToken(ctx context.Context, u PT, loginProvider, name string) (string, error) {
	var t identity.UserToken
	err := s.db.WithContext(ctx).
		First(&t, "user_id = ? AND login_provider = ? AND name = ?", u.Base().ID, loginProvider, name).Error
	if err == gorm.ErrRecordNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return t.Value, nil
}

func (s *GenericUserStore[T, PT]) SetToken(ctx context.Context, u PT, loginProvider, name, value string) error {
	return s.db.WithContext(ctx).Save(&identity.UserToken{
		UserID: u.Base().ID, LoginProvider: loginProvider, Name: name, Value: value,
	}).Error
}

func (s *GenericUserStore[T, PT]) RemoveToken(ctx context.Context, u PT, loginProvider, name string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.Base().ID, loginProvider, name).
		Delete(&identity.UserToken{}).Error
}

func (s *GenericUserStore[T, PT]) AddLogin(ctx context.Context, u PT, login identity.UserLoginInfo) error {
	return s.db.WithContext(ctx).Create(&identity.UserLogin{
		LoginProvider: login.LoginProvider, ProviderKey: login.ProviderKey,
		ProviderDisplayName: login.ProviderDisplayName, UserID: u.Base().ID,
	}).Error
}

func (s *GenericUserStore[T, PT]) RemoveLogin(ctx context.Context, u PT, loginProvider, providerKey string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ? AND login_provider = ? AND provider_key = ?", u.Base().ID, loginProvider, providerKey).
		Delete(&identity.UserLogin{}).Error
}

func (s *GenericUserStore[T, PT]) GetLogins(ctx context.Context, u PT) ([]identity.UserLoginInfo, error) {
	var rows []identity.UserLogin
	if err := s.db.WithContext(ctx).Where("user_id = ?", u.Base().ID).Find(&rows).Error; err != nil {
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
	if err := s.db.WithContext(ctx).
		First(&login, "login_provider = ? AND provider_key = ?", loginProvider, providerKey).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, login.UserID)
}
