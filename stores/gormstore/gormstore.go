// Package gormstore provides a GORM-backed implementation of the identity
// UserStore and RoleStore, supporting Postgres, MySQL and SQLite from a single
// codebase via a single ORM.
package gormstore

import (
	"context"
	"errors"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
)

// UserStore implements identity.UserStore over GORM.
type UserStore struct{ db *gorm.DB }

// RoleStore implements identity.RoleStore over GORM.
type RoleStore struct{ db *gorm.DB }

func NewUserStore(db *gorm.DB) *UserStore { return &UserStore{db: db} }
func NewRoleStore(db *gorm.DB) *RoleStore { return &RoleStore{db: db} }

// Compile-time interface conformance.
var (
	_ identity.DefaultUserStore = (*UserStore)(nil)
	_ identity.RoleStore        = (*RoleStore)(nil)
)

// Migrate creates/updates all identity tables.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&identity.User{}, &identity.Role{}, &identity.UserRole{},
		&identity.UserClaim{}, &identity.RoleClaim{},
		&identity.UserLogin{}, &identity.UserToken{},
	)
}

func mapNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return identity.ErrNotFound
	}
	return err
}

// --- UserStore ---

func (s *UserStore) Create(ctx context.Context, u *identity.User) error {
	return s.db.WithContext(ctx).Create(u).Error
}

func (s *UserStore) Update(ctx context.Context, u *identity.User) error {
	return s.db.WithContext(ctx).Save(u).Error
}

func (s *UserStore) Delete(ctx context.Context, u *identity.User) error {
	return s.db.WithContext(ctx).Delete(u).Error
}

func (s *UserStore) FindByID(ctx context.Context, id string) (*identity.User, error) {
	var u identity.User
	if err := s.db.WithContext(ctx).First(&u, "id = ?", id).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

func (s *UserStore) FindByName(ctx context.Context, normalizedUserName string) (*identity.User, error) {
	var u identity.User
	if err := s.db.WithContext(ctx).First(&u, "normalized_user_name = ?", normalizedUserName).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

func (s *UserStore) FindByEmail(ctx context.Context, normalizedEmail string) (*identity.User, error) {
	var u identity.User
	if err := s.db.WithContext(ctx).First(&u, "normalized_email = ?", normalizedEmail).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

func (s *UserStore) roleIDByName(ctx context.Context, normalizedRoleName string) (string, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).First(&r, "normalized_name = ?", normalizedRoleName).Error; err != nil {
		return "", mapNotFound(err)
	}
	return r.ID, nil
}

func (s *UserStore) AddToRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Create(&identity.UserRole{UserID: u.ID, RoleID: rid}).Error
}

func (s *UserStore) RemoveFromRole(ctx context.Context, u *identity.User, normalizedRoleName string) error {
	rid, err := s.roleIDByName(ctx, normalizedRoleName)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ?", u.ID, rid).
		Delete(&identity.UserRole{}).Error
}

func (s *UserStore) GetRoles(ctx context.Context, u *identity.User) ([]string, error) {
	var names []string
	err := s.db.WithContext(ctx).
		Model(&identity.Role{}).
		Joins("JOIN identity_user_roles ur ON ur.role_id = identity_roles.id").
		Where("ur.user_id = ?", u.ID).
		Pluck("identity_roles.name", &names).Error
	return names, err
}

func (s *UserStore) IsInRole(ctx context.Context, u *identity.User, normalizedRoleName string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).
		Model(&identity.UserRole{}).
		Joins("JOIN identity_roles r ON r.id = identity_user_roles.role_id").
		Where("identity_user_roles.user_id = ? AND r.normalized_name = ?", u.ID, normalizedRoleName).
		Count(&count).Error
	return count > 0, err
}

func (s *UserStore) GetClaims(ctx context.Context, u *identity.User) ([]identity.Claim, error) {
	var rows []identity.UserClaim
	if err := s.db.WithContext(ctx).Where("user_id = ?", u.ID).Find(&rows).Error; err != nil {
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
	return s.db.WithContext(ctx).Create(&rows).Error
}

func (s *UserStore) RemoveClaims(ctx context.Context, u *identity.User, claims []identity.Claim) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, c := range claims {
			if err := tx.Where("user_id = ? AND claim_type = ? AND claim_value = ?", u.ID, c.Type, c.Value).
				Delete(&identity.UserClaim{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *UserStore) GetToken(ctx context.Context, u *identity.User, loginProvider, name string) (string, error) {
	var t identity.UserToken
	err := s.db.WithContext(ctx).
		First(&t, "user_id = ? AND login_provider = ? AND name = ?", u.ID, loginProvider, name).Error
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
	// Upsert on the composite primary key.
	return s.db.WithContext(ctx).Save(&tok).Error
}

func (s *UserStore) RemoveToken(ctx context.Context, u *identity.User, loginProvider, name string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ? AND login_provider = ? AND name = ?", u.ID, loginProvider, name).
		Delete(&identity.UserToken{}).Error
}

func (s *UserStore) AddLogin(ctx context.Context, u *identity.User, login identity.UserLoginInfo) error {
	return s.db.WithContext(ctx).Create(&identity.UserLogin{
		LoginProvider:       login.LoginProvider,
		ProviderKey:         login.ProviderKey,
		ProviderDisplayName: login.ProviderDisplayName,
		UserID:              u.ID,
	}).Error
}

func (s *UserStore) RemoveLogin(ctx context.Context, u *identity.User, loginProvider, providerKey string) error {
	return s.db.WithContext(ctx).
		Where("user_id = ? AND login_provider = ? AND provider_key = ?", u.ID, loginProvider, providerKey).
		Delete(&identity.UserLogin{}).Error
}

func (s *UserStore) GetLogins(ctx context.Context, u *identity.User) ([]identity.UserLoginInfo, error) {
	var rows []identity.UserLogin
	if err := s.db.WithContext(ctx).Where("user_id = ?", u.ID).Find(&rows).Error; err != nil {
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
	if err := s.db.WithContext(ctx).
		First(&login, "login_provider = ? AND provider_key = ?", loginProvider, providerKey).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return s.FindByID(ctx, login.UserID)
}

// --- RoleStore ---

func (s *RoleStore) Create(ctx context.Context, r *identity.Role) error {
	return s.db.WithContext(ctx).Create(r).Error
}

func (s *RoleStore) Update(ctx context.Context, r *identity.Role) error {
	return s.db.WithContext(ctx).Save(r).Error
}

func (s *RoleStore) Delete(ctx context.Context, r *identity.Role) error {
	return s.db.WithContext(ctx).Delete(r).Error
}

func (s *RoleStore) FindByID(ctx context.Context, id string) (*identity.Role, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).First(&r, "id = ?", id).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) FindByName(ctx context.Context, normalizedName string) (*identity.Role, error) {
	var r identity.Role
	if err := s.db.WithContext(ctx).First(&r, "normalized_name = ?", normalizedName).Error; err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (s *RoleStore) GetClaims(ctx context.Context, r *identity.Role) ([]identity.Claim, error) {
	var rows []identity.RoleClaim
	if err := s.db.WithContext(ctx).Where("role_id = ?", r.ID).Find(&rows).Error; err != nil {
		return nil, err
	}
	claims := make([]identity.Claim, len(rows))
	for i, row := range rows {
		claims[i] = identity.Claim{Type: row.ClaimType, Value: row.ClaimValue}
	}
	return claims, nil
}

func (s *RoleStore) AddClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	return s.db.WithContext(ctx).Create(&identity.RoleClaim{RoleID: r.ID, ClaimType: c.Type, ClaimValue: c.Value}).Error
}

func (s *RoleStore) RemoveClaim(ctx context.Context, r *identity.Role, c identity.Claim) error {
	return s.db.WithContext(ctx).
		Where("role_id = ? AND claim_type = ? AND claim_value = ?", r.ID, c.Type, c.Value).
		Delete(&identity.RoleClaim{}).Error
}
