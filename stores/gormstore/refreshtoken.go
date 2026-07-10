package gormstore

import (
	"context"
	"errors"
	"time"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
)

// RefreshTokenStore is a GORM-backed identity.RefreshTokenStore (one row per
// refresh session). Build it with the same options as the user store so
// schema/table names match, and wire it via TokenService.WithSessionStore.
type RefreshTokenStore struct {
	db *gorm.DB
	t  tables
}

var _ identity.RefreshTokenStore = (*RefreshTokenStore)(nil)

// NewRefreshTokenStore builds a refresh-session store.
func NewRefreshTokenStore(db *gorm.DB, opts ...Option) *RefreshTokenStore {
	return &RefreshTokenStore{db: db, t: resolveTables(resolve(opts...))}
}

func (s *RefreshTokenStore) CreateRefreshToken(ctx context.Context, rt *identity.RefreshToken) error {
	return s.db.WithContext(ctx).Table(s.t.refreshTokens).Create(rt).Error
}

func (s *RefreshTokenStore) GetRefreshTokenBySession(ctx context.Context, sessionID string) (*identity.RefreshToken, error) {
	var rt identity.RefreshToken
	err := s.db.WithContext(ctx).Table(s.t.refreshTokens).Where("session_id = ?", sessionID).Take(&rt).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, identity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *RefreshTokenStore) UpdateRefreshToken(ctx context.Context, rt *identity.RefreshToken) error {
	res := s.db.WithContext(ctx).Table(s.t.refreshTokens).Where("session_id = ?", rt.SessionID).
		Select("token_hash", "expires_at", "last_used_at", "name").Updates(rt)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return identity.ErrNotFound
	}
	return nil
}

func (s *RefreshTokenStore) DeleteRefreshToken(ctx context.Context, sessionID string) error {
	return s.db.WithContext(ctx).Table(s.t.refreshTokens).
		Where("session_id = ?", sessionID).Delete(&identity.RefreshToken{}).Error
}

func (s *RefreshTokenStore) DeleteUserRefreshTokens(ctx context.Context, userID string) (int64, error) {
	res := s.db.WithContext(ctx).Table(s.t.refreshTokens).
		Where("user_id = ?", userID).Delete(&identity.RefreshToken{})
	return res.RowsAffected, res.Error
}

func (s *RefreshTokenStore) DeleteExpiredRefreshTokens(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Table(s.t.refreshTokens).
		Where("expires_at < ?", before).Delete(&identity.RefreshToken{})
	return res.RowsAffected, res.Error
}

func (s *RefreshTokenStore) ListUserRefreshTokens(ctx context.Context, userID string) ([]identity.RefreshToken, error) {
	var rows []identity.RefreshToken
	if err := s.db.WithContext(ctx).Table(s.t.refreshTokens).
		Where("user_id = ?", userID).Order("created_at").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
