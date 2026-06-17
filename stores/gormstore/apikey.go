package gormstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/terglos/go-idento/identity"
	"gorm.io/gorm"
)

// APIKeyStore is a GORM-backed identity.APIKeyStore. Build it with the same
// options used for the user store so schema/table names match.
type APIKeyStore struct {
	db *gorm.DB
	t  tables
}

var _ identity.APIKeyStore = (*APIKeyStore)(nil)

// NewAPIKeyStore builds an API-key store; pass the same options as the user store.
func NewAPIKeyStore(db *gorm.DB, opts ...Option) *APIKeyStore {
	return &APIKeyStore{db: db, t: resolveTables(resolve(opts...))}
}

func (s *APIKeyStore) CreateAPIKey(ctx context.Context, k *identity.APIKey) error {
	return s.db.WithContext(ctx).Table(s.t.apiKeys).Create(k).Error
}

func (s *APIKeyStore) GetActiveAPIKeyByHash(ctx context.Context, keyHash string) (*identity.APIKey, error) {
	var k identity.APIKey
	now := time.Now()
	err := s.db.WithContext(ctx).Table(s.t.apiKeys).
		Where("key_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)", keyHash, now).
		Take(&k).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, identity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *APIKeyStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]identity.APIKey, error) {
	var rows []identity.APIKey
	if err := s.db.WithContext(ctx).Table(s.t.apiKeys).
		Where("user_id = ?", userID).Order("created_at").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Table(s.t.apiKeys).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", time.Now()).Error
}

func (s *APIKeyStore) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Exec(
		fmt.Sprintf("UPDATE %s SET last_used_at = ? WHERE id = ?", s.t.apiKeys), time.Now(), id).Error
}
