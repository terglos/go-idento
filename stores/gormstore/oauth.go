package gormstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// OAuthStore is a GORM-backed oauth.Store (embedded OAuth 2.1 authorization
// server). Build it with the same options as the user store so schema/table
// names match; Migrate creates its tables.
type OAuthStore struct {
	db *gorm.DB
	t  tables
}

var _ oauth.Store = (*OAuthStore)(nil)

// NewOAuthStore builds the authorization server's store.
func NewOAuthStore(db *gorm.DB, opts ...Option) *OAuthStore {
	return &OAuthStore{db: db, t: resolveTables(resolve(opts...))}
}

func take[T any](q *gorm.DB) (*T, error) {
	var v T
	if err := q.Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, identity.ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

func (s *OAuthStore) CreateClient(ctx context.Context, c *oauth.Client) error {
	return s.db.WithContext(ctx).Table(s.t.oauthClients).Create(c).Error
}

func (s *OAuthStore) GetClient(ctx context.Context, clientID string) (*oauth.Client, error) {
	return take[oauth.Client](s.db.WithContext(ctx).Table(s.t.oauthClients).Where("client_id = ?", clientID))
}

func (s *OAuthStore) TouchClient(ctx context.Context, clientID string, at time.Time) error {
	return s.db.WithContext(ctx).Table(s.t.oauthClients).Where("client_id = ?", clientID).
		Update("last_used_at", at).Error
}

func (s *OAuthStore) DeleteStaleClients(ctx context.Context, before time.Time) (int64, error) {
	// Two steps (select, then delete by id) keep this portable across SQLite,
	// MySQL and Postgres, which disagree on correlated DELETE aliasing.
	var ids []string
	q := fmt.Sprintf(`SELECT c.client_id FROM %s c WHERE c.created_at < ? AND (c.last_used_at IS NULL OR c.last_used_at < ?)
		AND NOT EXISTS (SELECT 1 FROM %s g WHERE g.client_id = c.client_id)`, s.t.oauthClients, s.t.oauthGrants)
	if err := s.db.WithContext(ctx).Raw(q, before, before).Scan(&ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res := s.db.WithContext(ctx).Table(s.t.oauthClients).Where("client_id IN ?", ids).Delete(&oauth.Client{})
	return res.RowsAffected, res.Error
}

func (s *OAuthStore) CreateCode(ctx context.Context, c *oauth.Code) error {
	return s.db.WithContext(ctx).Table(s.t.oauthCodes).Create(c).Error
}

func (s *OAuthStore) GetCode(ctx context.Context, codeHash string) (*oauth.Code, error) {
	return take[oauth.Code](s.db.WithContext(ctx).Table(s.t.oauthCodes).Where("code_hash = ?", codeHash))
}

func (s *OAuthStore) MarkCodeUsed(ctx context.Context, codeHash, grantID string, at time.Time) (bool, error) {
	res := s.db.WithContext(ctx).Table(s.t.oauthCodes).Where("code_hash = ? AND used_at IS NULL", codeHash).
		Updates(map[string]any{"used_at": at, "grant_id": grantID})
	return res.RowsAffected == 1, res.Error
}

func (s *OAuthStore) DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Table(s.t.oauthCodes).Where("expires_at < ?", before).Delete(&oauth.Code{})
	return res.RowsAffected, res.Error
}

func (s *OAuthStore) GetConsent(ctx context.Context, userID, clientID string) (*oauth.Consent, error) {
	return take[oauth.Consent](s.db.WithContext(ctx).Table(s.t.oauthConsents).
		Where("user_id = ? AND client_id = ?", userID, clientID))
}

func (s *OAuthStore) SaveConsent(ctx context.Context, c *oauth.Consent) error {
	return s.db.WithContext(ctx).Table(s.t.oauthConsents).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"scopes", "updated_at"}),
	}).Create(c).Error
}

func (s *OAuthStore) DeleteConsent(ctx context.Context, userID, clientID string) error {
	return s.db.WithContext(ctx).Table(s.t.oauthConsents).
		Where("user_id = ? AND client_id = ?", userID, clientID).Delete(&oauth.Consent{}).Error
}

func (s *OAuthStore) CreateGrant(ctx context.Context, g *oauth.Grant) error {
	return s.db.WithContext(ctx).Table(s.t.oauthGrants).Create(g).Error
}

func (s *OAuthStore) GetGrant(ctx context.Context, id string) (*oauth.Grant, error) {
	return take[oauth.Grant](s.db.WithContext(ctx).Table(s.t.oauthGrants).Where("id = ?", id))
}

func (s *OAuthStore) RotateGrant(ctx context.Context, id, oldHash, newHash string, expiresAt, usedAt time.Time) (bool, error) {
	res := s.db.WithContext(ctx).Table(s.t.oauthGrants).Where("id = ? AND token_hash = ?", id, oldHash).
		Updates(map[string]any{"prev_token_hash": oldHash, "token_hash": newHash, "expires_at": expiresAt, "last_used_at": usedAt})
	return res.RowsAffected == 1, res.Error
}

func (s *OAuthStore) DeleteGrant(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Table(s.t.oauthGrants).Where("id = ?", id).Delete(&oauth.Grant{}).Error
}

func (s *OAuthStore) DeleteUserClientGrants(ctx context.Context, userID, clientID string) (int64, error) {
	res := s.db.WithContext(ctx).Table(s.t.oauthGrants).
		Where("user_id = ? AND client_id = ?", userID, clientID).Delete(&oauth.Grant{})
	return res.RowsAffected, res.Error
}

func (s *OAuthStore) ListUserGrants(ctx context.Context, userID string) ([]oauth.Grant, error) {
	var rows []oauth.Grant
	err := s.db.WithContext(ctx).Table(s.t.oauthGrants).Where("user_id = ?", userID).Order("created_at").Find(&rows).Error
	return rows, err
}

func (s *OAuthStore) DeleteExpiredGrants(ctx context.Context, before time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Table(s.t.oauthGrants).Where("expires_at < ?", before).Delete(&oauth.Grant{})
	return res.RowsAffected, res.Error
}
