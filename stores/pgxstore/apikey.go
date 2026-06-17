package pgxstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
)

// APIKeyStore is a raw-pgx identity.APIKeyStore. Build it with the same options
// as the user store so schema/table names match.
type APIKeyStore struct {
	db *pgxpool.Pool
	q  apiKeyQueries
}

var _ identity.APIKeyStore = (*APIKeyStore)(nil)

type apiKeyQueries struct {
	create, getActiveByHash, listByUser, revoke, touch string
}

func buildAPIKeyQueries(n identity.Naming) apiKeyQueries {
	t := n.Qualify(n.Tables.APIKeys)
	return apiKeyQueries{
		create: fmt.Sprintf(`INSERT INTO %s (id, user_id, name, prefix, key_hash, scopes, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, t),
		getActiveByHash: fmt.Sprintf(`SELECT id, user_id, name, prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_at
			FROM %s WHERE key_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, t),
		listByUser: fmt.Sprintf(`SELECT id, user_id, name, prefix, key_hash, scopes, expires_at, last_used_at, revoked_at, created_at
			FROM %s WHERE user_id=$1 ORDER BY created_at`, t),
		revoke: fmt.Sprintf(`UPDATE %s SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, t),
		touch:  fmt.Sprintf(`UPDATE %s SET last_used_at=now() WHERE id=$1`, t),
	}
}

// NewAPIKeyStore builds an API-key store; pass the same options as the user store.
func NewAPIKeyStore(db *pgxpool.Pool, opts ...Option) *APIKeyStore {
	return &APIKeyStore{db: db, q: buildAPIKeyQueries(resolve(opts...))}
}

func (s *APIKeyStore) CreateAPIKey(ctx context.Context, k *identity.APIKey) error {
	scopes, err := json.Marshal(k.Scopes)
	if err != nil {
		return err
	}
	created := k.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err = s.db.Exec(ctx, s.q.create, k.ID, k.UserID, k.Name, k.Prefix, k.KeyHash, scopes, k.ExpiresAt, created)
	return err
}

func scanAPIKey(row pgx.Row) (*identity.APIKey, error) {
	var k identity.APIKey
	var scopes []byte
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.KeyHash, &scopes,
		&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	if len(scopes) > 0 {
		_ = json.Unmarshal(scopes, &k.Scopes)
	}
	return &k, nil
}

func (s *APIKeyStore) GetActiveAPIKeyByHash(ctx context.Context, keyHash string) (*identity.APIKey, error) {
	return scanAPIKey(s.db.QueryRow(ctx, s.q.getActiveByHash, keyHash))
}

func (s *APIKeyStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]identity.APIKey, error) {
	rows, err := s.db.Query(ctx, s.q.listByUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *APIKeyStore) RevokeAPIKey(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, s.q.revoke, id)
	return err
}

func (s *APIKeyStore) TouchAPIKeyLastUsed(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, s.q.touch, id)
	return err
}
