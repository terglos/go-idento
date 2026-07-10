package pgxstore

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
)

// RefreshTokenStore is a raw-pgx identity.RefreshTokenStore (one row per refresh
// session). Build it with the same options as the user store, and wire it via
// TokenService.WithSessionStore.
type RefreshTokenStore struct {
	db *pgxpool.Pool
	q  refreshTokenQueries
}

var _ identity.RefreshTokenStore = (*RefreshTokenStore)(nil)

type refreshTokenQueries struct {
	create, getBySession, update, del, delByUser, delExpired, listByUser string
}

func buildRefreshTokenQueries(n identity.Naming) refreshTokenQueries {
	t := n.Qualify(n.Tables.RefreshTokens)
	const cols = `session_id, user_id, token_hash, name, expires_at, created_at, last_used_at`
	return refreshTokenQueries{
		create:       fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7)`, t, cols),
		getBySession: fmt.Sprintf(`SELECT %s FROM %s WHERE session_id=$1`, cols, t),
		update:       fmt.Sprintf(`UPDATE %s SET token_hash=$2, expires_at=$3, last_used_at=$4, name=$5 WHERE session_id=$1`, t),
		del:          fmt.Sprintf(`DELETE FROM %s WHERE session_id=$1`, t),
		delByUser:    fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1`, t),
		delExpired:   fmt.Sprintf(`DELETE FROM %s WHERE expires_at < $1`, t),
		listByUser:   fmt.Sprintf(`SELECT %s FROM %s WHERE user_id=$1 ORDER BY created_at`, cols, t),
	}
}

// NewRefreshTokenStore builds a refresh-session store.
func NewRefreshTokenStore(db *pgxpool.Pool, opts ...Option) *RefreshTokenStore {
	return &RefreshTokenStore{db: db, q: buildRefreshTokenQueries(resolve(opts...))}
}

func (s *RefreshTokenStore) CreateRefreshToken(ctx context.Context, rt *identity.RefreshToken) error {
	created := rt.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.Exec(ctx, s.q.create, rt.SessionID, rt.UserID, rt.TokenHash, rt.Name, rt.ExpiresAt, created, rt.LastUsedAt)
	return err
}

func scanRefreshToken(row pgx.Row) (*identity.RefreshToken, error) {
	var rt identity.RefreshToken
	if err := row.Scan(&rt.SessionID, &rt.UserID, &rt.TokenHash, &rt.Name,
		&rt.ExpiresAt, &rt.CreatedAt, &rt.LastUsedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &rt, nil
}

func (s *RefreshTokenStore) GetRefreshTokenBySession(ctx context.Context, sessionID string) (*identity.RefreshToken, error) {
	return scanRefreshToken(s.db.QueryRow(ctx, s.q.getBySession, sessionID))
}

func (s *RefreshTokenStore) UpdateRefreshToken(ctx context.Context, rt *identity.RefreshToken) error {
	tag, err := s.db.Exec(ctx, s.q.update, rt.SessionID, rt.TokenHash, rt.ExpiresAt, rt.LastUsedAt, rt.Name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}

func (s *RefreshTokenStore) DeleteRefreshToken(ctx context.Context, sessionID string) error {
	_, err := s.db.Exec(ctx, s.q.del, sessionID)
	return err
}

func (s *RefreshTokenStore) DeleteUserRefreshTokens(ctx context.Context, userID string) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.delByUser, userID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *RefreshTokenStore) DeleteExpiredRefreshTokens(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.delExpired, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *RefreshTokenStore) ListUserRefreshTokens(ctx context.Context, userID string) ([]identity.RefreshToken, error) {
	rows, err := s.db.Query(ctx, s.q.listByUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.RefreshToken
	for rows.Next() {
		rt, err := scanRefreshToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rt)
	}
	return out, rows.Err()
}
