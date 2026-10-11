package pgxstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
)

// OAuthStore is a raw-pgx oauth.Store (embedded OAuth 2.1 authorization
// server). Build it with the same options as the user store; Migrate creates its
// tables (with ON DELETE CASCADE to users for codes, consents and grants).
type OAuthStore struct {
	db *pgxpool.Pool
	q  oauthQueries
}

var _ oauth.Store = (*OAuthStore)(nil)

type oauthQueries struct {
	createClient, getClient, touchClient, deleteStaleClients                                string
	createCode, getCode, markCodeUsed, deleteExpiredCodes                                   string
	getConsent, saveConsent, deleteConsent                                                  string
	createGrant, getGrant, rotateGrant, deleteGrant, deleteUserClientGrants, listUserGrants string
	deleteExpiredGrants                                                                     string
}

const (
	clientCols = `client_id, secret_hash, name, redirect_uris, token_endpoint_auth_method, grant_types, created_at, last_used_at`
	codeCols   = `code_hash, client_id, user_id, redirect_uri, scopes, resource, code_challenge, expires_at, used_at, grant_id`
	grantCols  = `id, user_id, client_id, scopes, resource, token_hash, prev_token_hash, security_stamp, expires_at, created_at, last_used_at`
)

func buildOAuthQueries(n identity.Naming) oauthQueries {
	C, CD := n.Qualify(n.Tables.OAuthClients), n.Qualify(n.Tables.OAuthCodes)
	CS, G := n.Qualify(n.Tables.OAuthConsents), n.Qualify(n.Tables.OAuthGrants)
	return oauthQueries{
		createClient: fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, C, clientCols),
		getClient:    fmt.Sprintf(`SELECT %s FROM %s WHERE client_id=$1`, clientCols, C),
		touchClient:  fmt.Sprintf(`UPDATE %s SET last_used_at=$2 WHERE client_id=$1`, C),
		deleteStaleClients: fmt.Sprintf(`DELETE FROM %s c WHERE c.created_at < $1 AND (c.last_used_at IS NULL OR c.last_used_at < $1)
			AND NOT EXISTS (SELECT 1 FROM %s g WHERE g.client_id = c.client_id)`, C, G),
		createCode:         fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, CD, codeCols),
		getCode:            fmt.Sprintf(`SELECT %s FROM %s WHERE code_hash=$1`, codeCols, CD),
		markCodeUsed:       fmt.Sprintf(`UPDATE %s SET used_at=$3, grant_id=$2 WHERE code_hash=$1 AND used_at IS NULL`, CD),
		deleteExpiredCodes: fmt.Sprintf(`DELETE FROM %s WHERE expires_at < $1`, CD),
		getConsent:         fmt.Sprintf(`SELECT user_id, client_id, scopes, created_at, updated_at FROM %s WHERE user_id=$1 AND client_id=$2`, CS),
		saveConsent: fmt.Sprintf(`INSERT INTO %s (user_id, client_id, scopes, created_at, updated_at) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (user_id, client_id) DO UPDATE SET scopes=EXCLUDED.scopes, updated_at=EXCLUDED.updated_at`, CS),
		deleteConsent: fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND client_id=$2`, CS),
		createGrant:   fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, G, grantCols),
		getGrant:      fmt.Sprintf(`SELECT %s FROM %s WHERE id=$1`, grantCols, G),
		rotateGrant: fmt.Sprintf(`UPDATE %s SET prev_token_hash=token_hash, token_hash=$3, expires_at=$4, last_used_at=$5
			WHERE id=$1 AND token_hash=$2`, G),
		deleteGrant:            fmt.Sprintf(`DELETE FROM %s WHERE id=$1`, G),
		deleteUserClientGrants: fmt.Sprintf(`DELETE FROM %s WHERE user_id=$1 AND client_id=$2`, G),
		listUserGrants:         fmt.Sprintf(`SELECT %s FROM %s WHERE user_id=$1 ORDER BY created_at`, grantCols, G),
		deleteExpiredGrants:    fmt.Sprintf(`DELETE FROM %s WHERE expires_at < $1`, G),
	}
}

// NewOAuthStore builds the authorization server's store.
func NewOAuthStore(db *pgxpool.Pool, opts ...Option) *OAuthStore {
	return &OAuthStore{db: db, q: buildOAuthQueries(resolve(opts...))}
}

func jsonList(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (s *OAuthStore) CreateClient(ctx context.Context, c *oauth.Client) error {
	ru, err := jsonList(c.RedirectURIs)
	if err != nil {
		return err
	}
	gt, err := jsonList(c.GrantTypes)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, s.q.createClient, c.ClientID, c.SecretHash, c.Name, ru, c.TokenEndpointAuthMethod, gt, c.CreatedAt, c.LastUsedAt)
	return err
}

func (s *OAuthStore) GetClient(ctx context.Context, clientID string) (*oauth.Client, error) {
	var c oauth.Client
	var ru, gt string
	err := s.db.QueryRow(ctx, s.q.getClient, clientID).Scan(&c.ClientID, &c.SecretHash, &c.Name, &ru,
		&c.TokenEndpointAuthMethod, &gt, &c.CreatedAt, &c.LastUsedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err := json.Unmarshal([]byte(ru), &c.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(gt), &c.GrantTypes); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *OAuthStore) TouchClient(ctx context.Context, clientID string, at time.Time) error {
	_, err := s.db.Exec(ctx, s.q.touchClient, clientID, at)
	return err
}

func (s *OAuthStore) DeleteStaleClients(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.deleteStaleClients, before)
	return tag.RowsAffected(), err
}

func (s *OAuthStore) CreateCode(ctx context.Context, c *oauth.Code) error {
	_, err := s.db.Exec(ctx, s.q.createCode, c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scopes,
		c.Resource, c.CodeChallenge, c.ExpiresAt, c.UsedAt, c.GrantID)
	return err
}

func (s *OAuthStore) GetCode(ctx context.Context, codeHash string) (*oauth.Code, error) {
	var c oauth.Code
	err := s.db.QueryRow(ctx, s.q.getCode, codeHash).Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI,
		&c.Scopes, &c.Resource, &c.CodeChallenge, &c.ExpiresAt, &c.UsedAt, &c.GrantID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &c, nil
}

func (s *OAuthStore) MarkCodeUsed(ctx context.Context, codeHash, grantID string, at time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, s.q.markCodeUsed, codeHash, grantID, at)
	return tag.RowsAffected() == 1, err
}

func (s *OAuthStore) DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.deleteExpiredCodes, before)
	return tag.RowsAffected(), err
}

func (s *OAuthStore) GetConsent(ctx context.Context, userID, clientID string) (*oauth.Consent, error) {
	var c oauth.Consent
	err := s.db.QueryRow(ctx, s.q.getConsent, userID, clientID).Scan(&c.UserID, &c.ClientID, &c.Scopes, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &c, nil
}

func (s *OAuthStore) SaveConsent(ctx context.Context, c *oauth.Consent) error {
	_, err := s.db.Exec(ctx, s.q.saveConsent, c.UserID, c.ClientID, c.Scopes, c.CreatedAt, c.UpdatedAt)
	return err
}

func (s *OAuthStore) DeleteConsent(ctx context.Context, userID, clientID string) error {
	_, err := s.db.Exec(ctx, s.q.deleteConsent, userID, clientID)
	return err
}

func (s *OAuthStore) CreateGrant(ctx context.Context, g *oauth.Grant) error {
	_, err := s.db.Exec(ctx, s.q.createGrant, g.ID, g.UserID, g.ClientID, g.Scopes, g.Resource, g.TokenHash,
		g.PrevTokenHash, g.SecurityStamp, g.ExpiresAt, g.CreatedAt, g.LastUsedAt)
	return err
}

func scanGrant(row pgx.Row) (*oauth.Grant, error) {
	var g oauth.Grant
	if err := row.Scan(&g.ID, &g.UserID, &g.ClientID, &g.Scopes, &g.Resource, &g.TokenHash, &g.PrevTokenHash,
		&g.SecurityStamp, &g.ExpiresAt, &g.CreatedAt, &g.LastUsedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &g, nil
}

func (s *OAuthStore) GetGrant(ctx context.Context, id string) (*oauth.Grant, error) {
	return scanGrant(s.db.QueryRow(ctx, s.q.getGrant, id))
}

func (s *OAuthStore) RotateGrant(ctx context.Context, id, oldHash, newHash string, expiresAt, usedAt time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, s.q.rotateGrant, id, oldHash, newHash, expiresAt, usedAt)
	return tag.RowsAffected() == 1, err
}

func (s *OAuthStore) DeleteGrant(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, s.q.deleteGrant, id)
	return err
}

func (s *OAuthStore) DeleteUserClientGrants(ctx context.Context, userID, clientID string) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.deleteUserClientGrants, userID, clientID)
	return tag.RowsAffected(), err
}

func (s *OAuthStore) ListUserGrants(ctx context.Context, userID string) ([]oauth.Grant, error) {
	rows, err := s.db.Query(ctx, s.q.listUserGrants, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []oauth.Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *OAuthStore) DeleteExpiredGrants(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, s.q.deleteExpiredGrants, before)
	return tag.RowsAffected(), err
}
