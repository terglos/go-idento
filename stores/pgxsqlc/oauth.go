package pgxsqlc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/oauth"
	gen "github.com/terglos/go-idento/stores/pgxsqlc/internal/sqlcgen"
)

// OAuthStore adapts the sqlc queries to oauth.Store (embedded OAuth 2.1
// authorization server). Migrate creates its tables.
type OAuthStore struct{ q *gen.Queries }

var _ oauth.Store = (*OAuthStore)(nil)

// NewOAuthStore builds the authorization server's store over the sqlc queries.
func NewOAuthStore(db *pgxpool.Pool) *OAuthStore { return &OAuthStore{q: gen.New(db)} }

func listJSON(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func timePtr(t time.Time) *time.Time { return &t }

func (s *OAuthStore) CreateClient(ctx context.Context, c *oauth.Client) error {
	return s.q.CreateOAuthClient(ctx, gen.CreateOAuthClientParams{
		ClientID: c.ClientID, SecretHash: c.SecretHash, Name: c.Name, RedirectUris: listJSON(c.RedirectURIs),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, GrantTypes: listJSON(c.GrantTypes),
		CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
	})
}

func (s *OAuthStore) GetClient(ctx context.Context, clientID string) (*oauth.Client, error) {
	r, err := s.q.GetOAuthClient(ctx, clientID)
	if err != nil {
		return nil, mapNotFound(err)
	}
	c := &oauth.Client{ClientID: r.ClientID, SecretHash: r.SecretHash, Name: r.Name,
		TokenEndpointAuthMethod: r.TokenEndpointAuthMethod, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt}
	if err := json.Unmarshal([]byte(r.RedirectUris), &c.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(r.GrantTypes), &c.GrantTypes); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *OAuthStore) TouchClient(ctx context.Context, clientID string, at time.Time) error {
	return s.q.TouchOAuthClient(ctx, gen.TouchOAuthClientParams{ClientID: clientID, LastUsedAt: timePtr(at)})
}

func (s *OAuthStore) DeleteStaleClients(ctx context.Context, before time.Time) (int64, error) {
	return s.q.DeleteStaleOAuthClients(ctx, before)
}

func (s *OAuthStore) CreateCode(ctx context.Context, c *oauth.Code) error {
	return s.q.CreateOAuthCode(ctx, gen.CreateOAuthCodeParams{
		CodeHash: c.CodeHash, ClientID: c.ClientID, UserID: c.UserID, RedirectUri: c.RedirectURI,
		Scopes: c.Scopes, Resource: c.Resource, CodeChallenge: c.CodeChallenge, ExpiresAt: c.ExpiresAt,
		UsedAt: c.UsedAt, GrantID: c.GrantID,
	})
}

func (s *OAuthStore) GetCode(ctx context.Context, codeHash string) (*oauth.Code, error) {
	r, err := s.q.GetOAuthCode(ctx, codeHash)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &oauth.Code{CodeHash: r.CodeHash, ClientID: r.ClientID, UserID: r.UserID, RedirectURI: r.RedirectUri,
		Scopes: r.Scopes, Resource: r.Resource, CodeChallenge: r.CodeChallenge, ExpiresAt: r.ExpiresAt,
		UsedAt: r.UsedAt, GrantID: r.GrantID}, nil
}

func (s *OAuthStore) MarkCodeUsed(ctx context.Context, codeHash, grantID string, at time.Time) (bool, error) {
	n, err := s.q.MarkOAuthCodeUsed(ctx, gen.MarkOAuthCodeUsedParams{UsedAt: timePtr(at), GrantID: grantID, CodeHash: codeHash})
	return n == 1, err
}

func (s *OAuthStore) DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error) {
	return s.q.DeleteExpiredOAuthCodes(ctx, before)
}

func (s *OAuthStore) GetConsent(ctx context.Context, userID, clientID string) (*oauth.Consent, error) {
	r, err := s.q.GetOAuthConsent(ctx, gen.GetOAuthConsentParams{UserID: userID, ClientID: clientID})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &oauth.Consent{UserID: r.UserID, ClientID: r.ClientID, Scopes: r.Scopes, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}, nil
}

func (s *OAuthStore) SaveConsent(ctx context.Context, c *oauth.Consent) error {
	return s.q.SaveOAuthConsent(ctx, gen.SaveOAuthConsentParams{UserID: c.UserID, ClientID: c.ClientID,
		Scopes: c.Scopes, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt})
}

func (s *OAuthStore) DeleteConsent(ctx context.Context, userID, clientID string) error {
	return s.q.DeleteOAuthConsent(ctx, gen.DeleteOAuthConsentParams{UserID: userID, ClientID: clientID})
}

func (s *OAuthStore) CreateGrant(ctx context.Context, g *oauth.Grant) error {
	return s.q.CreateOAuthGrant(ctx, gen.CreateOAuthGrantParams{
		ID: g.ID, UserID: g.UserID, ClientID: g.ClientID, Scopes: g.Scopes, Resource: g.Resource,
		TokenHash: g.TokenHash, PrevTokenHash: g.PrevTokenHash, SecurityStamp: g.SecurityStamp,
		ExpiresAt: g.ExpiresAt, CreatedAt: g.CreatedAt, LastUsedAt: g.LastUsedAt,
	})
}

func toGrant(r gen.IdentityOauthGrant) oauth.Grant {
	return oauth.Grant{ID: r.ID, UserID: r.UserID, ClientID: r.ClientID, Scopes: r.Scopes, Resource: r.Resource,
		TokenHash: r.TokenHash, PrevTokenHash: r.PrevTokenHash, SecurityStamp: r.SecurityStamp,
		ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt}
}

func (s *OAuthStore) GetGrant(ctx context.Context, id string) (*oauth.Grant, error) {
	r, err := s.q.GetOAuthGrant(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	g := toGrant(r)
	return &g, nil
}

func (s *OAuthStore) RotateGrant(ctx context.Context, id, oldHash, newHash string, expiresAt, usedAt time.Time) (bool, error) {
	n, err := s.q.RotateOAuthGrant(ctx, gen.RotateOAuthGrantParams{NewHash: newHash, ExpiresAt: expiresAt,
		LastUsedAt: timePtr(usedAt), ID: id, OldHash: oldHash})
	return n == 1, err
}

func (s *OAuthStore) DeleteGrant(ctx context.Context, id string) error {
	return s.q.DeleteOAuthGrant(ctx, id)
}

func (s *OAuthStore) DeleteUserClientGrants(ctx context.Context, userID, clientID string) (int64, error) {
	return s.q.DeleteUserClientOAuthGrants(ctx, gen.DeleteUserClientOAuthGrantsParams{UserID: userID, ClientID: clientID})
}

func (s *OAuthStore) ListUserGrants(ctx context.Context, userID string) ([]oauth.Grant, error) {
	rows, err := s.q.ListUserOAuthGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]oauth.Grant, len(rows))
	for i, r := range rows {
		out[i] = toGrant(r)
	}
	return out, nil
}

func (s *OAuthStore) DeleteExpiredGrants(ctx context.Context, before time.Time) (int64, error) {
	return s.q.DeleteExpiredOAuthGrants(ctx, before)
}
