// Package oauth is an embedded OAuth 2.1 authorization server for go-idento
// apps — the piece that lets third-party clients (MCP clients such as Claude
// and ChatGPT, CLIs, integrations) obtain per-user, audience-bound access tokens
// for your API.
//
// It implements the authorization code grant with mandatory PKCE (S256), the
// refresh token grant with rotation and reuse detection, Authorization Server
// Metadata (RFC 8414), Protected Resource Metadata and the 401 challenge
// (RFC 9728), Resource Indicators (RFC 8707), Dynamic Client Registration
// (RFC 7591), Client ID Metadata Documents (CIMD), loopback redirects
// (RFC 8252) and token revocation (RFC 7009) — the profile required by the MCP
// authorization specification.
//
// The app keeps ownership of the user experience: it tells the server who is
// signed in (Options.CurrentUser), where to send anonymous users
// (Options.LoginURL) and how to render the consent page
// (Options.RenderConsent). Access tokens are JWTs signed with the app's
// existing TokenService signer, so the existing JWKS endpoint publishes the
// verification keys.
package oauth

import (
	"context"
	"time"
)

// Token endpoint client authentication methods.
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	// AuthMethodPrivateKeyJWT is RFC 7523 §2.2 client authentication with a JWT
	// signed by the client's private key; the server verifies it against the
	// client's published keys (jwks_uri / jwks). Supported for clients that use
	// a Client ID Metadata Document.
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type of an RFC 7523
// client assertion.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Grant types.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// ScopeOfflineAccess is the conventional scope a client adds to ask for a
// refresh token.
const ScopeOfflineAccess = "offline_access"

// StringList is a JSON-serialized list of strings.
type StringList []string

// Client is a registered OAuth client (DCR or pre-registered). Clients that use
// Client ID Metadata Documents (an HTTPS URL as client_id) are resolved on
// demand and are never stored.
type Client struct {
	ClientID   string `gorm:"primaryKey;type:varchar(512)" json:"client_id"`
	SecretHash string `gorm:"type:varchar(128)" json:"-"` // empty for public clients
	Name       string `gorm:"type:varchar(256)" json:"client_name"`
	// RedirectURIs are matched exactly, except loopback http URIs, whose port is
	// ignored (RFC 8252 §7.3).
	RedirectURIs            StringList `gorm:"column:redirect_uris;serializer:json;type:text" json:"redirect_uris"`
	TokenEndpointAuthMethod string     `gorm:"column:token_endpoint_auth_method;type:varchar(32)" json:"token_endpoint_auth_method"`
	GrantTypes              StringList `gorm:"column:grant_types;serializer:json;type:text" json:"grant_types"`
	CreatedAt               time.Time  `json:"-"`
	LastUsedAt              *time.Time `json:"-"`
}

func (Client) TableName() string { return "identity_oauth_clients" }

// Code is an issued authorization code. Only its hash is stored; it is
// single-use (UsedAt) and short-lived (ExpiresAt). GrantID records the grant
// minted from it, so a replay can revoke everything issued from the code.
type Code struct {
	CodeHash      string    `gorm:"primaryKey;type:varchar(128)"`
	ClientID      string    `gorm:"type:varchar(512)"`
	UserID        string    `gorm:"type:varchar(36);index"`
	RedirectURI   string    `gorm:"column:redirect_uri;type:text"`
	Scopes        string    `gorm:"type:text"` // space-separated
	Resource      string    `gorm:"type:text"`
	CodeChallenge string    `gorm:"type:varchar(128)"`
	ExpiresAt     time.Time `gorm:"index"`
	UsedAt        *time.Time
	GrantID       string `gorm:"type:varchar(36)"`
}

func (Code) TableName() string { return "identity_oauth_codes" }

// Consent records the scopes a user approved for a client, so a later request
// for the same or fewer scopes can skip the consent page.
type Consent struct {
	UserID    string `gorm:"primaryKey;type:varchar(36)"`
	ClientID  string `gorm:"primaryKey;type:varchar(512)"`
	Scopes    string `gorm:"type:text"` // space-separated
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (Consent) TableName() string { return "identity_oauth_consents" }

// Grant is one authorization of a client by a user ("connected app"): the
// refresh-token family. The refresh token handed out is "<ID>.<secret>"; only
// the secret's hash is stored, together with the previous hash so a replayed
// (rotated-away) token is recognized and revokes the whole grant. Access tokens
// carry the grant ID and are rejected once the grant is gone.
type Grant struct {
	ID            string `gorm:"primaryKey;type:varchar(36)"`
	UserID        string `gorm:"type:varchar(36);index"`
	ClientID      string `gorm:"type:varchar(512);index"`
	Scopes        string `gorm:"type:text"` // space-separated
	Resource      string `gorm:"type:text"`
	TokenHash     string `gorm:"type:varchar(128)"` // current refresh secret hash ("" = no refresh token)
	PrevTokenHash string `gorm:"type:varchar(128)"` // last rotated-away hash (reuse detection)
	// SecurityStamp is the user's stamp when the grant was issued; a later stamp
	// change (password change, UpdateSecurityStamp) invalidates the grant.
	SecurityStamp string    `gorm:"type:varchar(64)"`
	ExpiresAt     time.Time `gorm:"index"`
	CreatedAt     time.Time
	LastUsedAt    *time.Time
}

func (Grant) TableName() string { return "identity_oauth_grants" }

// ClientAssertion records the id (jti) of a client assertion that was
// accepted, until it expires, so the same assertion can't be replayed — on any
// instance sharing the store.
type ClientAssertion struct {
	ClientID  string    `gorm:"primaryKey;type:varchar(512)"`
	JTI       string    `gorm:"column:jti;primaryKey;type:varchar(256)"`
	ExpiresAt time.Time `gorm:"index"`
}

func (ClientAssertion) TableName() string { return "identity_oauth_assertions" }

// Store persists the authorization server's state. The bundled stores
// (memstore, gormstore, pgxstore, pgxsqlc) implement it; all lookups return
// identity.ErrNotFound for a missing row. Run oauthtest.RunStoreConformance
// against a custom implementation.
type Store interface {
	// Clients (DCR / pre-registered).
	CreateClient(ctx context.Context, c *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)
	TouchClient(ctx context.Context, clientID string, at time.Time) error
	// DeleteStaleClients removes stored clients created before the cutoff that
	// were not used since and hold no grants (DCR garbage collection).
	DeleteStaleClients(ctx context.Context, before time.Time) (int64, error)

	// Authorization codes.
	CreateCode(ctx context.Context, c *Code) error
	GetCode(ctx context.Context, codeHash string) (*Code, error)
	// MarkCodeUsed atomically marks an unused code as used and records the grant
	// minted from it; it returns false when the code was already used.
	MarkCodeUsed(ctx context.Context, codeHash, grantID string, at time.Time) (bool, error)
	DeleteExpiredCodes(ctx context.Context, before time.Time) (int64, error)

	// Consents (upserted by user+client).
	GetConsent(ctx context.Context, userID, clientID string) (*Consent, error)
	SaveConsent(ctx context.Context, c *Consent) error
	DeleteConsent(ctx context.Context, userID, clientID string) error

	// Grants (refresh-token families).
	CreateGrant(ctx context.Context, g *Grant) error
	GetGrant(ctx context.Context, id string) (*Grant, error)
	// RotateGrant swaps the refresh hash only if it still equals oldHash
	// (compare-and-swap), moving oldHash to PrevTokenHash; false = lost a race.
	RotateGrant(ctx context.Context, id, oldHash, newHash string, expiresAt, usedAt time.Time) (bool, error)
	DeleteGrant(ctx context.Context, id string) error
	DeleteUserClientGrants(ctx context.Context, userID, clientID string) (int64, error)
	ListUserGrants(ctx context.Context, userID string) ([]Grant, error)
	DeleteExpiredGrants(ctx context.Context, before time.Time) (int64, error)

	// Client assertions (private_key_jwt replay protection).
	// UseClientAssertion records (clientID, jti) until expiresAt and reports
	// false when that pair was already recorded (a replay). It must be atomic.
	UseClientAssertion(ctx context.Context, clientID, jti string, expiresAt time.Time) (bool, error)
	DeleteExpiredClientAssertions(ctx context.Context, before time.Time) (int64, error)
}
