// Package auth provides HTTP middleware that turns a validated identity into a
// request-scoped principal, plus cookie-session helpers — the transport layer
// on top of the identity core.
package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terglos/go-idento/identity"
)

type ctxKey int

const principalKey ctxKey = 0

// Principal is the authenticated user attached to the request context.
type Principal struct {
	User   *identity.User
	Claims jwt.MapClaims
	Roles  []string
	// Scopes are set when the request authenticated via an API key that carries
	// scopes; nil for JWT/cookie auth. Use [Principal.HasScope] for checks.
	Scopes []string
	// ViaAPIKey is true when the request authenticated with an API key.
	ViaAPIKey bool
}

// HasRole reports role membership for [RequireRole].
func (p *Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// HasScope reports whether the principal's API key carries the given scope
// (always false for non-API-key auth or a key without scopes).
func (p *Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// PrincipalFrom extracts the principal placed by [Middleware]; ok is false for
// anonymous requests.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok
}

// Option configures [Middleware].
type Option func(*middlewareConfig)

type middlewareConfig struct {
	keys *identity.APIKeyManager
}

// WithAPIKeys enables opaque API-key authentication: a Bearer value that isn't a
// valid JWT is tried as an API key, producing the same Principal (user + roles +
// claims) so RequireRole/RequirePolicy work identically. Cookie tokens are never
// treated as API keys.
func WithAPIKeys(keys *identity.APIKeyManager) Option {
	return func(c *middlewareConfig) { c.keys = keys }
}

// Middleware authenticates via Bearer token (and falls back to a session
// cookie) and attaches the Principal. It does NOT reject anonymous requests —
// compose [RequireAuth] for that (authentication vs authorization). Pass
// [WithAPIKeys] to also accept opaque API keys on the Bearer header.
func Middleware(tokens *identity.TokenService, cookies *CookieAuth, opts ...Option) func(http.Handler) http.Handler {
	var cfg middlewareConfig
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := authenticate(r, tokens, cookies, &cfg); p != nil {
				r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func authenticate(r *http.Request, tokens *identity.TokenService, cookies *CookieAuth, cfg *middlewareConfig) *Principal {
	token := bearerToken(r)
	fromCookie := false
	if token == "" && cookies != nil {
		token, fromCookie = cookies.read(r), true
	}
	if token == "" {
		return nil
	}
	// Prefer JWT validation.
	if tokens != nil {
		if u, claims, err := tokens.ValidateAccessToken(r.Context(), token); err == nil {
			return &Principal{User: u, Claims: claims, Roles: rolesFromClaims(claims)}
		}
	}
	// Fall back to an API key for a Bearer value that isn't a valid JWT. Cookie
	// values are session tokens and are never treated as API keys.
	if cfg.keys != nil && !fromCookie {
		if p := authenticateAPIKey(r.Context(), token, cfg.keys); p != nil {
			return p
		}
	}
	return nil
}

// authenticateAPIKey resolves an API key to a Principal carrying the owner's
// roles/claims (so authorization behaves exactly like a JWT) plus the key's
// scopes. A store/infra failure (not an invalid key) yields nil → anonymous.
func authenticateAPIKey(ctx context.Context, token string, keys *identity.APIKeyManager) *Principal {
	u, key, err := keys.VerifyAPIKey(ctx, token)
	if err != nil || u == nil {
		return nil
	}
	roles, _ := keys.Users.GetRoles(ctx, u)
	claims := jwt.MapClaims{}
	if cs, err := keys.Users.GetClaims(ctx, u); err == nil {
		for _, c := range cs {
			if _, taken := claims[c.Type]; !taken {
				claims[c.Type] = c.Value
			}
		}
	}
	if len(roles) > 0 {
		claims[identity.ClaimRole] = roles
	}
	return &Principal{User: u, Claims: claims, Roles: roles, Scopes: []string(key.Scopes), ViaAPIKey: true}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	return ""
}

func rolesFromClaims(claims jwt.MapClaims) []string {
	raw, ok := claims[identity.ClaimRole]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// RequireAuth rejects anonymous requests with 401.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := PrincipalFrom(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole rejects requests whose principal lacks the role with 403.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !p.HasRole(role) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
