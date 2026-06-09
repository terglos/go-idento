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

// PrincipalFrom extracts the principal placed by [Middleware]; ok is false for
// anonymous requests.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey).(*Principal)
	return p, ok
}

// Middleware authenticates via Bearer token (and falls back to a session
// cookie) and attaches the Principal. It does NOT reject anonymous requests —
// compose [RequireAuth] for that (authentication vs authorization).
func Middleware(tokens *identity.TokenService, cookies *CookieAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := authenticate(r, tokens, cookies); p != nil {
				r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func authenticate(r *http.Request, tokens *identity.TokenService, cookies *CookieAuth) *Principal {
	token := bearerToken(r)
	if token == "" && cookies != nil {
		token = cookies.read(r)
	}
	if token == "" {
		return nil
	}
	u, claims, err := tokens.ValidateAccessToken(r.Context(), token)
	if err != nil {
		return nil
	}
	return &Principal{User: u, Claims: claims, Roles: rolesFromClaims(claims)}
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
