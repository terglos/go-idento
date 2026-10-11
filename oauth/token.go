package oauth

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terglos/go-idento/identity"
)

// Claims carried by OAuth access tokens, beyond iss/sub/aud/exp/iat/nbf/jti.
const (
	ClaimClientID = "client_id"
	ClaimScope    = "scope"
	ClaimGrantID  = "gid"
)

// TokenResponse is the token endpoint's success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenHandler serves the token endpoint (authorization_code and refresh_token
// grants). Requests must be application/x-www-form-urlencoded (RFC 6749 §4.1.3).
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		noStore(w)
		if r.Method != http.MethodPost {
			writeError(w, oerr(http.StatusMethodNotAllowed, "invalid_request", "use POST"))
			return
		}
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
			writeError(w, errInvalidRequest("content type must be application/x-www-form-urlencoded"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, errInvalidRequest("malformed form body"))
			return
		}
		for k, vs := range r.PostForm {
			if len(vs) > 1 {
				writeError(w, errInvalidRequest("parameter "+k+" is duplicated"))
				return
			}
		}
		client, basic, e := s.authenticateClient(r.Context(), r)
		if e != nil {
			if e.Code == "invalid_client" && basic {
				w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			}
			writeError(w, e)
			return
		}
		var resp *TokenResponse
		switch gt := r.PostForm.Get("grant_type"); gt {
		case GrantTypeAuthorizationCode:
			resp, e = s.exchangeCode(r.Context(), client, r.PostForm)
		case GrantTypeRefreshToken:
			resp, e = s.refreshGrant(r.Context(), client, r.PostForm)
		case "":
			e = errInvalidRequest("grant_type is required")
		default:
			e = errUnsupportedGrant("unsupported grant_type: " + gt)
		}
		if e != nil {
			writeError(w, e)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
}

// authenticateClient implements none / client_secret_basic / client_secret_post.
// basic reports whether HTTP Basic credentials were presented.
func (s *Server) authenticateClient(ctx context.Context, r *http.Request) (*resolvedClient, bool, *Error) {
	var id, secret string
	basicID, basicSecret, basic := r.BasicAuth()
	formSecret := r.PostForm.Get("client_secret")
	switch {
	case basic:
		if formSecret != "" {
			return nil, true, errInvalidRequest("use only one client authentication method")
		}
		var err1, err2 error
		id, err1 = url.QueryUnescape(basicID) // RFC 6749 §2.3.1
		secret, err2 = url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, true, errInvalidClient("malformed client credentials")
		}
		if fid := r.PostForm.Get("client_id"); fid != "" && fid != id {
			return nil, true, errInvalidClient("client_id mismatch")
		}
	default:
		id, secret = r.PostForm.Get("client_id"), formSecret
	}
	if id == "" {
		return nil, basic, errInvalidClient("client authentication required")
	}
	client, err := s.resolveClient(ctx, id)
	if err != nil {
		return nil, basic, errInvalidClient(err.Error())
	}
	if client.public() {
		if secret != "" {
			return nil, basic, errInvalidClient("public client must not present a secret")
		}
		return client, basic, nil
	}
	if secret == "" || !constEq(hashSecret(secret), client.SecretHash) {
		return nil, basic, errInvalidClient("invalid client credentials")
	}
	return client, basic, nil
}

func (s *Server) clientAllows(c *resolvedClient, grantType string) bool {
	if len(c.GrantTypes) == 0 {
		return grantType == GrantTypeAuthorizationCode || grantType == GrantTypeRefreshToken
	}
	return hasScope(c.GrantTypes, grantType)
}

func (s *Server) exchangeCode(ctx context.Context, client *resolvedClient, f url.Values) (*TokenResponse, *Error) {
	if !s.clientAllows(client, GrantTypeAuthorizationCode) {
		return nil, oerr(http.StatusBadRequest, "unauthorized_client", "client may not use this grant")
	}
	raw := f.Get("code")
	if raw == "" {
		return nil, errInvalidRequest("code is required")
	}
	hash := hashSecret(raw)
	code, err := s.store.GetCode(ctx, hash)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, errInvalidGrant("invalid authorization code")
	}
	if err != nil {
		return nil, errServer("code lookup failed")
	}
	now := s.opts.Now()
	if code.UsedAt != nil {
		// Replay: revoke everything issued from this code.
		if code.GrantID != "" {
			_ = s.store.DeleteGrant(ctx, code.GrantID)
		}
		return nil, errInvalidGrant("authorization code already used")
	}
	if now.After(code.ExpiresAt) {
		return nil, errInvalidGrant("authorization code expired")
	}
	if code.ClientID != client.ID {
		return nil, errInvalidGrant("authorization code was issued to another client")
	}
	if ru := f.Get("redirect_uri"); ru != "" && ru != code.RedirectURI {
		return nil, errInvalidGrant("redirect_uri does not match the authorization request")
	}
	if !verifyS256(f.Get("code_verifier"), code.CodeChallenge) {
		return nil, errInvalidGrant("PKCE verification failed")
	}
	if res := f.Get("resource"); res != "" {
		if c, ok := canonicalResource(res); !ok || c != code.Resource {
			return nil, errInvalidTarget("resource does not match the authorization request")
		}
	}
	u, err := s.users.FindByID(ctx, code.UserID)
	if err != nil || u == nil || s.users.IsLockedOut(u) {
		return nil, errInvalidGrant("the authorizing user is not available")
	}

	grantID := newID()
	won, err := s.store.MarkCodeUsed(ctx, hash, grantID, now)
	if err != nil {
		return nil, errServer("could not redeem code")
	}
	if !won { // lost a concurrent redemption: treat as replay
		if c, err := s.store.GetCode(ctx, hash); err == nil && c.GrantID != "" {
			_ = s.store.DeleteGrant(ctx, c.GrantID)
		}
		return nil, errInvalidGrant("authorization code already used")
	}

	scopes := parseScopes(code.Scopes)
	g := &Grant{
		ID: grantID, UserID: u.ID, ClientID: client.ID, Scopes: code.Scopes, Resource: code.Resource,
		SecurityStamp: u.SecurityStamp, ExpiresAt: now.Add(s.opts.RefreshTokenTTL), CreatedAt: now,
	}
	var refresh string
	if s.issuesRefresh(client, scopes) {
		secret := randomSecret(32)
		g.TokenHash = hashSecret(secret)
		refresh = g.ID + "." + secret
	}
	if err := s.store.CreateGrant(ctx, g); err != nil {
		return nil, errServer("could not create grant")
	}
	if !client.CIMD {
		_ = s.store.TouchClient(ctx, client.ID, now)
	}
	return s.tokenResponse(ctx, u, g, scopes, refresh)
}

func (s *Server) issuesRefresh(c *resolvedClient, scopes []string) bool {
	if !s.clientAllows(c, GrantTypeRefreshToken) {
		return false
	}
	if s.opts.RequireOfflineAccess {
		return hasScope(scopes, ScopeOfflineAccess)
	}
	return true
}

func (s *Server) refreshGrant(ctx context.Context, client *resolvedClient, f url.Values) (*TokenResponse, *Error) {
	if !s.clientAllows(client, GrantTypeRefreshToken) {
		return nil, oerr(http.StatusBadRequest, "unauthorized_client", "client may not use this grant")
	}
	gid, secret, ok := strings.Cut(f.Get("refresh_token"), ".")
	if !ok || gid == "" || secret == "" || len(gid) > 64 {
		return nil, errInvalidGrant("invalid refresh token")
	}
	g, err := s.store.GetGrant(ctx, gid)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, errInvalidGrant("invalid refresh token")
	}
	if err != nil {
		return nil, errServer("grant lookup failed")
	}
	if g.ClientID != client.ID {
		return nil, errInvalidGrant("refresh token was issued to another client")
	}
	now := s.opts.Now()
	presented := hashSecret(secret)
	if g.TokenHash == "" || !constEq(presented, g.TokenHash) {
		if g.PrevTokenHash != "" && constEq(presented, g.PrevTokenHash) {
			// A rotated-away token came back: the family is compromised, unless it
			// is a benign retry inside the configured grace window.
			inGrace := s.opts.RefreshReuseGrace > 0 && g.LastUsedAt != nil &&
				now.Sub(*g.LastUsedAt) <= s.opts.RefreshReuseGrace
			if !inGrace {
				_ = s.store.DeleteGrant(ctx, g.ID)
			}
			return nil, errInvalidGrant("refresh token already used")
		}
		return nil, errInvalidGrant("invalid refresh token")
	}
	if now.After(g.ExpiresAt) {
		_ = s.store.DeleteGrant(ctx, g.ID)
		return nil, errInvalidGrant("refresh token expired")
	}
	if res := f.Get("resource"); res != "" {
		if c, ok := canonicalResource(res); !ok || c != g.Resource {
			return nil, errInvalidTarget("resource does not match the grant")
		}
	}
	u, err := s.users.FindByID(ctx, g.UserID)
	if err != nil || u == nil || s.users.IsLockedOut(u) {
		return nil, errInvalidGrant("the authorizing user is not available")
	}
	if !constEq(u.SecurityStamp, g.SecurityStamp) {
		_ = s.store.DeleteGrant(ctx, g.ID) // password change / sign-out-everywhere
		return nil, errInvalidGrant("grant was revoked")
	}
	scopes := parseScopes(g.Scopes)
	if req := parseScopes(f.Get("scope")); len(req) > 0 {
		if !containsAll(scopes, req) {
			return nil, errInvalidScope("requested scope exceeds the original grant")
		}
		scopes = req
	}
	newSecret := randomSecret(32)
	newHash := hashSecret(newSecret)
	ok, err = s.store.RotateGrant(ctx, g.ID, g.TokenHash, newHash, now.Add(s.opts.RefreshTokenTTL), now)
	if err != nil {
		return nil, errServer("could not rotate refresh token")
	}
	if !ok {
		return nil, errInvalidGrant("refresh token already used")
	}
	return s.tokenResponse(ctx, u, g, scopes, g.ID+"."+newSecret)
}

func (s *Server) tokenResponse(ctx context.Context, u *identity.User, g *Grant, scopes []string, refresh string) (*TokenResponse, *Error) {
	at, exp, err := s.signAccessToken(ctx, u, g, scopes)
	if err != nil {
		return nil, errServer("could not sign access token")
	}
	return &TokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int64(exp.Sub(s.opts.Now()).Seconds()),
		RefreshToken: refresh,
		Scope:        joinScopes(scopes),
	}, nil
}

// signAccessToken mints an RFC 9068 JWT access token (typ at+jwt) bound to the
// grant's resource (aud), client and scopes, plus the user's roles and security
// stamp so the usual revocation keeps working.
func (s *Server) signAccessToken(ctx context.Context, u *identity.User, g *Grant, scopes []string) (string, time.Time, error) {
	now := s.opts.Now()
	exp := now.Add(s.opts.AccessTokenTTL)
	claims := jwt.MapClaims{
		"iss":                       s.issuer,
		"sub":                       u.ID,
		"aud":                       g.Resource,
		"iat":                       now.Unix(),
		"nbf":                       now.Unix(),
		"exp":                       exp.Unix(),
		"jti":                       newID(),
		ClaimClientID:               g.ClientID,
		ClaimScope:                  joinScopes(scopes),
		ClaimGrantID:                g.ID,
		identity.ClaimSecurityStamp: u.SecurityStamp,
	}
	if roles, err := s.users.GetRoles(ctx, u); err == nil && len(roles) > 0 {
		claims[identity.ClaimRole] = roles
	}
	tok := jwt.NewWithClaims(s.signer.Method(), claims)
	tok.Header["typ"] = identity.TokenTypeAccessJWT
	kid, key := s.signer.SignKey()
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	return signed, exp, err
}

// ValidateResourceToken validates an OAuth access token presented to resource:
// signature and algorithm, issuer, audience == resource, expiry, typ at+jwt,
// the user and its security stamp, and that the grant still exists (so code
// replay, refresh reuse, revocation and disconnecting the app take effect
// immediately). It returns identity.ErrInvalidToken for any invalid token and a
// wrapped error for store failures. App session tokens are never accepted.
func (s *Server) ValidateResourceToken(ctx context.Context, token, resource string) (*identity.User, jwt.MapClaims, error) {
	res, ok := canonicalResource(resource)
	if !ok {
		return nil, nil, identity.ErrInvalidToken
	}
	parsed, err := jwt.Parse(token, s.signer.Keyfunc,
		jwt.WithValidMethods([]string{s.signer.Method().Alg()}),
		jwt.WithIssuer(s.issuer), jwt.WithAudience(res), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		return nil, nil, identity.ErrInvalidToken
	}
	if typ, _ := parsed.Header["typ"].(string); !strings.EqualFold(typ, identity.TokenTypeAccessJWT) {
		return nil, nil, identity.ErrInvalidToken
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, identity.ErrInvalidToken
	}
	sub, _ := claims["sub"].(string)
	gid, _ := claims[ClaimGrantID].(string)
	if sub == "" || gid == "" {
		return nil, nil, identity.ErrInvalidToken
	}
	u, err := s.users.FindByID(ctx, sub)
	if errors.Is(err, identity.ErrNotFound) || (err == nil && u == nil) {
		return nil, nil, identity.ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	if stamp, _ := claims[identity.ClaimSecurityStamp].(string); !constEq(stamp, u.SecurityStamp) {
		return nil, nil, identity.ErrInvalidToken
	}
	if s.users.IsLockedOut(u) {
		return nil, nil, identity.ErrInvalidToken
	}
	g, err := s.store.GetGrant(ctx, gid)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, nil, identity.ErrInvalidToken
	}
	if err != nil {
		return nil, nil, err
	}
	if g.UserID != u.ID {
		return nil, nil, identity.ErrInvalidToken
	}
	return u, claims, nil
}

// RevokeHandler serves the revocation endpoint (RFC 7009). Revoking a refresh
// token or an access token removes the whole grant. It always answers 200 for
// unknown tokens, as the RFC requires.
func (s *Server) RevokeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		noStore(w)
		if r.Method != http.MethodPost {
			writeError(w, oerr(http.StatusMethodNotAllowed, "invalid_request", "use POST"))
			return
		}
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
			writeError(w, errInvalidRequest("content type must be application/x-www-form-urlencoded"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			writeError(w, errInvalidRequest("malformed form body"))
			return
		}
		client, basic, e := s.authenticateClient(r.Context(), r)
		if e != nil {
			if e.Code == "invalid_client" && basic {
				w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			}
			writeError(w, e)
			return
		}
		token := r.PostForm.Get("token")
		if token == "" {
			writeError(w, errInvalidRequest("token is required"))
			return
		}
		if gid := s.grantIDOf(r.Context(), token); gid != "" {
			if g, err := s.store.GetGrant(r.Context(), gid); err == nil && g.ClientID == client.ID {
				_ = s.store.DeleteGrant(r.Context(), gid)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

// grantIDOf extracts the grant a refresh token ("gid.secret", current or
// previous secret) or an access token belongs to; "" when unrecognized.
func (s *Server) grantIDOf(ctx context.Context, token string) string {
	if gid, secret, ok := strings.Cut(token, "."); ok && !strings.Contains(secret, ".") {
		if g, err := s.store.GetGrant(ctx, gid); err == nil {
			h := hashSecret(secret)
			if (g.TokenHash != "" && constEq(h, g.TokenHash)) || (g.PrevTokenHash != "" && constEq(h, g.PrevTokenHash)) {
				return gid
			}
		}
		return ""
	}
	parsed, err := jwt.Parse(token, s.signer.Keyfunc,
		jwt.WithValidMethods([]string{s.signer.Method().Alg()}), jwt.WithIssuer(s.issuer))
	if err != nil || !parsed.Valid {
		return ""
	}
	if typ, _ := parsed.Header["typ"].(string); !strings.EqualFold(typ, identity.TokenTypeAccessJWT) {
		return ""
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	gid, _ := claims[ClaimGrantID].(string)
	return gid
}
