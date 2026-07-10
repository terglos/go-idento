package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claim names used in issued access tokens (idiomatic, short JWT claims).
const (
	ClaimNameIdentifier = "uid"
	ClaimName           = "name"
	ClaimEmail          = "email"
	ClaimRole           = "roles"
	ClaimSecurityStamp  = "idn_sstamp"
)

// TokenOptions configures JWT issuance.
type TokenOptions struct {
	// SigningKey is the HMAC secret used when Signer is nil (back-compat).
	SigningKey []byte
	// Signer, when set, overrides SigningKey and enables RS256/ES256 + rotation.
	Signer         Signer
	Issuer         string
	Audience       string
	AccessTokenTTL time.Duration
	// RefreshTokenTTL bounds how long an issued refresh token stays redeemable.
	// The expiry is stamped server-side at issuance and re-stamped on each
	// rotation (sliding window); Refresh rejects an expired token.
	RefreshTokenTTL time.Duration
	// MaxSessions caps concurrent refresh sessions per user when a session store
	// is configured (WithSessionStore); issuing beyond the cap evicts the
	// oldest-expiring session. 0 = unlimited. MaxSessions=1 reproduces the
	// legacy single-session behavior (a new login signs out the previous one).
	MaxSessions int
}

// signer resolves the effective signer: explicit Signer, else HMAC over SigningKey.
func (o TokenOptions) signer() Signer {
	if o.Signer != nil {
		return o.Signer
	}
	return NewHMACSigner(o.SigningKey)
}

// DefaultTokenOptions returns 15-minute access tokens and 7-day refresh tokens.
func DefaultTokenOptions(signingKey []byte, issuer, audience string) TokenOptions {
	return TokenOptions{
		SigningKey:      signingKey,
		Issuer:          issuer,
		Audience:        audience,
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
}

// TokenPair is what a successful sign-in returns to API clients.
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	TokenType    string    `json:"tokenType"`
}

const refreshTokenProvider = "GoIdentity"
const refreshTokenName = "RefreshToken"

// TokenServiceOf issues and validates JWT access tokens and opaque refresh
// tokens. The refresh token is stored hashed in the user token store, and the
// access token embeds the security stamp so revocation works by bumping it.
// Generic over the user type; use [TokenService] / [NewTokenService] for the
// built-in user.
type TokenServiceOf[T any, PT Ptr[T]] struct {
	Users   *UserManagerOf[T, PT]
	Options TokenOptions
	// Sessions, when set (via WithSessionStore), stores one refresh session per
	// device/browser — concurrent logins no longer overwrite each other. Nil
	// keeps the legacy single-slot behavior.
	Sessions RefreshTokenStore
}

// TokenService is the token service for the built-in [User] type.
type TokenService = TokenServiceOf[User, *User]

// NewTokenService wires a token service for the built-in user.
func NewTokenService(users *UserManager, opts TokenOptions) *TokenService {
	return NewTokenServiceOf[User](users, opts)
}

// NewTokenServiceOf wires a token service for a custom user type T.
func NewTokenServiceOf[T any, PT Ptr[T]](users *UserManagerOf[T, PT], opts TokenOptions) *TokenServiceOf[T, PT] {
	return &TokenServiceOf[T, PT]{Users: users, Options: opts}
}

// WithSessionStore enables multi-session refresh tokens: each IssuePair creates
// its own session row (one per device/browser), so concurrent logins no longer
// overwrite each other's refresh token. Tokens issued before enabling this (the
// legacy single slot) keep redeeming and are migrated to a session on their
// first rotation. Returns the service for chaining.
func (t *TokenServiceOf[T, PT]) WithSessionStore(s RefreshTokenStore) *TokenServiceOf[T, PT] {
	t.Sessions = s
	return t
}

// refreshTTL resolves the configured TTL with the 7-day fallback.
func (t *TokenServiceOf[T, PT]) refreshTTL() time.Duration {
	if t.Options.RefreshTokenTTL > 0 {
		return t.Options.RefreshTokenTTL
	}
	return 7 * 24 * time.Hour
}

// IssuePair builds an access token from the user's claims/roles and persists a
// fresh refresh token.
func (t *TokenServiceOf[T, PT]) IssuePair(ctx context.Context, u PT) (*TokenPair, error) {
	signed, exp, err := t.signAccessToken(ctx, u)
	if err != nil {
		return nil, err
	}

	// Multi-session path: one refresh session row per login/device.
	if t.Sessions != nil {
		refresh, err := t.newSessionRefresh(ctx, u)
		if err != nil {
			return nil, err
		}
		return &TokenPair{AccessToken: signed, RefreshToken: refresh, ExpiresAt: exp, TokenType: "Bearer"}, nil
	}

	// Legacy single-slot path. Stored value: "<hash>:<expiryUnix>" so
	// RefreshTokenTTL is enforced server-side; each rotation re-stamps the
	// expiry (sliding window). An unset TTL falls back to 7 days (mirrors
	// NewDataTokenProvider) so manual TokenOptions construction doesn't yield
	// instantly-expired tokens.
	refresh := randomToken()
	refreshExp := nowFn().Add(t.refreshTTL()).Unix()
	stored := hashRefresh(refresh) + ":" + strconv.FormatInt(refreshExp, 10)
	if err := t.Users.Store.SetToken(ctx, u, refreshTokenProvider, refreshTokenName, stored); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  signed,
		RefreshToken: refresh,
		ExpiresAt:    exp,
		TokenType:    "Bearer",
	}, nil
}

// signAccessToken builds and signs the JWT access token from the user's
// identity, roles and claims.
func (t *TokenServiceOf[T, PT]) signAccessToken(ctx context.Context, u PT) (string, time.Time, error) {
	b := u.Base()
	roles, err := t.Users.GetRoles(ctx, u)
	if err != nil {
		return "", time.Time{}, err
	}
	now := nowFn()
	exp := now.Add(t.Options.AccessTokenTTL)

	claims := jwt.MapClaims{
		"sub":               b.ID,
		ClaimNameIdentifier: b.ID,
		ClaimName:           b.UserName,
		ClaimEmail:          b.Email,
		ClaimSecurityStamp:  b.SecurityStamp,
		"iss":               t.Options.Issuer,
		"aud":               t.Options.Audience,
		"iat":               now.Unix(),
		"nbf":               now.Unix(),
		"exp":               exp.Unix(),
	}
	if len(roles) > 0 {
		claims[ClaimRole] = roles
	}
	// Custom user claims are merged in.
	if userClaims, err := t.Users.GetClaims(ctx, u); err != nil {
		t.Users.logger().Warn("identity: failed to load user claims for token", "user", b.ID, "err", err)
	} else {
		for _, c := range userClaims {
			if _, taken := claims[c.Type]; !taken {
				claims[c.Type] = c.Value
			}
		}
	}

	signer := t.Options.signer()
	tok := jwt.NewWithClaims(signer.Method(), claims)
	kid, key := signer.SignKey()
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// newSessionRefresh creates a fresh refresh session for the user, runs the
// opportunistic GC and the MaxSessions eviction, and returns the opaque token
// "<sessionID>.<secret>" (the sessionID only routes to the row; the secret is
// what is hashed and verified).
func (t *TokenServiceOf[T, PT]) newSessionRefresh(ctx context.Context, u PT) (string, error) {
	now := nowFn()
	secret := randomToken()
	rt := &RefreshToken{
		SessionID: uuid.NewString(),
		UserID:    u.Base().ID,
		TokenHash: hashRefresh(secret),
		ExpiresAt: now.Add(t.refreshTTL()),
		CreatedAt: now,
	}
	if err := t.Sessions.CreateRefreshToken(ctx, rt); err != nil {
		return "", err
	}
	// Opportunistic GC: sweep dormant, expired sessions (best-effort).
	if _, err := t.Sessions.DeleteExpiredRefreshTokens(ctx, now); err != nil {
		t.Users.logger().Warn("identity: refresh-session GC failed", "err", err)
	}
	t.enforceMaxSessions(ctx, u.Base().ID, rt.SessionID)
	return rt.SessionID + "." + secret, nil
}

// enforceMaxSessions evicts the oldest-expiring sessions beyond
// Options.MaxSessions (best-effort; keepID is never evicted).
func (t *TokenServiceOf[T, PT]) enforceMaxSessions(ctx context.Context, userID, keepID string) {
	max := t.Options.MaxSessions
	if max <= 0 {
		return
	}
	sessions, err := t.Sessions.ListUserRefreshTokens(ctx, userID)
	if err != nil || len(sessions) <= max {
		return
	}
	// Oldest-expiring first (expiry slides on use, so it proxies recency).
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ExpiresAt.Before(sessions[j].ExpiresAt) })
	excess := len(sessions) - max
	for _, s := range sessions {
		if excess == 0 {
			break
		}
		if s.SessionID == keepID {
			continue
		}
		if err := t.Sessions.DeleteRefreshToken(ctx, s.SessionID); err != nil {
			t.Users.logger().Warn("identity: session eviction failed", "session", s.SessionID, "err", err)
			continue
		}
		excess--
	}
}

// ValidateAccessToken parses and validates a JWT, then checks the embedded
// security stamp still matches (enforces revocation).
func (t *TokenServiceOf[T, PT]) ValidateAccessToken(ctx context.Context, tokenStr string) (PT, jwt.MapClaims, error) {
	signer := t.Options.signer()
	parsed, err := jwt.Parse(tokenStr, signer.Keyfunc,
		jwt.WithValidMethods([]string{signer.Method().Alg()}),
		jwt.WithIssuer(t.Options.Issuer), jwt.WithAudience(t.Options.Audience))
	if err != nil || !parsed.Valid {
		return nil, nil, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, ErrInvalidToken
	}
	uid, _ := claims["sub"].(string)
	u, err := t.Users.FindByID(ctx, uid)
	if err != nil || u == nil {
		return nil, nil, ErrInvalidToken
	}
	if stamp, _ := claims[ClaimSecurityStamp].(string); stamp != u.Base().SecurityStamp {
		return nil, nil, ErrInvalidToken // password changed / token revoked
	}
	return u, claims, nil
}

// Refresh swaps a valid, unexpired refresh token for a new token pair
// (rotation). RefreshTokenTTL is enforced against the expiry stamped when the
// token was issued; rotation re-stamps it, so an actively-used session slides
// while a stolen, dormant token dies at the TTL. With a session store
// configured, rotation stays within the token's own session — other
// devices/tabs are untouched — and a legacy (pre-session) token is migrated to
// its own session on first rotation.
func (t *TokenServiceOf[T, PT]) Refresh(ctx context.Context, u PT, refreshToken string) (*TokenPair, error) {
	if t.Sessions != nil {
		if sid, secret, ok := strings.Cut(refreshToken, "."); ok {
			return t.refreshSession(ctx, u, sid, secret)
		}
		// Legacy-format token: validate against the old single slot, then
		// migrate it into its own session (and retire the slot).
		if err := t.validateLegacySlot(ctx, u, refreshToken); err != nil {
			return nil, err
		}
		pair, err := t.IssuePair(ctx, u) // session path: creates a new session
		if err != nil {
			return nil, err
		}
		_ = t.Users.Store.RemoveToken(ctx, u, refreshTokenProvider, refreshTokenName)
		return pair, nil
	}
	if err := t.validateLegacySlot(ctx, u, refreshToken); err != nil {
		return nil, err
	}
	return t.IssuePair(ctx, u) // SetToken overwrites the old refresh token
}

// validateLegacySlot checks a refresh token against the legacy single slot.
func (t *TokenServiceOf[T, PT]) validateLegacySlot(ctx context.Context, u PT, refreshToken string) error {
	stored, err := t.Users.Store.GetToken(ctx, u, refreshTokenProvider, refreshTokenName)
	if err != nil || stored == "" {
		return ErrInvalidToken
	}
	hashPart, expPart, ok := strings.Cut(stored, ":")
	if !ok {
		return ErrInvalidToken // pre-expiry format: fail closed
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || nowFn().After(time.Unix(exp, 0)) {
		return ErrInvalidToken // expired
	}
	if subtle.ConstantTimeCompare([]byte(hashPart), []byte(hashRefresh(refreshToken))) != 1 {
		return ErrInvalidToken
	}
	return nil
}

// refreshSession validates and rotates one session in place: same SessionID,
// new secret/hash, re-stamped sliding expiry.
func (t *TokenServiceOf[T, PT]) refreshSession(ctx context.Context, u PT, sessionID, secret string) (*TokenPair, error) {
	if sessionID == "" || len(sessionID) > 64 {
		return nil, ErrInvalidToken
	}
	rt, err := t.Sessions.GetRefreshTokenBySession(ctx, sessionID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err // store/infra failure — distinct from an invalid token
	}
	now := nowFn()
	if rt.UserID != u.Base().ID || now.After(rt.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	if subtle.ConstantTimeCompare([]byte(rt.TokenHash), []byte(hashRefresh(secret))) != 1 {
		return nil, ErrInvalidToken
	}

	signed, exp, err := t.signAccessToken(ctx, u)
	if err != nil {
		return nil, err
	}
	newSecret := randomToken()
	rt.TokenHash = hashRefresh(newSecret)
	rt.ExpiresAt = now.Add(t.refreshTTL())
	rt.LastUsedAt = &now
	if err := t.Sessions.UpdateRefreshToken(ctx, rt); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  signed,
		RefreshToken: rt.SessionID + "." + newSecret,
		ExpiresAt:    exp,
		TokenType:    "Bearer",
	}, nil
}

// Revoke ends the user's refresh sessions: the legacy slot and, when a session
// store is configured, every per-device session (global sign-out for refresh
// tokens; outstanding access tokens die at their TTL, or immediately via
// UserManager.UpdateSecurityStamp).
func (t *TokenServiceOf[T, PT]) Revoke(ctx context.Context, u PT) error {
	if err := t.Users.Store.RemoveToken(ctx, u, refreshTokenProvider, refreshTokenName); err != nil {
		return err
	}
	if t.Sessions != nil {
		if _, err := t.Sessions.DeleteUserRefreshTokens(ctx, u.Base().ID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeSession revokes the single session the given refresh token belongs to,
// leaving the user's other devices signed in. A legacy-format token revokes the
// legacy slot.
func (t *TokenServiceOf[T, PT]) RevokeSession(ctx context.Context, u PT, refreshToken string) error {
	if t.Sessions != nil {
		if sid, _, ok := strings.Cut(refreshToken, "."); ok {
			rt, err := t.Sessions.GetRefreshTokenBySession(ctx, sid)
			if errors.Is(err, ErrNotFound) {
				return nil // already gone
			}
			if err != nil {
				return err
			}
			if rt.UserID != u.Base().ID {
				return ErrInvalidToken
			}
			return t.Sessions.DeleteRefreshToken(ctx, sid)
		}
	}
	return t.Users.Store.RemoveToken(ctx, u, refreshTokenProvider, refreshTokenName)
}

// ListSessions returns the user's active refresh sessions (metadata only — the
// secret is never recoverable). Requires a session store; returns
// [ErrListNotSupported] otherwise.
func (t *TokenServiceOf[T, PT]) ListSessions(ctx context.Context, u PT) ([]RefreshToken, error) {
	if t.Sessions == nil {
		return nil, ErrListNotSupported
	}
	return t.Sessions.ListUserRefreshTokens(ctx, u.Base().ID)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
