package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// IssuePair builds an access token from the user's claims/roles and persists a
// fresh refresh token.
func (t *TokenServiceOf[T, PT]) IssuePair(ctx context.Context, u PT) (*TokenPair, error) {
	b := u.Base()
	roles, err := t.Users.GetRoles(ctx, u)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	refresh := randomToken()
	// Stored value: "<hash>:<expiryUnix>" so RefreshTokenTTL is enforced
	// server-side. Each rotation re-stamps the expiry (sliding window).
	refreshExp := now.Add(t.Options.RefreshTokenTTL).Unix()
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
// while a stolen, dormant token dies at the TTL.
func (t *TokenServiceOf[T, PT]) Refresh(ctx context.Context, u PT, refreshToken string) (*TokenPair, error) {
	stored, err := t.Users.Store.GetToken(ctx, u, refreshTokenProvider, refreshTokenName)
	if err != nil || stored == "" {
		return nil, ErrInvalidToken
	}
	hashPart, expPart, ok := strings.Cut(stored, ":")
	if !ok {
		return nil, ErrInvalidToken // legacy/unknown format: fail closed
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || nowFn().After(time.Unix(exp, 0)) {
		return nil, ErrInvalidToken // expired
	}
	if subtle.ConstantTimeCompare([]byte(hashPart), []byte(hashRefresh(refreshToken))) != 1 {
		return nil, ErrInvalidToken
	}
	return t.IssuePair(ctx, u) // SetToken overwrites the old refresh token
}

// Revoke removes the stored refresh token, ending the session.
func (t *TokenServiceOf[T, PT]) Revoke(ctx context.Context, u PT) error {
	return t.Users.Store.RemoveToken(ctx, u, refreshTokenProvider, refreshTokenName)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
