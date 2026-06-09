package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// DataTokenProvider generates time-limited, purpose-bound, single-use-ish
// tokens for email confirmation, password reset, etc. The token binds the
// user's SecurityStamp, so any credential change (or another reset)
// invalidates outstanding tokens. It operates on the base [User] fields and is
// not generic.
type DataTokenProvider struct {
	key      []byte        // server-side secret
	lifespan time.Duration // token validity window
}

// NewDataTokenProvider builds a provider; tokens expire after lifespan (a day
// is a reasonable default). Use a stable secret per app.
func NewDataTokenProvider(key []byte, lifespan time.Duration) *DataTokenProvider {
	if lifespan == 0 {
		lifespan = 24 * time.Hour
	}
	return &DataTokenProvider{key: key, lifespan: lifespan}
}

// Generate creates a token for (user, purpose). The bound SecurityStamp means
// using one reset token, then changing the stamp, invalidates the rest.
func (p *DataTokenProvider) Generate(purpose string, u *User) string {
	issued := nowFn().Unix()
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(issued))

	payload := append(ts[:], []byte(u.ID+"|"+purpose+"|"+u.SecurityStamp)...)
	mac := p.sign(payload)
	// token = base64( issued(8) || mac(32) ); user/purpose/stamp are recomputed
	// from the live user on validation, so they need not be transmitted.
	out := append(append([]byte{}, ts[:]...), mac...)
	return base64.RawURLEncoding.EncodeToString(out)
}

// Validate checks a token for (user, purpose) and that it is unexpired (within
// the provider's configured lifespan).
func (p *DataTokenProvider) Validate(purpose, token string, u *User) bool {
	return p.ValidateWithLifespan(purpose, token, u, p.lifespan)
}

// ValidateWithLifespan is like [Validate] but checks against an explicit
// lifespan instead of the provider default — used for longer-lived tokens such
// as the "remember this machine" two-factor token. Generation is unchanged
// ([Generate] stamps the issue time); only the accepted age differs.
func (p *DataTokenProvider) ValidateWithLifespan(purpose, token string, u *User, lifespan time.Duration) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	issued := int64(binary.BigEndian.Uint64(raw[:8]))
	if nowFn().Sub(time.Unix(issued, 0)) > lifespan {
		return false
	}
	// Rebuild the payload from a fresh buffer; appending onto raw[:8] would
	// alias and overwrite the MAC bytes in raw[8:].
	payload := make([]byte, 0, 8+len(u.ID)+len(purpose)+len(u.SecurityStamp)+2)
	payload = append(payload, raw[:8]...)
	payload = append(payload, []byte(u.ID+"|"+purpose+"|"+u.SecurityStamp)...)
	expected := p.sign(payload)
	return subtle.ConstantTimeCompare(raw[8:], expected) == 1
}

func (p *DataTokenProvider) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, p.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

// Purposes used by the UserManager helpers below.
const (
	purposeEmailConfirmation = "EmailConfirmation"
	purposePasswordReset     = "ResetPassword"
	purposeChangeEmail       = "ChangeEmail"
	purposeTwoFactorRemember = "TwoFactorRemember"
)

// TwoFactorRememberTTL is how long a "remember this machine" token stays valid.
var TwoFactorRememberTTL = 30 * 24 * time.Hour

// GenerateTwoFactorRememberToken issues a long-lived token a client can store to
// skip the second factor on this device (see [SignInManagerOf.PasswordSignInRemembering]).
// It binds the SecurityStamp, so a password or 2FA change invalidates it.
func (m *UserManagerOf[T, PT]) GenerateTwoFactorRememberToken(u PT) string {
	return m.Tokens.Generate(purposeTwoFactorRemember, u.Base())
}

// VerifyTwoFactorRememberToken reports whether token is a valid, unexpired
// remember-this-machine token for the user.
func (m *UserManagerOf[T, PT]) VerifyTwoFactorRememberToken(u PT, token string) bool {
	return m.Tokens != nil && token != "" &&
		m.Tokens.ValidateWithLifespan(purposeTwoFactorRemember, token, u.Base(), TwoFactorRememberTTL)
}

// --- UserManager integration ---

// WithTokenProvider attaches a DataTokenProvider, enabling the confirmation/
// reset helpers below. Returns the manager for chaining.
func (m *UserManagerOf[T, PT]) WithTokenProvider(p *DataTokenProvider) *UserManagerOf[T, PT] {
	m.Tokens = p
	return m
}

// GenerateEmailConfirmationToken issues a token to confirm the user's email.
func (m *UserManagerOf[T, PT]) GenerateEmailConfirmationToken(u PT) string {
	return m.Tokens.Generate(purposeEmailConfirmation, u.Base())
}

// ConfirmEmail validates the token and marks the email confirmed.
func (m *UserManagerOf[T, PT]) ConfirmEmail(ctx context.Context, u PT, token string) error {
	b := u.Base()
	if m.Tokens == nil || !m.Tokens.Validate(purposeEmailConfirmation, token, b) {
		return ErrInvalidToken
	}
	b.EmailConfirmed = true
	return m.Store.Update(ctx, u)
}

// GeneratePasswordResetToken issues a token to reset the user's password.
func (m *UserManagerOf[T, PT]) GeneratePasswordResetToken(u PT) string {
	return m.Tokens.Generate(purposePasswordReset, u.Base())
}

// ResetPassword validates the token, applies the policy and sets the new
// password, bumping the security stamp (which invalidates the token + sessions).
func (m *UserManagerOf[T, PT]) ResetPassword(ctx context.Context, u PT, token, newPassword string) error {
	b := u.Base()
	if m.Tokens == nil || !m.Tokens.Validate(purposePasswordReset, token, b) {
		return ErrInvalidToken
	}
	if err := m.ValidatePassword(newPassword); err != nil {
		return err
	}
	b.PasswordHash = m.Hasher.Hash(b, newPassword)
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}

// GenerateChangeEmailToken issues a token to confirm a new email address.
func (m *UserManagerOf[T, PT]) GenerateChangeEmailToken(u PT, newEmail string) string {
	return m.Tokens.Generate(purposeChangeEmail+":"+strings.ToUpper(newEmail), u.Base())
}

// ChangeEmail validates the token and updates the (normalized) email.
func (m *UserManagerOf[T, PT]) ChangeEmail(ctx context.Context, u PT, newEmail, token string) error {
	b := u.Base()
	purpose := purposeChangeEmail + ":" + strings.ToUpper(newEmail)
	if m.Tokens == nil || !m.Tokens.Validate(purpose, token, b) {
		return ErrInvalidToken
	}
	normalized := m.Normalizer.Normalize(newEmail)
	// Re-enforce email uniqueness at apply time: a token minted earlier must not
	// let two accounts collide on the same address.
	if m.Options.User.RequireUniqueEmail && normalized != "" {
		if existing, err := m.Store.FindByEmail(ctx, normalized); err == nil && existing != nil && existing.Base().ID != b.ID {
			return ErrDuplicateEmail
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	b.Email = newEmail
	b.NormalizedEmail = normalized
	b.EmailConfirmed = true
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}
