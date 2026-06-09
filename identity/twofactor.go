package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// Internal token provider/name keys used by the user-token store.
const (
	internalProvider     = "[go-idento]"
	authenticatorKeyName = "AuthenticatorKey"
	recoveryCodesName    = "RecoveryCodes"
)

// GetAuthenticatorKey returns the user's TOTP secret, generating and persisting
// one on first use.
func (m *UserManagerOf[T, PT]) GetAuthenticatorKey(ctx context.Context, u PT) (string, error) {
	key, err := m.Store.GetToken(ctx, u, internalProvider, authenticatorKeyName)
	if err != nil {
		return "", err
	}
	if key == "" {
		key = GenerateSecret()
		if err := m.Store.SetToken(ctx, u, internalProvider, authenticatorKeyName, key); err != nil {
			return "", err
		}
	}
	return key, nil
}

// ResetAuthenticatorKey replaces the TOTP secret (invalidates old authenticator).
func (m *UserManagerOf[T, PT]) ResetAuthenticatorKey(ctx context.Context, u PT) (string, error) {
	key := GenerateSecret()
	if err := m.Store.SetToken(ctx, u, internalProvider, authenticatorKeyName, key); err != nil {
		return "", err
	}
	return key, nil
}

// VerifyTwoFactorTOTP validates a TOTP code against the user's stored key.
func (m *UserManagerOf[T, PT]) VerifyTwoFactorTOTP(ctx context.Context, u PT, code string) (bool, error) {
	key, err := m.Store.GetToken(ctx, u, internalProvider, authenticatorKeyName)
	if err != nil || key == "" {
		return false, err
	}
	return DefaultTOTP().Validate(key, strings.TrimSpace(code), nowFn()), nil
}

// SetTwoFactorEnabled toggles 2FA, bumping the security stamp.
func (m *UserManagerOf[T, PT]) SetTwoFactorEnabled(ctx context.Context, u PT, enabled bool) error {
	b := u.Base()
	b.TwoFactorEnabled = enabled
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}

// GenerateRecoveryCodes creates n single-use recovery codes, stores them hashed
// and returns the plaintext codes (shown to the user once).
func (m *UserManagerOf[T, PT]) GenerateRecoveryCodes(ctx context.Context, u PT, n int) ([]string, error) {
	codes := make([]string, n)
	hashed := make([]string, n)
	for i := range codes {
		codes[i] = randomRecoveryCode()
		hashed[i] = hashRefresh(codes[i])
	}
	if err := m.Store.SetToken(ctx, u, internalProvider, recoveryCodesName, strings.Join(hashed, ";")); err != nil {
		return nil, err
	}
	return codes, nil
}

// RedeemRecoveryCode consumes a recovery code if valid (one-time use).
func (m *UserManagerOf[T, PT]) RedeemRecoveryCode(ctx context.Context, u PT, code string) (bool, error) {
	stored, err := m.Store.GetToken(ctx, u, internalProvider, recoveryCodesName)
	if err != nil || stored == "" {
		return false, err
	}
	target := hashRefresh(strings.TrimSpace(code))
	parts := strings.Split(stored, ";")
	remaining := make([]string, 0, len(parts))
	found := false
	for _, p := range parts {
		if p == target && !found {
			found = true
			continue // consume it
		}
		if p != "" {
			remaining = append(remaining, p)
		}
	}
	if !found {
		return false, nil
	}
	if err := m.Store.SetToken(ctx, u, internalProvider, recoveryCodesName, strings.Join(remaining, ";")); err != nil {
		return false, err
	}
	return true, nil
}

// CountRecoveryCodes returns how many unused recovery codes remain.
func (m *UserManagerOf[T, PT]) CountRecoveryCodes(ctx context.Context, u PT) (int, error) {
	stored, err := m.Store.GetToken(ctx, u, internalProvider, recoveryCodesName)
	if err != nil || stored == "" {
		return 0, err
	}
	return len(strings.Split(stored, ";")), nil
}

func randomRecoveryCode() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random recovery code: " + err.Error())
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return strings.ToLower(s[:5] + "-" + s[5:10]) // grouped for readability
}
