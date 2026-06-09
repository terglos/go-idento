package identity

import (
	"context"
	"sort"
)

// TwoFactorTokenProvider produces and validates a named second-factor token,
// pluggable like ASP.NET's IUserTwoFactorTokenProvider. Register custom ones via
// [UserManagerOf.RegisterTwoFactorProvider]; the built-in "Authenticator" (TOTP)
// and "Phone" (SMS) providers are resolved on demand without registration.
type TwoFactorTokenProvider[T any, PT Ptr[T]] interface {
	// Name is the stable identifier used with GenerateUserToken/VerifyUserToken.
	Name() string
	// CanGenerate reports whether the provider is usable for this user right now
	// (e.g. the phone provider needs a phone number on file).
	CanGenerate(ctx context.Context, m *UserManagerOf[T, PT], u PT) bool
	// Generate issues a token (may be empty when the code originates client-side,
	// as with an authenticator app).
	Generate(ctx context.Context, m *UserManagerOf[T, PT], u PT) (string, error)
	// Validate checks a submitted token.
	Validate(ctx context.Context, m *UserManagerOf[T, PT], u PT, token string) (bool, error)
}

// Built-in two-factor provider names.
const (
	TwoFactorProviderAuthenticator = "Authenticator"
	TwoFactorProviderPhone         = "Phone"
)

// RegisterTwoFactorProvider adds (or replaces) a named second-factor provider.
// Registering one under a built-in name overrides that built-in.
func (m *UserManagerOf[T, PT]) RegisterTwoFactorProvider(p TwoFactorTokenProvider[T, PT]) {
	if m.tokenProviders == nil {
		m.tokenProviders = map[string]TwoFactorTokenProvider[T, PT]{}
	}
	m.tokenProviders[p.Name()] = p
}

func (m *UserManagerOf[T, PT]) resolveProvider(name string) (TwoFactorTokenProvider[T, PT], bool) {
	if p, ok := m.tokenProviders[name]; ok {
		return p, true
	}
	switch name {
	case TwoFactorProviderAuthenticator:
		return authenticatorProvider[T, PT]{}, true
	case TwoFactorProviderPhone:
		return phoneProvider[T, PT]{}, true
	}
	return nil, false
}

// GenerateUserToken issues a second-factor token from the named provider.
func (m *UserManagerOf[T, PT]) GenerateUserToken(ctx context.Context, u PT, provider string) (string, error) {
	p, ok := m.resolveProvider(provider)
	if !ok {
		return "", newErr("UnknownTokenProvider", "no such two-factor token provider: "+provider)
	}
	return p.Generate(ctx, m, u)
}

// VerifyUserToken validates a second-factor token against the named provider.
func (m *UserManagerOf[T, PT]) VerifyUserToken(ctx context.Context, u PT, provider, token string) (bool, error) {
	p, ok := m.resolveProvider(provider)
	if !ok {
		return false, newErr("UnknownTokenProvider", "no such two-factor token provider: "+provider)
	}
	return p.Validate(ctx, m, u, token)
}

// GetValidTwoFactorProviders returns the names of providers currently usable for
// the user (built-ins plus any registered custom ones whose CanGenerate is
// true), sorted for determinism.
func (m *UserManagerOf[T, PT]) GetValidTwoFactorProviders(ctx context.Context, u PT) ([]string, error) {
	candidates := map[string]struct{}{
		TwoFactorProviderAuthenticator: {},
		TwoFactorProviderPhone:         {},
	}
	for name := range m.tokenProviders {
		candidates[name] = struct{}{}
	}
	var out []string
	for name := range candidates {
		if p, ok := m.resolveProvider(name); ok && p.CanGenerate(ctx, m, u) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// --- built-in providers ---

type authenticatorProvider[T any, PT Ptr[T]] struct{}

func (authenticatorProvider[T, PT]) Name() string { return TwoFactorProviderAuthenticator }

func (authenticatorProvider[T, PT]) CanGenerate(ctx context.Context, m *UserManagerOf[T, PT], u PT) bool {
	// Usable only once an authenticator key exists (do not lazily create one).
	key, err := m.Store.GetToken(ctx, u, internalProvider, authenticatorKeyName)
	return err == nil && key != ""
}

// Generate is a no-op for the authenticator: the code comes from the user's app.
func (authenticatorProvider[T, PT]) Generate(context.Context, *UserManagerOf[T, PT], PT) (string, error) {
	return "", nil
}

func (authenticatorProvider[T, PT]) Validate(ctx context.Context, m *UserManagerOf[T, PT], u PT, token string) (bool, error) {
	return m.VerifyTwoFactorTOTP(ctx, u, token)
}

type phoneProvider[T any, PT Ptr[T]] struct{}

func (phoneProvider[T, PT]) Name() string { return TwoFactorProviderPhone }

func (phoneProvider[T, PT]) CanGenerate(_ context.Context, _ *UserManagerOf[T, PT], u PT) bool {
	return u.Base().PhoneNumber != ""
}

func (phoneProvider[T, PT]) Generate(ctx context.Context, m *UserManagerOf[T, PT], u PT) (string, error) {
	return m.GeneratePhoneToken(ctx, u)
}

func (phoneProvider[T, PT]) Validate(ctx context.Context, m *UserManagerOf[T, PT], u PT, token string) (bool, error) {
	return m.VerifyPhoneToken(ctx, u, token)
}
