package identity

import "context"

// AddLogin associates an external (OAuth/OIDC) login with the user.
func (m *UserManagerOf[T, PT]) AddLogin(ctx context.Context, u PT, login UserLoginInfo) error {
	return m.Store.AddLogin(ctx, u, login)
}

// RemoveLogin removes an external login association.
func (m *UserManagerOf[T, PT]) RemoveLogin(ctx context.Context, u PT, loginProvider, providerKey string) error {
	return m.Store.RemoveLogin(ctx, u, loginProvider, providerKey)
}

// GetLogins lists the user's external logins.
func (m *UserManagerOf[T, PT]) GetLogins(ctx context.Context, u PT) ([]UserLoginInfo, error) {
	return m.Store.GetLogins(ctx, u)
}

// FindByLogin resolves the user behind an external login, if any.
func (m *UserManagerOf[T, PT]) FindByLogin(ctx context.Context, loginProvider, providerKey string) (PT, error) {
	return m.Store.FindByLogin(ctx, loginProvider, providerKey)
}

// ExternalLoginSignIn signs in a user via an external login, applying the same
// lockout/confirmation rules as password sign-in. Returns the result and the
// user (nil when no account is linked to the external login).
//
// SECURITY: loginProvider/providerKey are trusted as already-verified identity.
// The caller MUST have validated them against the provider first — i.e. verified
// the OAuth/OIDC ID-token signature (against the provider JWKS) and its
// iss/aud/exp, then taken providerKey from the validated "sub" claim. Passing
// unverified, user-controlled values here allows signing in as any linked user.
func (s *SignInManagerOf[T, PT]) ExternalLoginSignIn(ctx context.Context, loginProvider, providerKey string) (SignInResult, PT) {
	u, err := s.Users.FindByLogin(ctx, loginProvider, providerKey)
	if err != nil || u == nil {
		return SignInResult{}, nil
	}
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}, u
	}
	if !s.CanSignIn(u) {
		return SignInResult{IsNotAllowed: true}, u
	}
	_ = s.Users.ResetAccessFailedCount(ctx, u)
	if u.Base().TwoFactorEnabled {
		return SignInResult{RequiresTwoFactor: true}, u
	}
	return SignInResult{Succeeded: true}, u
}
