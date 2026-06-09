package identity

import (
	"context"
	"crypto/subtle"
)

// subtleConstEq compares two strings in constant time.
func subtleConstEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SignInResult is the outcome of a sign-in attempt.
type SignInResult struct {
	Succeeded         bool
	IsLockedOut       bool
	IsNotAllowed      bool
	RequiresTwoFactor bool
}

// SignInManagerOf orchestrates credential checks, lockout and the "is allowed to
// sign in" rules. Generic over the user type; use
// [SignInManager] / [NewSignInManager] for the built-in user.
type SignInManagerOf[T any, PT Ptr[T]] struct {
	Users   *UserManagerOf[T, PT]
	Options SignInOptions
}

// SignInManager is the sign-in manager for the built-in [User] type.
type SignInManager = SignInManagerOf[User, *User]

// NewSignInManager wires a sign-in manager for the built-in user.
func NewSignInManager(users *UserManager) *SignInManager {
	return NewSignInManagerOf[User](users)
}

// NewSignInManagerOf wires a sign-in manager for a custom user type T.
func NewSignInManagerOf[T any, PT Ptr[T]](users *UserManagerOf[T, PT]) *SignInManagerOf[T, PT] {
	return &SignInManagerOf[T, PT]{Users: users, Options: users.Options.SignIn}
}

// CanSignIn applies the confirmation requirements (email/phone).
func (s *SignInManagerOf[T, PT]) CanSignIn(u PT) bool {
	b := u.Base()
	if s.Options.RequireConfirmedEmail && !b.EmailConfirmed {
		return false
	}
	if s.Options.RequireConfirmedPhoneNumber && !b.PhoneNumberConfirmed {
		return false
	}
	return true
}

// PasswordSignIn validates a username + password, applying lockout on failure
// when requested.
func (s *SignInManagerOf[T, PT]) PasswordSignIn(ctx context.Context, userName, password string, lockoutOnFailure bool) (SignInResult, PT) {
	u, err := s.Users.FindByName(ctx, userName)
	if err != nil || u == nil {
		return SignInResult{}, nil // generic failure: do not reveal existence
	}
	return s.passwordSignInUser(ctx, u, password, lockoutOnFailure)
}

// PasswordSignInRemembering is like [PasswordSignIn] but, when the account has
// two-factor enabled, a valid rememberToken (from a prior
// [UserManagerOf.GenerateTwoFactorRememberToken] on this device) short-circuits
// the second factor and the result Succeeds directly. An empty or invalid token
// behaves exactly like PasswordSignIn (returns RequiresTwoFactor).
func (s *SignInManagerOf[T, PT]) PasswordSignInRemembering(ctx context.Context, userName, password string, lockoutOnFailure bool, rememberToken string) (SignInResult, PT) {
	u, err := s.Users.FindByName(ctx, userName)
	if err != nil || u == nil {
		return SignInResult{}, nil
	}
	res, user := s.passwordSignInUser(ctx, u, password, lockoutOnFailure)
	if res.RequiresTwoFactor && s.IsTwoFactorClientRemembered(user, rememberToken) {
		return SignInResult{Succeeded: true}, user
	}
	return res, user
}

// IsTwoFactorClientRemembered reports whether rememberToken is a valid
// remember-this-machine token for the user (skips the second factor).
func (s *SignInManagerOf[T, PT]) IsTwoFactorClientRemembered(u PT, rememberToken string) bool {
	return s.Users.VerifyTwoFactorRememberToken(u, rememberToken)
}

func (s *SignInManagerOf[T, PT]) passwordSignInUser(ctx context.Context, u PT, password string, lockoutOnFailure bool) (SignInResult, PT) {
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}, u
	}
	if !s.CanSignIn(u) {
		return SignInResult{IsNotAllowed: true}, u
	}
	if s.Users.CheckPassword(ctx, u, password) {
		if err := s.Users.ResetAccessFailedCount(ctx, u); err != nil {
			s.Users.logger().Warn("identity: failed to reset access-failed count", "user", u.Base().ID, "err", err)
		}
		if u.Base().TwoFactorEnabled {
			return SignInResult{RequiresTwoFactor: true}, u
		}
		return SignInResult{Succeeded: true}, u
	}
	if lockoutOnFailure {
		if err := s.Users.AccessFailed(ctx, u); err != nil {
			s.Users.logger().Warn("identity: failed to record access failure", "user", u.Base().ID, "err", err)
		}
		if s.Users.IsLockedOut(u) {
			return SignInResult{IsLockedOut: true}, u
		}
	}
	return SignInResult{}, u
}

// TwoFactorAuthenticatorSignIn completes a sign-in that required 2FA, using a
// TOTP code. Call after PasswordSignIn returned RequiresTwoFactor.
func (s *SignInManagerOf[T, PT]) TwoFactorAuthenticatorSignIn(ctx context.Context, u PT, code string) SignInResult {
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}
	}
	ok, err := s.Users.VerifyTwoFactorTOTP(ctx, u, code)
	if err == nil && ok {
		if err := s.Users.ResetAccessFailedCount(ctx, u); err != nil {
			s.Users.logger().Warn("identity: failed to reset access-failed count", "user", u.Base().ID, "err", err)
		}
		return SignInResult{Succeeded: true}
	}
	_ = s.Users.AccessFailed(ctx, u)
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}
	}
	return SignInResult{}
}

// TwoFactorPhoneSignIn completes a sign-in that required 2FA, using an SMS code
// previously delivered via SendPhoneToken.
func (s *SignInManagerOf[T, PT]) TwoFactorPhoneSignIn(ctx context.Context, u PT, code string) SignInResult {
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}
	}
	ok, err := s.Users.VerifyPhoneToken(ctx, u, code)
	if err == nil && ok {
		if err := s.Users.ResetAccessFailedCount(ctx, u); err != nil {
			s.Users.logger().Warn("identity: failed to reset access-failed count", "user", u.Base().ID, "err", err)
		}
		return SignInResult{Succeeded: true}
	}
	_ = s.Users.AccessFailed(ctx, u)
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}
	}
	return SignInResult{}
}

// ValidateSecurityStamp reloads the user by id and reports whether the supplied
// stamp still matches — i.e. the session/cookie is current and no credential
// change has revoked it. Returns the fresh user and true on a match; nil and
// false otherwise. Use it to revalidate long-lived cookie sessions (the JWT path
// already checks the stamp during token validation).
func (s *SignInManagerOf[T, PT]) ValidateSecurityStamp(ctx context.Context, userID, stamp string) (PT, bool) {
	u, err := s.Users.FindByID(ctx, userID)
	if err != nil || u == nil {
		return nil, false
	}
	if subtleConstEq(u.Base().SecurityStamp, stamp) {
		return u, true
	}
	return nil, false
}

// RefreshSignIn re-evaluates an existing session: it reloads the user, checks
// the security stamp is current and that the user may still sign in. On success
// it returns Succeeded with the fresh user — useful before re-issuing tokens.
func (s *SignInManagerOf[T, PT]) RefreshSignIn(ctx context.Context, userID, stamp string) (SignInResult, PT) {
	u, ok := s.ValidateSecurityStamp(ctx, userID, stamp)
	if !ok {
		return SignInResult{}, nil
	}
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}, u
	}
	if !s.CanSignIn(u) {
		return SignInResult{IsNotAllowed: true}, u
	}
	return SignInResult{Succeeded: true}, u
}

// TwoFactorRecoveryCodeSignIn completes 2FA using a one-time recovery code.
func (s *SignInManagerOf[T, PT]) TwoFactorRecoveryCodeSignIn(ctx context.Context, u PT, code string) SignInResult {
	if s.Users.IsLockedOut(u) {
		return SignInResult{IsLockedOut: true}
	}
	ok, err := s.Users.RedeemRecoveryCode(ctx, u, code)
	if err == nil && ok {
		if err := s.Users.ResetAccessFailedCount(ctx, u); err != nil {
			s.Users.logger().Warn("identity: failed to reset access-failed count", "user", u.Base().ID, "err", err)
		}
		return SignInResult{Succeeded: true}
	}
	return SignInResult{}
}
