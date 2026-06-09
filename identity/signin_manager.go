package identity

import "context"

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
