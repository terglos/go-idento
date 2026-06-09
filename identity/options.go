package identity

import "time"

// Options aggregates the configuration knobs (password, lockout, user, sign-in).
type Options struct {
	Password PasswordOptions
	Lockout  LockoutOptions
	User     UserOptions
	SignIn   SignInOptions
}

// PasswordOptions is the password strength policy.
type PasswordOptions struct {
	RequiredLength         int
	RequireDigit           bool
	RequireLowercase       bool
	RequireUppercase       bool
	RequireNonAlphanumeric bool
	RequiredUniqueChars    int
}

// LockoutOptions is the account-lockout policy.
type LockoutOptions struct {
	AllowedForNewUsers      bool
	MaxFailedAccessAttempts int
	DefaultLockoutDuration  time.Duration
}

// UserOptions is the user-validation policy.
type UserOptions struct {
	RequireUniqueEmail        bool
	AllowedUserNameCharacters string
}

// SignInOptions is the sign-in confirmation policy.
type SignInOptions struct {
	RequireConfirmedEmail       bool
	RequireConfirmedPhoneNumber bool
}

// DefaultOptions returns sensible, secure defaults.
func DefaultOptions() Options {
	return Options{
		Password: PasswordOptions{
			RequiredLength:         6,
			RequireDigit:           true,
			RequireLowercase:       true,
			RequireUppercase:       true,
			RequireNonAlphanumeric: true,
			RequiredUniqueChars:    1,
		},
		Lockout: LockoutOptions{
			AllowedForNewUsers:      true,
			MaxFailedAccessAttempts: 5,
			DefaultLockoutDuration:  5 * time.Minute,
		},
		User: UserOptions{
			RequireUniqueEmail:        true,
			AllowedUserNameCharacters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+",
		},
		SignIn: SignInOptions{
			RequireConfirmedEmail: false,
		},
	}
}
