package identity

import "time"

// Options aggregates the configuration knobs, mirroring IdentityOptions in .NET.
type Options struct {
	Password PasswordOptions
	Lockout  LockoutOptions
	User     UserOptions
	SignIn   SignInOptions
}

// PasswordOptions mirrors PasswordOptions: the password strength policy.
type PasswordOptions struct {
	RequiredLength         int
	RequireDigit           bool
	RequireLowercase       bool
	RequireUppercase       bool
	RequireNonAlphanumeric bool
	RequiredUniqueChars    int
}

// LockoutOptions mirrors LockoutOptions.
type LockoutOptions struct {
	AllowedForNewUsers      bool
	MaxFailedAccessAttempts int
	DefaultLockoutDuration  time.Duration
}

// UserOptions mirrors UserOptions.
type UserOptions struct {
	RequireUniqueEmail        bool
	AllowedUserNameCharacters string
}

// SignInOptions mirrors SignInOptions.
type SignInOptions struct {
	RequireConfirmedEmail       bool
	RequireConfirmedPhoneNumber bool
}

// DefaultOptions returns the same defaults ASP.NET Core Identity ships with.
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
