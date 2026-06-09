package identity

import "context"

// Ptr constrains a pointer-to-T that is also a UserModel — the standard Go
// pattern for "construct a new T" inside generic stores while requiring T to
// carry the identity fields.
type Ptr[T any] interface {
	*T
	UserModel
}

// UserStore abstracts user persistence: identity fields, passwords, email,
// roles, claims, lockout, tokens and external logins. It is generic over the
// user type so stores can persist custom columns; the built-in [DefaultUserStore] alias
// fixes it to the plain *User and is what the concrete stores implement.
type UserStore[T any, PT Ptr[T]] interface {
	Create(ctx context.Context, u PT) error
	// Update persists changes with optimistic concurrency: it matches the row by
	// id AND the user's current ConcurrencyStamp, rotates the stamp on success
	// (updating u in place), and returns [ErrConcurrencyFailure] if no row
	// matched (a concurrent write won), or [ErrNotFound] if the user is gone.
	Update(ctx context.Context, u PT) error
	Delete(ctx context.Context, u PT) error

	FindByID(ctx context.Context, id string) (PT, error)
	FindByName(ctx context.Context, normalizedUserName string) (PT, error)
	FindByEmail(ctx context.Context, normalizedEmail string) (PT, error)

	// Roles
	AddToRole(ctx context.Context, u PT, normalizedRoleName string) error
	RemoveFromRole(ctx context.Context, u PT, normalizedRoleName string) error
	GetRoles(ctx context.Context, u PT) ([]string, error)
	IsInRole(ctx context.Context, u PT, normalizedRoleName string) (bool, error)

	// Claims
	GetClaims(ctx context.Context, u PT) ([]Claim, error)
	AddClaims(ctx context.Context, u PT, claims []Claim) error
	RemoveClaims(ctx context.Context, u PT, claims []Claim) error

	// Tokens (refresh tokens, recovery codes, etc.)
	GetToken(ctx context.Context, u PT, loginProvider, name string) (string, error)
	SetToken(ctx context.Context, u PT, loginProvider, name, value string) error
	RemoveToken(ctx context.Context, u PT, loginProvider, name string) error

	// External logins (OAuth/OIDC)
	AddLogin(ctx context.Context, u PT, login UserLoginInfo) error
	RemoveLogin(ctx context.Context, u PT, loginProvider, providerKey string) error
	GetLogins(ctx context.Context, u PT) ([]UserLoginInfo, error)
	FindByLogin(ctx context.Context, loginProvider, providerKey string) (PT, error)
}

// DefaultUserStore is the user store for the built-in [User] type — what the
// gorm/pgx/in-memory stores satisfy out of the box.
type DefaultUserStore = UserStore[User, *User]

// UserLoginInfo describes an external (OAuth/OIDC) login association.
type UserLoginInfo struct {
	LoginProvider       string
	ProviderKey         string
	ProviderDisplayName string
}

// RoleStore abstracts role and role-claim persistence.
type RoleStore interface {
	Create(ctx context.Context, r *Role) error
	Update(ctx context.Context, r *Role) error
	Delete(ctx context.Context, r *Role) error

	FindByID(ctx context.Context, id string) (*Role, error)
	FindByName(ctx context.Context, normalizedName string) (*Role, error)

	GetClaims(ctx context.Context, r *Role) ([]Claim, error)
	AddClaim(ctx context.Context, r *Role, claim Claim) error
	RemoveClaim(ctx context.Context, r *Role, claim Claim) error
}
