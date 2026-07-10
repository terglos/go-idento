package identity

import (
	"context"
	"time"
)

// Ptr constrains a pointer-to-T that is also a UserModel — the standard Go
// pattern for "construct a new T" inside generic stores while requiring T to
// carry the identity fields.
type Ptr[T any] interface {
	*T
	UserModel
}

// The user store is split into focused, composable interfaces (interface
// segregation): a store may be built from just the slices it needs, and adding
// a capability does not force every implementer to change. [UserStore] composes
// all of them and is what the bundled stores implement.

// UserCrudStore is the minimum: create, update (optimistic concurrency), delete
// and lookups.
type UserCrudStore[T any, PT Ptr[T]] interface {
	Create(ctx context.Context, u PT) error
	// Update persists changes with optimistic concurrency: it matches the row by
	// id AND the user's current ConcurrencyStamp, rotates the stamp on success
	// (updating u in place), and returns [ErrConcurrencyFailure] if no row
	// matched (a concurrent write won), or [ErrNotFound] if the user is gone.
	Update(ctx context.Context, u PT) error
	Delete(ctx context.Context, u PT) error

	FindByID(ctx context.Context, id string) (PT, error)
	FindByName(ctx context.Context, normalizedUserName string) (PT, error)
	// FindByEmail looks up by normalized email. An empty normalizedEmail returns
	// ErrNotFound (users without an email store '' — it must never match).
	FindByEmail(ctx context.Context, normalizedEmail string) (PT, error)
}

// UserRoleStore handles a user's role memberships (role names are normalized).
type UserRoleStore[T any, PT Ptr[T]] interface {
	// AddToRole adds the membership. It returns ErrRoleNotFound when the role
	// does not exist and is idempotent when the user is already a member.
	AddToRole(ctx context.Context, u PT, normalizedRoleName string) error
	// RemoveFromRole is a no-op (nil) when the role does not exist or the user
	// is not a member.
	RemoveFromRole(ctx context.Context, u PT, normalizedRoleName string) error
	GetRoles(ctx context.Context, u PT) ([]string, error)
	IsInRole(ctx context.Context, u PT, normalizedRoleName string) (bool, error)
	// GetUsersInRole returns every user that belongs to the role. An unknown
	// role yields an empty slice (not an error).
	GetUsersInRole(ctx context.Context, normalizedRoleName string) ([]PT, error)
}

// UserClaimStore handles a user's claims.
type UserClaimStore[T any, PT Ptr[T]] interface {
	GetClaims(ctx context.Context, u PT) ([]Claim, error)
	AddClaims(ctx context.Context, u PT, claims []Claim) error
	RemoveClaims(ctx context.Context, u PT, claims []Claim) error
	// GetUsersForClaim returns every user carrying the exact claim type/value.
	GetUsersForClaim(ctx context.Context, claimType, claimValue string) ([]PT, error)
}

// UserTokenStore handles per-user tokens (refresh tokens, recovery codes, etc.).
type UserTokenStore[T any, PT Ptr[T]] interface {
	GetToken(ctx context.Context, u PT, loginProvider, name string) (string, error)
	SetToken(ctx context.Context, u PT, loginProvider, name, value string) error
	RemoveToken(ctx context.Context, u PT, loginProvider, name string) error
}

// UserLoginStore handles external (OAuth/OIDC) login associations.
type UserLoginStore[T any, PT Ptr[T]] interface {
	// AddLogin associates the external login. (provider, key) is unique across
	// users: re-adding an already-associated login errors (ErrLoginAlreadyUsed
	// in the in-memory store; a driver unique-violation in the SQL stores).
	AddLogin(ctx context.Context, u PT, login UserLoginInfo) error
	RemoveLogin(ctx context.Context, u PT, loginProvider, providerKey string) error
	GetLogins(ctx context.Context, u PT) ([]UserLoginInfo, error)
	FindByLogin(ctx context.Context, loginProvider, providerKey string) (PT, error)
}

// UserStore is the full user store: every capability composed. It is generic
// over the user type so stores can persist custom columns; the built-in
// [DefaultUserStore] alias fixes it to the plain *User and is what the
// gorm/pgx/in-memory stores implement.
type UserStore[T any, PT Ptr[T]] interface {
	UserCrudStore[T, PT]
	UserRoleStore[T, PT]
	UserClaimStore[T, PT]
	UserTokenStore[T, PT]
	UserLoginStore[T, PT]
}

// DefaultUserStore is the user store for the built-in [User] type — what the
// gorm/pgx/in-memory stores satisfy out of the box.
type DefaultUserStore = UserStore[User, *User]

// ListFilter parameterizes a paged user listing. Search matches the user name
// or email case-insensitively (empty = all). Limit/Offset page the result.
type ListFilter struct {
	Search string
	Limit  int
	Offset int
}

// Clamp applies sane bounds (default page 50, max 500) and is called by the
// manager before delegating to the store.
func (f ListFilter) Clamp() ListFilter {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return f
}

// UserLister is an OPTIONAL capability: paged enumeration of users. Stores
// implement it to support admin listings; the manager's ListUsers returns
// [ErrListNotSupported] when the configured store does not. It returns the page
// plus the total count of matching users (for pagination UIs).
type UserLister[T any, PT Ptr[T]] interface {
	ListUsers(ctx context.Context, f ListFilter) (page []PT, total int64, err error)
}

// APIKeyStore persists opaque API keys (see [APIKey]). It is a small, composable
// capability the bundled stores implement; wire it into an [APIKeyManagerOf].
// Method names carry the APIKey suffix so a single store type can implement both
// this and [UserStore] without collisions.
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, k *APIKey) error
	// GetActiveAPIKeyByHash returns the key with keyHash that is neither revoked
	// nor past ExpiresAt; it returns [ErrNotFound] when absent/revoked/expired
	// (so callers can't distinguish those — all map to an invalid key) and a real
	// error only on store/infra failure.
	GetActiveAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, id string) error
	// TouchAPIKeyLastUsed updates LastUsedAt; callers treat failure as non-fatal.
	TouchAPIKeyLastUsed(ctx context.Context, id string) error
}

// RefreshTokenStore persists refresh sessions (see [RefreshToken]) — one row per
// concurrent device/browser session, the industry model. Wire it into a
// TokenService with [TokenServiceOf.WithSessionStore] to enable multi-session
// refresh tokens; without it the service keeps the legacy single-slot behavior.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, rt *RefreshToken) error
	// GetRefreshTokenBySession returns the session row or [ErrNotFound]; the
	// caller (token service) does the constant-time hash comparison.
	GetRefreshTokenBySession(ctx context.Context, sessionID string) (*RefreshToken, error)
	// UpdateRefreshToken persists a rotation: same SessionID, new TokenHash,
	// re-stamped ExpiresAt/LastUsedAt.
	UpdateRefreshToken(ctx context.Context, rt *RefreshToken) error
	// DeleteRefreshToken revokes one session; deleting a missing session is a no-op.
	DeleteRefreshToken(ctx context.Context, sessionID string) error
	// DeleteUserRefreshTokens revokes every session of a user (global sign-out).
	DeleteUserRefreshTokens(ctx context.Context, userID string) (int64, error)
	// DeleteExpiredRefreshTokens is the GC sweep for dormant sessions.
	DeleteExpiredRefreshTokens(ctx context.Context, before time.Time) (int64, error)
	// ListUserRefreshTokens returns a user's active sessions (metadata only).
	ListUserRefreshTokens(ctx context.Context, userID string) ([]RefreshToken, error)
}

// AnonymousPurger is an OPTIONAL capability: bulk-delete guest (anonymous) users
// created before a cutoff, cascading their satellite rows — the GC sweep behind
// [UserManagerOf.PurgeAnonymousUsers]. Stores that don't implement it cause the
// manager to return [ErrPurgeNotSupported].
type AnonymousPurger[T any, PT Ptr[T]] interface {
	PurgeAnonymousUsers(ctx context.Context, createdBefore time.Time) (deleted int64, err error)
}

// UserLoginInfo describes an external (OAuth/OIDC) login association.
type UserLoginInfo struct {
	LoginProvider       string
	ProviderKey         string
	ProviderDisplayName string
}

// RoleStore abstracts role and role-claim persistence.
type RoleStore interface {
	Create(ctx context.Context, r *Role) error
	// Update persists role changes under optimistic concurrency: it must match
	// on the incoming ConcurrencyStamp, rotate it on success, and return
	// ErrConcurrencyFailure on a stale write (or ErrNotFound if the row is gone).
	Update(ctx context.Context, r *Role) error
	Delete(ctx context.Context, r *Role) error

	FindByID(ctx context.Context, id string) (*Role, error)
	FindByName(ctx context.Context, normalizedName string) (*Role, error)

	GetClaims(ctx context.Context, r *Role) ([]Claim, error)
	AddClaim(ctx context.Context, r *Role, claim Claim) error
	RemoveClaim(ctx context.Context, r *Role, claim Claim) error
}
