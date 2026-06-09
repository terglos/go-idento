// Package identity is a batteries-included identity framework for Go: user/role
// management, password hashing, claims, lockout, two-factor and token
// generation, built on pluggable stores so the persistence layer can be swapped
// without touching the business logic in the managers.
package identity

import "time"

// User is the core user entity. The primary key is a UUID stored as a string.
type User struct {
	ID string `gorm:"primaryKey;type:varchar(36)" json:"id"`

	UserName           string `gorm:"type:varchar(256)" json:"userName"`
	NormalizedUserName string `gorm:"type:varchar(256);uniqueIndex" json:"normalizedUserName"`

	Email           string `gorm:"type:varchar(256)" json:"email"`
	NormalizedEmail string `gorm:"type:varchar(256);index" json:"normalizedEmail"`
	EmailConfirmed  bool   `json:"emailConfirmed"`

	// PasswordHash holds the encoded PBKDF2 hash (see PasswordHasher).
	PasswordHash string `gorm:"type:varchar(256)" json:"-"`

	// SecurityStamp is regenerated whenever credentials change; embedding it in
	// issued tokens lets us revoke them by bumping the stamp.
	SecurityStamp string `gorm:"type:varchar(64)" json:"-"`

	// ConcurrencyStamp is a per-write token reserved for optimistic-concurrency
	// checks. It is generated and persisted, but the bundled stores do not yet
	// enforce it on update (planned). Do not rely on it for lost-update
	// protection today.
	ConcurrencyStamp string `gorm:"type:varchar(64)" json:"-"`

	PhoneNumber          string `gorm:"type:varchar(32)" json:"phoneNumber"`
	PhoneNumberConfirmed bool   `json:"phoneNumberConfirmed"`

	TwoFactorEnabled bool `json:"twoFactorEnabled"`

	LockoutEnd        *time.Time `json:"lockoutEnd"`
	LockoutEnabled    bool       `json:"lockoutEnabled"`
	AccessFailedCount int        `json:"accessFailedCount"`

	// Attributes is an optional bag of custom key/value data persisted as JSON
	// (Option C in docs/design/extending-user-and-migrations.md). Use it for
	// flexible, schema-less metadata; for first-class typed columns prefer an
	// extension table or the generic UserManagerOf[T].
	Attributes Attributes `gorm:"serializer:json;type:text" json:"attributes,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Attributes is a JSON-serialized string map for ad-hoc user metadata.
type Attributes map[string]string

// GetAttribute returns a custom attribute and whether it was present.
func (u *User) GetAttribute(key string) (string, bool) {
	if u.Attributes == nil {
		return "", false
	}
	v, ok := u.Attributes[key]
	return v, ok
}

// SetAttribute sets a custom attribute, allocating the map on first use.
func (u *User) SetAttribute(key, value string) {
	if u.Attributes == nil {
		u.Attributes = Attributes{}
	}
	u.Attributes[key] = value
}

func (User) TableName() string { return "identity_users" }

// Role is a named role for role-based access control.
type Role struct {
	ID               string `gorm:"primaryKey;type:varchar(36)" json:"id"`
	Name             string `gorm:"type:varchar(256)" json:"name"`
	NormalizedName   string `gorm:"type:varchar(256);uniqueIndex" json:"normalizedName"`
	ConcurrencyStamp string `gorm:"type:varchar(64)" json:"-"`
}

func (Role) TableName() string { return "identity_roles" }

// UserRole is the user-to-role join entity with a composite key.
type UserRole struct {
	UserID string `gorm:"primaryKey;type:varchar(36)" json:"userId"`
	RoleID string `gorm:"primaryKey;type:varchar(36)" json:"roleId"`
}

func (UserRole) TableName() string { return "identity_user_roles" }

// UserClaim is a claim attached to a user.
type UserClaim struct {
	ID         int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID     string `gorm:"type:varchar(36);index" json:"userId"`
	ClaimType  string `gorm:"type:varchar(256)" json:"claimType"`
	ClaimValue string `gorm:"type:varchar(256)" json:"claimValue"`
}

func (UserClaim) TableName() string { return "identity_user_claims" }

// RoleClaim is a claim attached to a role.
type RoleClaim struct {
	ID         int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	RoleID     string `gorm:"type:varchar(36);index" json:"roleId"`
	ClaimType  string `gorm:"type:varchar(256)" json:"claimType"`
	ClaimValue string `gorm:"type:varchar(256)" json:"claimValue"`
}

func (RoleClaim) TableName() string { return "identity_role_claims" }

// UserLogin is an external/social (OAuth/OIDC) login association.
type UserLogin struct {
	LoginProvider       string `gorm:"primaryKey;type:varchar(128)" json:"loginProvider"`
	ProviderKey         string `gorm:"primaryKey;type:varchar(128)" json:"providerKey"`
	ProviderDisplayName string `gorm:"type:varchar(128)" json:"providerDisplayName"`
	UserID              string `gorm:"type:varchar(36);index" json:"userId"`
}

func (UserLogin) TableName() string { return "identity_user_logins" }

// UserToken stores per-user tokens (refresh tokens, 2FA recovery codes, etc.).
type UserToken struct {
	UserID        string `gorm:"primaryKey;type:varchar(36)" json:"userId"`
	LoginProvider string `gorm:"primaryKey;type:varchar(128)" json:"loginProvider"`
	Name          string `gorm:"primaryKey;type:varchar(128)" json:"name"`
	Value         string `gorm:"type:text" json:"value"`
}

func (UserToken) TableName() string { return "identity_user_tokens" }

// Claim is a type/value pair attached to a user or role.
type Claim struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// UserModel is the contract a custom user type must satisfy to be managed by
// the generic UserManagerOf[T]. A custom type embeds [User] and gets Base() for
// free via method promotion, so the managers can read/write the standard
// identity fields while the store persists the whole (extended) row.
//
//	type AppUser struct {
//	    identity.User        // embeds -> Base() promoted
//	    TenantID string
//	}
type UserModel interface {
	// Base returns the embedded identity fields the managers operate on.
	Base() *User
}

// Base satisfies [UserModel] for the built-in user (returns itself), and for any
// type embedding User via method promotion.
func (u *User) Base() *User { return u }

// Ensure the built-in type is a valid model.
var _ UserModel = (*User)(nil)
