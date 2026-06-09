package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Normalizer produces the canonical key used for lookups (uppercase invariant
// by default).
type Normalizer interface{ Normalize(s string) string }

type upperNormalizer struct{}

func (upperNormalizer) Normalize(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// UserManagerOf is the business-layer API for users.
// It is generic over a custom user type T (which must embed [User], satisfying
// [UserModel] via Base()). Use [UserManager] / [NewUserManager] for the built-in
// user, or [NewUserManagerOf] for an extended type with custom columns.
type UserManagerOf[T any, PT Ptr[T]] struct {
	Store      UserStore[T, PT]
	Hasher     PasswordHasher
	Options    Options
	Normalizer Normalizer
	// Tokens powers email-confirmation / password-reset helpers; nil until set
	// via WithTokenProvider.
	Tokens *DataTokenProvider
	// SMS delivers phone two-factor codes; nil until set via WithSMSSender.
	SMS SMSSender
}

// UserManager is the manager for the built-in [User] type.
type UserManager = UserManagerOf[User, *User]

// NewUserManager wires a manager for the built-in user with sensible defaults.
func NewUserManager(store DefaultUserStore, opts Options) *UserManager {
	return NewUserManagerOf[User](store, opts)
}

// NewUserManagerOf wires a manager for a custom user type T.
func NewUserManagerOf[T any, PT Ptr[T]](store UserStore[T, PT], opts Options) *UserManagerOf[T, PT] {
	return &UserManagerOf[T, PT]{
		Store:      store,
		Hasher:     NewPasswordHasher(),
		Options:    opts,
		Normalizer: upperNormalizer{},
	}
}

// Create persists a new user without a password (e.g. external login).
func (m *UserManagerOf[T, PT]) Create(ctx context.Context, u PT) error {
	if err := m.prepareForCreate(ctx, u); err != nil {
		return err
	}
	return m.Store.Create(ctx, u)
}

// CreateWithPassword validates the policy, hashes the password and persists the
// user.
func (m *UserManagerOf[T, PT]) CreateWithPassword(ctx context.Context, u PT, password string) error {
	if err := m.ValidatePassword(password); err != nil {
		return err
	}
	if err := m.prepareForCreate(ctx, u); err != nil {
		return err
	}
	b := u.Base()
	b.PasswordHash = m.Hasher.Hash(b, password)
	return m.Store.Create(ctx, u)
}

func (m *UserManagerOf[T, PT]) prepareForCreate(ctx context.Context, u PT) error {
	b := u.Base()
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	b.NormalizedUserName = m.Normalizer.Normalize(b.UserName)
	b.NormalizedEmail = m.Normalizer.Normalize(b.Email)
	b.SecurityStamp = newStamp()
	b.ConcurrencyStamp = uuid.NewString()
	b.LockoutEnabled = m.Options.Lockout.AllowedForNewUsers

	if existing, err := m.Store.FindByName(ctx, b.NormalizedUserName); err == nil && existing != nil {
		return ErrDuplicateUserName
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if m.Options.User.RequireUniqueEmail && b.Email != "" {
		if existing, err := m.Store.FindByEmail(ctx, b.NormalizedEmail); err == nil && existing != nil {
			return ErrDuplicateEmail
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// ValidatePassword enforces the configured PasswordOptions policy.
func (m *UserManagerOf[T, PT]) ValidatePassword(pw string) error {
	o := m.Options.Password
	if len([]rune(pw)) < o.RequiredLength {
		return ErrPasswordTooShort
	}
	var hasDigit, hasUpper, hasLower, hasNonAlpha bool
	for _, r := range pw {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			hasNonAlpha = true
		}
	}
	if o.RequireDigit && !hasDigit {
		return ErrPasswordRequiresDigit
	}
	if o.RequireUppercase && !hasUpper {
		return ErrPasswordRequiresUpper
	}
	if o.RequireLowercase && !hasLower {
		return ErrPasswordRequiresLower
	}
	if o.RequireNonAlphanumeric && !hasNonAlpha {
		return ErrPasswordRequiresNonAlpha
	}
	return nil
}

// CheckPassword verifies a plaintext password against the stored hash,
// upgrading the hash transparently when parameters are outdated.
func (m *UserManagerOf[T, PT]) CheckPassword(ctx context.Context, u PT, password string) bool {
	b := u.Base()
	if b.PasswordHash == "" {
		return false
	}
	ok, needsRehash := m.Hasher.Verify(b, b.PasswordHash, password)
	if !ok {
		return false
	}
	if needsRehash {
		b.PasswordHash = m.Hasher.Hash(b, password)
		_ = m.Store.Update(ctx, u)
	}
	return true
}

// ChangePassword verifies the current password then sets a new one.
func (m *UserManagerOf[T, PT]) ChangePassword(ctx context.Context, u PT, current, newPassword string) error {
	if !m.CheckPassword(ctx, u, current) {
		return ErrPasswordMismatch
	}
	if err := m.ValidatePassword(newPassword); err != nil {
		return err
	}
	b := u.Base()
	b.PasswordHash = m.Hasher.Hash(b, newPassword)
	b.SecurityStamp = newStamp() // invalidate existing tokens/sessions
	return m.Store.Update(ctx, u)
}

func (m *UserManagerOf[T, PT]) FindByID(ctx context.Context, id string) (PT, error) {
	return m.Store.FindByID(ctx, id)
}

func (m *UserManagerOf[T, PT]) FindByName(ctx context.Context, userName string) (PT, error) {
	return m.Store.FindByName(ctx, m.Normalizer.Normalize(userName))
}

func (m *UserManagerOf[T, PT]) FindByEmail(ctx context.Context, email string) (PT, error) {
	return m.Store.FindByEmail(ctx, m.Normalizer.Normalize(email))
}

// --- Roles ---

func (m *UserManagerOf[T, PT]) AddToRole(ctx context.Context, u PT, role string) error {
	return m.Store.AddToRole(ctx, u, m.Normalizer.Normalize(role))
}

func (m *UserManagerOf[T, PT]) RemoveFromRole(ctx context.Context, u PT, role string) error {
	return m.Store.RemoveFromRole(ctx, u, m.Normalizer.Normalize(role))
}

func (m *UserManagerOf[T, PT]) GetRoles(ctx context.Context, u PT) ([]string, error) {
	return m.Store.GetRoles(ctx, u)
}

func (m *UserManagerOf[T, PT]) IsInRole(ctx context.Context, u PT, role string) (bool, error) {
	return m.Store.IsInRole(ctx, u, m.Normalizer.Normalize(role))
}

// --- Claims ---

func (m *UserManagerOf[T, PT]) GetClaims(ctx context.Context, u PT) ([]Claim, error) {
	return m.Store.GetClaims(ctx, u)
}

func (m *UserManagerOf[T, PT]) AddClaims(ctx context.Context, u PT, claims ...Claim) error {
	return m.Store.AddClaims(ctx, u, claims)
}

func (m *UserManagerOf[T, PT]) RemoveClaims(ctx context.Context, u PT, claims ...Claim) error {
	return m.Store.RemoveClaims(ctx, u, claims)
}

// --- Lockout ---

// IsLockedOut reports whether the user is currently locked out.
func (m *UserManagerOf[T, PT]) IsLockedOut(u PT) bool {
	b := u.Base()
	if !b.LockoutEnabled || b.LockoutEnd == nil {
		return false
	}
	return b.LockoutEnd.After(time.Now())
}

// AccessFailed increments the failure counter and locks the account once it
// reaches MaxFailedAccessAttempts.
func (m *UserManagerOf[T, PT]) AccessFailed(ctx context.Context, u PT) error {
	b := u.Base()
	b.AccessFailedCount++
	if b.AccessFailedCount >= m.Options.Lockout.MaxFailedAccessAttempts {
		end := time.Now().Add(m.Options.Lockout.DefaultLockoutDuration)
		b.LockoutEnd = &end
		b.AccessFailedCount = 0
	}
	return m.Store.Update(ctx, u)
}

// ResetAccessFailedCount clears the failure counter after a successful sign-in.
func (m *UserManagerOf[T, PT]) ResetAccessFailedCount(ctx context.Context, u PT) error {
	b := u.Base()
	if b.AccessFailedCount == 0 {
		return nil
	}
	b.AccessFailedCount = 0
	return m.Store.Update(ctx, u)
}

// NewConcurrencyStamp returns a fresh optimistic-concurrency token. Stores call
// it when rotating ConcurrencyStamp on a successful Update.
func NewConcurrencyStamp() string { return uuid.NewString() }

func newStamp() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random stamp: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
