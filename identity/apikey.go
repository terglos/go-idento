package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

// APIKeyHasher hashes an API-key secret for storage and lookup. API keys are
// high-entropy random secrets, so a single fast hash (SHA-256) is the right
// choice — PBKDF2 would only waste CPU on the auth hot path. It must be
// deterministic; the stored hash is compared in constant time on verify.
type APIKeyHasher func(plaintext string) string

// sha256Hex is the default APIKeyHasher: hex-encoded SHA-256 of the full key.
func sha256Hex(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// APIKeyOptions parameterizes a new key.
type APIKeyOptions struct {
	Name      string     // human label
	ExpiresAt *time.Time // nil = never expires
	Scopes    []string   // optional subset of the owner's authority
}

// APIKeyManagerOf issues and verifies opaque API keys (see [APIKey]) for user
// type T. It is independent of the JWT/refresh-token lifecycle. Use
// [APIKeyManager] / [NewAPIKeyManager] for the built-in user.
type APIKeyManagerOf[T any, PT Ptr[T]] struct {
	Store  APIKeyStore
	Users  *UserManagerOf[T, PT]
	Hasher APIKeyHasher
	// Prefix is prepended to every generated key (e.g. "myapp-"); empty by default.
	Prefix string
	// PrefixLen is how many leading characters of the generated key are stored as
	// the display Prefix (Stripe/GitHub style); the secret itself is never stored.
	PrefixLen int
}

// APIKeyManager is the API-key manager for the built-in [User] type.
type APIKeyManager = APIKeyManagerOf[User, *User]

// NewAPIKeyManager wires an API-key manager for the built-in user with SHA-256
// hashing and a 12-char display prefix.
func NewAPIKeyManager(store APIKeyStore, users *UserManager) *APIKeyManager {
	return NewAPIKeyManagerOf[User](store, users)
}

// NewAPIKeyManagerOf wires an API-key manager for a custom user type T.
func NewAPIKeyManagerOf[T any, PT Ptr[T]](store APIKeyStore, users *UserManagerOf[T, PT]) *APIKeyManagerOf[T, PT] {
	return &APIKeyManagerOf[T, PT]{Store: store, Users: users, Hasher: sha256Hex, PrefixLen: 12}
}

// WithAPIKeyHasher overrides the hash function (e.g. to match an existing system
// for zero-reissue migration). Returns the manager for chaining.
func (m *APIKeyManagerOf[T, PT]) WithAPIKeyHasher(h APIKeyHasher) *APIKeyManagerOf[T, PT] {
	if h != nil {
		m.Hasher = h
	}
	return m
}

// WithAPIKeyPrefix sets the prefix prepended to generated keys. Returns the
// manager for chaining.
func (m *APIKeyManagerOf[T, PT]) WithAPIKeyPrefix(prefix string) *APIKeyManagerOf[T, PT] {
	m.Prefix = prefix
	return m
}

// CreateAPIKey mints a new key for the user. The plaintext secret is returned
// ONCE (never stored); only its hash and a display prefix are persisted.
func (m *APIKeyManagerOf[T, PT]) CreateAPIKey(ctx context.Context, user PT, opts APIKeyOptions) (plaintext string, key *APIKey, err error) {
	secret := m.Prefix + randomToken() // randomToken: 256-bit base64url, high entropy
	k := &APIKey{
		ID:        uuid.NewString(),
		UserID:    user.Base().ID,
		Name:      opts.Name,
		Prefix:    displayPrefix(secret, m.PrefixLen),
		KeyHash:   m.Hasher(secret),
		Scopes:    Scopes(opts.Scopes),
		ExpiresAt: opts.ExpiresAt,
		CreatedAt: nowFn(),
	}
	if err := m.Store.CreateAPIKey(ctx, k); err != nil {
		return "", nil, err
	}
	return secret, k, nil
}

// ImportAPIKey inserts a key from a PRECOMPUTED hash (admin/migration path), so
// keys already issued by another system stay valid with no reissue — point the
// manager's hasher at the same function and import the existing hashes.
func (m *APIKeyManagerOf[T, PT]) ImportAPIKey(ctx context.Context, userID, name, prefix, keyHash string, expiresAt *time.Time, scopes ...string) (*APIKey, error) {
	k := &APIKey{
		ID:        uuid.NewString(),
		UserID:    userID,
		Name:      name,
		Prefix:    prefix,
		KeyHash:   keyHash,
		Scopes:    Scopes(scopes),
		ExpiresAt: expiresAt,
		CreatedAt: nowFn(),
	}
	if err := m.Store.CreateAPIKey(ctx, k); err != nil {
		return nil, err
	}
	return k, nil
}

// VerifyAPIKey resolves a plaintext key to its owning user. It returns
// [ErrInvalidAPIKey] for an unknown, revoked, expired key or a locked-out owner
// (caller → 401), and a wrapped store error for an infrastructure failure
// (caller → 503), so the two are distinguishable. LastUsedAt is updated
// best-effort. The returned user carries the roles/claims the caller authorizes
// on.
func (m *APIKeyManagerOf[T, PT]) VerifyAPIKey(ctx context.Context, plaintext string) (PT, *APIKey, error) {
	if plaintext == "" {
		return nil, nil, ErrInvalidAPIKey
	}
	k, err := m.Store.GetActiveAPIKeyByHash(ctx, m.Hasher(plaintext))
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrInvalidAPIKey
	}
	if err != nil {
		return nil, nil, err // store/infra failure — distinct from invalid
	}
	// Defensive re-check (store already filters), so the contract holds even for
	// a store that doesn't filter server-side.
	now := nowFn()
	if k.RevokedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) {
		return nil, nil, ErrInvalidAPIKey
	}
	u, err := m.Users.FindByID(ctx, k.UserID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrInvalidAPIKey
	}
	if err != nil {
		return nil, nil, err
	}
	if m.Users.IsLockedOut(u) {
		return nil, nil, ErrInvalidAPIKey
	}
	if err := m.Store.TouchAPIKeyLastUsed(ctx, k.ID); err != nil {
		m.Users.logger().Warn("identity: failed to touch api key last_used", "key", k.ID, "err", err)
	}
	return u, k, nil
}

// RevokeAPIKey permanently invalidates a key by id.
func (m *APIKeyManagerOf[T, PT]) RevokeAPIKey(ctx context.Context, id string) error {
	return m.Store.RevokeAPIKey(ctx, id)
}

// ListAPIKeys returns the user's keys (metadata only — never the secret).
func (m *APIKeyManagerOf[T, PT]) ListAPIKeys(ctx context.Context, user PT) ([]APIKey, error) {
	return m.Store.ListAPIKeysByUser(ctx, user.Base().ID)
}

// displayPrefix returns the leading n chars of the secret for UI display. It
// never returns the whole secret (guards against a short n vs secret length).
func displayPrefix(secret string, n int) string {
	if n <= 0 {
		n = 8
	}
	if n > len(secret) {
		n = len(secret)
	}
	return secret[:n]
}
