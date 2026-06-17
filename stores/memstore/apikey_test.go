package memstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func newAPIKeyManager(t *testing.T) (*identity.APIKeyManager, *identity.UserManager, *memstore.Store) {
	t.Helper()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	km := identity.NewAPIKeyManager(st.APIKeys(), um)
	return km, um, st
}

// TestAPIKeyLifecycle covers the client's acceptance criteria: create returns
// the plaintext once (only hash+prefix persisted), verify resolves the owner,
// non-expiring keys work, expiry+revocation reject, list shows metadata not the
// secret, last_used is updated.
func TestAPIKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	km, um, _ := newAPIKeyManager(t)
	u := mustUser(t, &harness{users: um}, "svc", "Abcdef1!")

	// Create → plaintext returned once; never stored.
	secret, key, err := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "POS terminal"})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if secret == "" || key.KeyHash == secret || key.Prefix == secret {
		t.Fatal("secret must not be stored as hash/prefix")
	}
	if key.ExpiresAt != nil {
		t.Fatal("default key should never expire")
	}

	// Verify resolves the owning user.
	got, vk, err := km.VerifyAPIKey(ctx, secret)
	if err != nil || got == nil || got.ID != u.ID || vk.ID != key.ID {
		t.Fatalf("VerifyAPIKey should resolve owner: u=%v err=%v", got, err)
	}
	// last_used updated.
	keys, _ := km.ListAPIKeys(ctx, u)
	if len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("list should show 1 key with last_used set: %+v", keys)
	}
	if keys[0].KeyHash != "" && keys[0].KeyHash == secret {
		t.Fatal("listed key must never expose the secret")
	}

	// Wrong secret → invalid.
	if _, _, err := km.VerifyAPIKey(ctx, "nope"); !errors.Is(err, identity.ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}

	// Revoke → invalid.
	if err := km.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, _, err := km.VerifyAPIKey(ctx, secret); !errors.Is(err, identity.ErrInvalidAPIKey) {
		t.Fatalf("revoked key must be invalid, got %v", err)
	}
}

func TestAPIKeyExpiry(t *testing.T) {
	ctx := context.Background()
	km, um, _ := newAPIKeyManager(t)
	u := mustUser(t, &harness{users: um}, "svc2", "Abcdef1!")

	past := time.Now().Add(-time.Hour)
	secret, _, err := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "expired", ExpiresAt: &past})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := km.VerifyAPIKey(ctx, secret); !errors.Is(err, identity.ErrInvalidAPIKey) {
		t.Fatalf("expired key must be invalid, got %v", err)
	}

	future := time.Now().Add(time.Hour)
	secret2, _, _ := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "valid", ExpiresAt: &future})
	if _, _, err := km.VerifyAPIKey(ctx, secret2); err != nil {
		t.Fatalf("unexpired key should verify: %v", err)
	}
}

// TestAPIKeyImportAndCustomHasher covers the zero-reissue migration path:
// a custom hasher + ImportAPIKey of a precomputed hash keeps an existing key valid.
func TestAPIKeyImportAndCustomHasher(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	// A deterministic custom hasher (simulating the client's existing scheme).
	km := identity.NewAPIKeyManager(st.APIKeys(), um).
		WithAPIKeyHasher(func(s string) string { return "h:" + s }).
		WithAPIKeyPrefix("myapp-")
	u := mustUser(t, &harness{users: um}, "svc3", "Abcdef1!")

	// Simulate an already-issued key from the old system.
	existingPlaintext := "myapp-EXISTINGKEY123"
	existingHash := "h:" + existingPlaintext // what the old system stored
	if _, err := km.ImportAPIKey(ctx, u.ID, "legacy", "myapp-EXIST", existingHash, nil); err != nil {
		t.Fatalf("ImportAPIKey: %v", err)
	}
	// The existing key keeps working with zero reissue.
	got, _, err := km.VerifyAPIKey(ctx, existingPlaintext)
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("imported key should verify: u=%v err=%v", got, err)
	}

	// A freshly created key uses the configured prefix.
	secret, key, _ := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "new"})
	if key.Prefix == "" || secret[:6] != "myapp-" {
		t.Fatalf("generated key should carry the configured prefix: %q", secret)
	}
}

// TestAPIKeyLockedOutOwner: a locked-out owner's key is rejected.
func TestAPIKeyLockedOutOwner(t *testing.T) {
	ctx := context.Background()
	km, um, _ := newAPIKeyManager(t)
	u := mustUser(t, &harness{users: um}, "svc4", "Abcdef1!")
	secret, _, _ := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "k"})

	// Lock the user out.
	for i := 0; i < 5; i++ {
		_ = um.AccessFailed(ctx, u)
	}
	if !um.IsLockedOut(u) {
		t.Fatal("precondition: user should be locked out")
	}
	if _, _, err := km.VerifyAPIKey(ctx, secret); !errors.Is(err, identity.ErrInvalidAPIKey) {
		t.Fatalf("locked-out owner's key must be rejected, got %v", err)
	}
}
