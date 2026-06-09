package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestStoreContractParity pins the cross-store behavioral contract documented on
// the store interfaces (same assertions exist for the SQL stores).
func TestStoreContractParity(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "pat", "Abcdef1!")

	// AddToRole on a missing role -> ErrRoleNotFound.
	if err := h.users.AddToRole(ctx, u, "ghost"); !errors.Is(err, identity.ErrRoleNotFound) {
		t.Fatalf("AddToRole(missing role) must be ErrRoleNotFound, got %v", err)
	}
	// RemoveFromRole on a missing role -> no-op.
	if err := h.users.RemoveFromRole(ctx, u, "ghost"); err != nil {
		t.Fatalf("RemoveFromRole(missing role) must be a no-op, got %v", err)
	}

	// FindByEmail("") must not match users created without an email.
	noEmail := &identity.User{UserName: "no_email_user"}
	if err := h.users.Create(ctx, noEmail); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, err := h.users.FindByEmail(ctx, ""); got != nil || !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("FindByEmail(\"\") must be ErrNotFound, got user=%v err=%v", got, err)
	}

	// AddLogin must not silently re-bind an existing (provider, key).
	login := identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-dup"}
	if err := h.users.AddLogin(ctx, u, login); err != nil {
		t.Fatalf("first AddLogin: %v", err)
	}
	other := mustUser(t, h, "mallet", "Abcdef1!")
	if err := h.users.AddLogin(ctx, other, login); !errors.Is(err, identity.ErrLoginAlreadyUsed) {
		t.Fatalf("duplicate AddLogin must fail with ErrLoginAlreadyUsed, got %v", err)
	}
	// The original association is untouched.
	if found, _ := h.users.FindByLogin(ctx, "GitHub", "gh-dup"); found == nil || found.ID != u.ID {
		t.Fatal("duplicate AddLogin must not re-bind the login to another user")
	}
}
