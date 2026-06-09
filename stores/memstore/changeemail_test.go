package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestChangeEmailUniqueness verifies ChangeEmail re-checks RequireUniqueEmail at
// apply time: a token minted earlier must not let two accounts collide.
func TestChangeEmailUniqueness(t *testing.T) {
	ctx := context.Background()
	h := newHarness()

	a := mustUser(t, h, "alice", "Abcdef1!")
	_ = mustUser(t, h, "bob", "Abcdef1!") // owns bob@x.com

	// Alice gets a valid token to move to bob's address.
	tok := h.users.GenerateChangeEmailToken(a, "bob@x.com")
	if err := h.users.ChangeEmail(ctx, a, "bob@x.com", tok); !errors.Is(err, identity.ErrDuplicateEmail) {
		t.Fatalf("expected ErrDuplicateEmail, got %v", err)
	}
	// Alice keeps her original address.
	if a.Email != "alice@x.com" {
		t.Fatalf("email should be unchanged on collision, got %q", a.Email)
	}

	// Moving to a free address still works.
	tok2 := h.users.GenerateChangeEmailToken(a, "alice2@x.com")
	if err := h.users.ChangeEmail(ctx, a, "alice2@x.com", tok2); err != nil {
		t.Fatalf("change to free email should succeed: %v", err)
	}
	if a.Email != "alice2@x.com" || !a.EmailConfirmed {
		t.Fatalf("email should be updated and confirmed, got %q confirmed=%v", a.Email, a.EmailConfirmed)
	}
}
