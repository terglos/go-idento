package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestAddRemoveHasPassword covers the passwordless (external-login) -> local
// password lifecycle.
func TestAddRemoveHasPassword(t *testing.T) {
	ctx := context.Background()
	h := newHarness()

	// User created without a password (external-login style).
	u := &identity.User{UserName: "leo"}
	if err := h.users.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if h.users.HasPassword(u) {
		t.Fatal("new external user should have no password")
	}

	// AddPassword validates policy.
	if err := h.users.AddPassword(ctx, u, "weak"); err == nil {
		t.Fatal("weak password should be rejected")
	}
	// AddPassword sets it and rotates the stamp.
	oldStamp := u.SecurityStamp
	if err := h.users.AddPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("AddPassword: %v", err)
	}
	if !h.users.HasPassword(u) || u.SecurityStamp == oldStamp {
		t.Fatal("password should be set and stamp rotated")
	}
	if !h.users.CheckPassword(ctx, u, "Abcdef1!") {
		t.Fatal("added password should verify")
	}

	// AddPassword again is rejected.
	if err := h.users.AddPassword(ctx, u, "Another1!"); !errors.Is(err, identity.ErrPasswordAlreadySet) {
		t.Fatalf("expected ErrPasswordAlreadySet, got %v", err)
	}

	// RemovePassword clears it.
	if err := h.users.RemovePassword(ctx, u); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	if h.users.HasPassword(u) {
		t.Fatal("password should be removed")
	}
	if h.users.CheckPassword(ctx, u, "Abcdef1!") {
		t.Fatal("removed password must not verify")
	}
	// After removal, AddPassword works again.
	if err := h.users.AddPassword(ctx, u, "Newpass1!"); err != nil {
		t.Fatalf("AddPassword after removal: %v", err)
	}
}
