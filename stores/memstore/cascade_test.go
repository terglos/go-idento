package memstore_test

import (
	"context"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestDeleteCascade verifies that deleting a user also removes its roles,
// claims, tokens and external logins from the in-memory store.
func TestDeleteCascade(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	if err := h.roles.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := mustUser(t, h, "mallory", "Abcdef1!")

	if err := h.users.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := h.users.AddClaims(ctx, u, identity.Claim{Type: "dept", Value: "eng"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if err := h.users.AddLogin(ctx, u, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-9", ProviderDisplayName: "GitHub"}); err != nil {
		t.Fatalf("add login: %v", err)
	}
	if _, err := h.users.GenerateRecoveryCodes(ctx, u, 3); err != nil {
		t.Fatalf("recovery codes (token write): %v", err)
	}

	if err := h.users.Delete(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// The user is gone.
	if got, _ := h.users.FindByID(ctx, u.ID); got != nil {
		t.Fatal("user should be deleted")
	}
	// Satellite rows are gone: roles, claims, login.
	if roles, _ := h.users.GetRoles(ctx, u); len(roles) != 0 {
		t.Fatalf("roles should cascade-delete, got %v", roles)
	}
	if claims, _ := h.users.GetClaims(ctx, u); len(claims) != 0 {
		t.Fatalf("claims should cascade-delete, got %v", claims)
	}
	if logins, _ := h.users.GetLogins(ctx, u); len(logins) != 0 {
		t.Fatalf("logins should cascade-delete, got %v", logins)
	}
	if _, found := h.signIn.ExternalLoginSignIn(ctx, "GitHub", "gh-9"); found != nil {
		t.Fatal("external login lookup should fail after cascade delete")
	}
}
