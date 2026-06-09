package memstore_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestGetUsersInRoleAndForClaim covers the reverse-query API (users by role,
// users by claim).
func TestGetUsersInRoleAndForClaim(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	if err := h.roles.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	alice := mustUser(t, h, "alice", "Abcdef1!")
	bob := mustUser(t, h, "bob", "Abcdef1!")
	_ = mustUser(t, h, "carol", "Abcdef1!") // no role, no claim

	if err := h.users.AddToRole(ctx, alice, "Admin"); err != nil {
		t.Fatalf("add alice: %v", err)
	}
	if err := h.users.AddToRole(ctx, bob, "Admin"); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	if err := h.users.AddClaims(ctx, alice, identity.Claim{Type: "tenant", Value: "acme"}); err != nil {
		t.Fatalf("claim alice: %v", err)
	}
	if err := h.users.AddClaims(ctx, bob, identity.Claim{Type: "tenant", Value: "globex"}); err != nil {
		t.Fatalf("claim bob: %v", err)
	}

	// Users in role Admin = {alice, bob}.
	inRole, err := h.users.GetUsersInRole(ctx, "admin") // case-insensitive
	if err != nil {
		t.Fatalf("GetUsersInRole: %v", err)
	}
	if got := names(inRole); got != "alice,bob" {
		t.Fatalf("expected alice,bob in Admin, got %q", got)
	}

	// Unknown role -> empty.
	if u, _ := h.users.GetUsersInRole(ctx, "ghost"); len(u) != 0 {
		t.Fatalf("unknown role should be empty, got %d", len(u))
	}

	// Users for claim tenant=acme = {alice}.
	forClaim, err := h.users.GetUsersForClaim(ctx, "tenant", "acme")
	if err != nil {
		t.Fatalf("GetUsersForClaim: %v", err)
	}
	if got := names(forClaim); got != "alice" {
		t.Fatalf("expected only alice for tenant=acme, got %q", got)
	}
	// Non-matching value -> empty.
	if u, _ := h.users.GetUsersForClaim(ctx, "tenant", "nope"); len(u) != 0 {
		t.Fatalf("non-matching claim should be empty, got %d", len(u))
	}
}

// names returns the usernames sorted, so assertions are order-independent
// (stores order results by id/UUID, not by name).
func names(us []*identity.User) string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.UserName
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
