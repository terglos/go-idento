package gormstore_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// TestGetUsersInRoleAndForClaim covers the reverse-query API on the GORM store,
// including that the Attributes serializer round-trips through the id-based load.
func TestGetUsersInRoleAndForClaim(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
	rm := identity.NewRoleManager(gormstore.NewRoleStore(db))

	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	alice := &identity.User{UserName: "alice", Email: "alice@x.com"}
	alice.SetAttribute("tenant", "acme")
	bob := &identity.User{UserName: "bob", Email: "bob@x.com"}
	for _, u := range []*identity.User{alice, bob} {
		if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
			t.Fatalf("create %s: %v", u.UserName, err)
		}
		if err := um.AddToRole(ctx, u, "Admin"); err != nil {
			t.Fatalf("role %s: %v", u.UserName, err)
		}
	}
	if err := um.AddClaims(ctx, alice, identity.Claim{Type: "tenant", Value: "acme"}); err != nil {
		t.Fatalf("claim: %v", err)
	}

	inRole, err := um.GetUsersInRole(ctx, "Admin")
	if err != nil {
		t.Fatalf("GetUsersInRole: %v", err)
	}
	if got := names(inRole); got != "alice,bob" {
		t.Fatalf("expected alice,bob, got %q", got)
	}
	// Attributes survived the id-based reload.
	for _, u := range inRole {
		if u.UserName == "alice" {
			if v, ok := u.GetAttribute("tenant"); !ok || v != "acme" {
				t.Fatalf("alice attributes lost in reverse query: %q (%v)", v, ok)
			}
		}
	}

	forClaim, err := um.GetUsersForClaim(ctx, "tenant", "acme")
	if err != nil {
		t.Fatalf("GetUsersForClaim: %v", err)
	}
	if got := names(forClaim); got != "alice" {
		t.Fatalf("expected only alice, got %q", got)
	}
}

func names(us []*identity.User) string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.UserName
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
