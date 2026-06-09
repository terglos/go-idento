package gormstore_test

import (
	"context"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// AddToRole is idempotent: adding the same role twice is a no-op, not an error.
func TestAddToRoleIdempotent(t *testing.T) {
	ctx := context.Background()
	um, rm, _ := setup(t)
	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := &identity.User{UserName: "dup"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("second add must be a no-op, got: %v", err)
	}
	roles, _ := um.GetRoles(ctx, u)
	if len(roles) != 1 {
		t.Fatalf("expected exactly 1 role, got %v", roles)
	}
}
