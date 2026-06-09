package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

// Two readers of the same user; the first write wins, the second (stale) write
// is rejected with ErrConcurrencyFailure.
func TestOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())

	u := &identity.User{UserName: "carol"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Two independent loads (each a snapshot with the same stamp).
	a, _ := um.FindByID(ctx, u.ID)
	b, _ := um.FindByID(ctx, u.ID)
	if a.ConcurrencyStamp != b.ConcurrencyStamp {
		t.Fatal("expected both loads to share the stamp")
	}

	// First write succeeds and rotates the stamp.
	a.SetAttribute("x", "1")
	if err := um.Store.Update(ctx, a); err != nil {
		t.Fatalf("first update should succeed: %v", err)
	}

	// Second write with the now-stale stamp must fail.
	b.SetAttribute("x", "2")
	if err := um.Store.Update(ctx, b); !errors.Is(err, identity.ErrConcurrencyFailure) {
		t.Fatalf("expected ErrConcurrencyFailure, got %v", err)
	}

	// Re-load and update succeeds again (fresh stamp).
	c, _ := um.FindByID(ctx, u.ID)
	c.SetAttribute("x", "3")
	if err := um.Store.Update(ctx, c); err != nil {
		t.Fatalf("reloaded update should succeed: %v", err)
	}
}

// Roles carry the same optimistic-concurrency guarantee as users.
func TestRoleOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	rm := identity.NewRoleManager(st.Roles())

	r := &identity.Role{Name: "Admin"}
	if err := rm.Create(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}

	a, _ := rm.FindByID(ctx, r.ID)
	b, _ := rm.FindByID(ctx, r.ID)

	a.Name = "Administrator"
	if err := rm.Update(ctx, a); err != nil {
		t.Fatalf("first role update should succeed: %v", err)
	}
	if a.ConcurrencyStamp == b.ConcurrencyStamp {
		t.Fatal("stamp should rotate after a successful update")
	}

	b.Name = "Superuser"
	if err := rm.Update(ctx, b); !errors.Is(err, identity.ErrConcurrencyFailure) {
		t.Fatalf("stale role update must fail with ErrConcurrencyFailure, got %v", err)
	}

	// Updating a non-existent role reports ErrNotFound.
	ghost := &identity.Role{ID: "missing", Name: "Ghost", ConcurrencyStamp: "x"}
	if err := rm.Update(ctx, ghost); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing role, got %v", err)
	}
}

// A rename collision with another existing role is rejected.
func TestRoleUpdateDuplicateName(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	rm := identity.NewRoleManager(st.Roles())

	_ = rm.Create(ctx, &identity.Role{Name: "Admin"})
	editor := &identity.Role{Name: "Editor"}
	_ = rm.Create(ctx, editor)

	editor.Name = "Admin" // collides with the existing role
	if err := rm.Update(ctx, editor); !errors.Is(err, identity.ErrDuplicateRoleName) {
		t.Fatalf("expected ErrDuplicateRoleName, got %v", err)
	}
}
