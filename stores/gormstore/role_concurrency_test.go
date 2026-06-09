package gormstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// TestRoleOptimisticConcurrency verifies the GORM role store matches and rotates
// ConcurrencyStamp: the first write wins, a stale write fails.
func TestRoleOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	rm := identity.NewRoleManager(gormstore.NewRoleStore(db))

	r := &identity.Role{Name: "Admin"}
	if err := rm.Create(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}

	a, _ := rm.FindByID(ctx, r.ID)
	b, _ := rm.FindByID(ctx, r.ID)

	a.Name = "Administrator"
	if err := rm.Update(ctx, a); err != nil {
		t.Fatalf("first update should win: %v", err)
	}
	b.Name = "Superuser"
	if err := rm.Update(ctx, b); !errors.Is(err, identity.ErrConcurrencyFailure) {
		t.Fatalf("stale update must fail with ErrConcurrencyFailure, got %v", err)
	}

	// The committed rename is visible; the rotated stamp lets a fresh load update.
	got, _ := rm.FindByID(ctx, r.ID)
	if got.Name != "Administrator" {
		t.Fatalf("expected committed name Administrator, got %q", got.Name)
	}
	got.Name = "Owner"
	if err := rm.Update(ctx, got); err != nil {
		t.Fatalf("reloaded update should succeed: %v", err)
	}
}
