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

// TestStoreContractParity pins the cross-store behavioral contract on the GORM
// store (mirrors the memstore assertions; pgx stores assert it in integration).
func TestStoreContractParity(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())

	u := &identity.User{UserName: "pat", Email: "pat@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// AddToRole on a missing role -> ErrRoleNotFound (was ErrNotFound before).
	if err := um.AddToRole(ctx, u, "ghost"); !errors.Is(err, identity.ErrRoleNotFound) {
		t.Fatalf("AddToRole(missing role) must be ErrRoleNotFound, got %v", err)
	}
	// RemoveFromRole on a missing role -> no-op (was ErrNotFound before).
	if err := um.RemoveFromRole(ctx, u, "ghost"); err != nil {
		t.Fatalf("RemoveFromRole(missing role) must be a no-op, got %v", err)
	}

	// FindByEmail("") must not match users created without an email.
	noEmail := &identity.User{UserName: "no_email_user"}
	if err := um.Create(ctx, noEmail); err != nil {
		t.Fatalf("create no-email user: %v", err)
	}
	if got, err := um.FindByEmail(ctx, ""); got != nil || !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("FindByEmail(\"\") must be ErrNotFound, got user=%v err=%v", got, err)
	}
}

// TestGenericStoreContractParity pins the same contract on the generic store.
func TestGenericStoreContractParity(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.MigrateOf[identity.User](db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManagerOf[identity.User](gormstore.NewUserStoreOf[identity.User](db), identity.DefaultOptions())

	u := &identity.User{UserName: "gen"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := um.AddToRole(ctx, u, "ghost"); !errors.Is(err, identity.ErrRoleNotFound) {
		t.Fatalf("AddToRole(missing role) must be ErrRoleNotFound, got %v", err)
	}
	if err := um.RemoveFromRole(ctx, u, "ghost"); err != nil {
		t.Fatalf("RemoveFromRole(missing role) must be a no-op, got %v", err)
	}
	if got, err := um.FindByEmail(ctx, ""); got != nil || !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("FindByEmail(\"\") must be ErrNotFound, got user=%v err=%v", got, err)
	}
}
