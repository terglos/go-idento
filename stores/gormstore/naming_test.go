package gormstore_test

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// A custom table prefix must flow through migrate, writes and the role join.
func TestGormTablePrefix(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	opt := gormstore.WithTablePrefix("app_")
	if err := gormstore.Migrate(db, opt); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// The prefixed table must exist (and the canonical one must not).
	var n int
	db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, "app_identity_users").Scan(&n)
	if n != 1 {
		t.Fatalf("expected table app_identity_users to exist, got %d", n)
	}
	db.Raw(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, "identity_users").Scan(&n)
	if n != 0 {
		t.Fatalf("did not expect canonical identity_users table, got %d", n)
	}

	um := identity.NewUserManager(gormstore.NewUserStore(db, opt), identity.DefaultOptions())
	rm := identity.NewRoleManager(gormstore.NewRoleStore(db, opt))
	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := &identity.User{UserName: "prefixed"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if in, _ := um.IsInRole(ctx, u, "Admin"); !in { // join across prefixed tables
		t.Fatal("expected user in Admin role via prefixed-table join")
	}
	got, err := um.FindByName(ctx, "prefixed")
	if err != nil || got == nil {
		t.Fatalf("find: %v", err)
	}
}
