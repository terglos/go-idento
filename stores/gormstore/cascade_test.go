package gormstore_test

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// TestDeleteCascade verifies that UserManager.Delete removes the user row and
// every satellite row (roles, claims, logins, tokens) in one transaction.
func TestDeleteCascade(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := gormstore.NewUserStore(db)
	um := identity.NewUserManager(store, identity.DefaultOptions())
	rm := identity.NewRoleManager(gormstore.NewRoleStore(db))

	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := &identity.User{UserName: "nadia", Email: "nadia@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := um.AddClaims(ctx, u, identity.Claim{Type: "dept", Value: "eng"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if err := um.AddLogin(ctx, u, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-7", ProviderDisplayName: "GitHub"}); err != nil {
		t.Fatalf("add login: %v", err)
	}
	if err := store.SetToken(ctx, u, "auth", "recovery", "code-abc"); err != nil {
		t.Fatalf("set token: %v", err)
	}

	if err := um.Delete(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if got, _ := um.FindByID(ctx, u.ID); got != nil {
		t.Fatal("user should be deleted")
	}
	assertCount(t, db, "identity_user_roles", "user_id = ?", u.ID)
	assertCount(t, db, "identity_user_claims", "user_id = ?", u.ID)
	assertCount(t, db, "identity_user_logins", "user_id = ?", u.ID)
	assertCount(t, db, "identity_user_tokens", "user_id = ?", u.ID)
}

func assertCount(t *testing.T, db *gorm.DB, table, where string, arg any) {
	t.Helper()
	var n int64
	if err := db.Table(table).Where(where, arg).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if n != 0 {
		t.Fatalf("%s should have 0 rows after cascade delete, got %d", table, n)
	}
}
