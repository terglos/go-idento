// Package customfields demonstrates the two no-refactor ways to attach custom
// data to a user with the current concrete API (see
// docs/design/extending-user-and-migrations.md):
//
//   - Option A: a 1:1 "profile" extension table joined on the user id.
//   - Option B: claims as lightweight attributes (flow into the JWT).
//
// Both work today on the stock framework — no generics, no fork.
package customfields_test

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// Profile is the app-owned extension table. It is NOT part of go-idento; the
// application defines and migrates it alongside the identity tables.
type Profile struct {
	UserID   string `gorm:"primaryKey;type:varchar(36)"`
	TenantID string `gorm:"index"`
	FullName string
	Avatar   string
}

func TestExtensionTable(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Migrate the identity tables AND the app's own Profile table.
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("identity migrate: %v", err)
	}
	if err := db.AutoMigrate(&Profile{}); err != nil {
		t.Fatalf("profile migrate: %v", err)
	}

	users := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())

	// 1. Create the user through the manager (handles hashing, stamps, etc).
	u := &identity.User{UserName: "jane", Email: "jane@x.com"}
	if err := users.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// 2. Persist the extension row keyed by the generated user id.
	if err := db.Create(&Profile{UserID: u.ID, TenantID: "acme", FullName: "Jane D.", Avatar: "m.png"}).Error; err != nil {
		t.Fatalf("create profile: %v", err)
	}

	// Read back with a join: identity owns auth, the app owns the profile.
	type row struct {
		UserName string
		TenantID string
		FullName string
	}
	var got row
	err = db.Table("identity_users").
		Select("identity_users.user_name, profiles.tenant_id, profiles.full_name").
		Joins("JOIN profiles ON profiles.user_id = identity_users.id").
		Where("identity_users.id = ?", u.ID).
		Scan(&got).Error
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if got.UserName != "jane" || got.TenantID != "acme" || got.FullName != "Jane D." {
		t.Fatalf("unexpected joined row: %+v", got)
	}
}

func TestClaimsAsAttributes(t *testing.T) {
	ctx := context.Background()
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	_ = gormstore.Migrate(db)

	users := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
	tokens := identity.NewTokenService(users,
		identity.DefaultTokenOptions([]byte("customfields-signing-key-000000!"), "go-idento", "api"))

	u := &identity.User{UserName: "nina"}
	if err := users.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Attach attributes as claims — no schema change required.
	if err := users.AddClaims(ctx, u,
		identity.Claim{Type: "tenant", Value: "acme"},
		identity.Claim{Type: "plan", Value: "pro"},
	); err != nil {
		t.Fatalf("add claims: %v", err)
	}

	// They surface automatically inside the issued JWT.
	pair, err := tokens.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, claims, err := tokens.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims["tenant"] != "acme" || claims["plan"] != "pro" {
		t.Fatalf("custom claims missing from token: tenant=%v plan=%v", claims["tenant"], claims["plan"])
	}
}
