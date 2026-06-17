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

// TestAPIKeyStore covers the API-key flow on the GORM store, including that
// deleting the user cascades its keys.
func TestAPIKeyStore(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
	km := identity.NewAPIKeyManager(gormstore.NewAPIKeyStore(db), um)

	u := &identity.User{UserName: "svc", Email: "svc@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	secret, key, err := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "POS", Scopes: []string{"a", "b"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	got, vk, err := km.VerifyAPIKey(ctx, secret)
	if err != nil || got.ID != u.ID || len(vk.Scopes) != 2 {
		t.Fatalf("verify should resolve owner + scopes: u=%v scopes=%v err=%v", got, vk.Scopes, err)
	}

	// Revoke rejects.
	if err := km.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := km.VerifyAPIKey(ctx, secret); !errors.Is(err, identity.ErrInvalidAPIKey) {
		t.Fatalf("revoked key must be invalid, got %v", err)
	}

	// Cascade: a new key, then delete the user → key row gone.
	_, key2, _ := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "k2"})
	if err := um.Delete(ctx, u); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var n int64
	if err := db.Table("identity_api_keys").Where("id = ?", key2.ID).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("api keys should cascade on user delete, got %d rows", n)
	}
}
