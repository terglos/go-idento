package gormstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// TestGuestIdentity covers CreateAnonymous, ConvertToRegistered and the
// PurgeAnonymousUsers GC sweep (with satellite cascade) on the GORM store.
func TestGuestIdentity(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())

	// Conversion preserves the ID.
	g, err := um.CreateAnonymous(ctx)
	if err != nil {
		t.Fatalf("CreateAnonymous: %v", err)
	}
	id := g.ID
	if err := um.AddClaims(ctx, g, identity.Claim{Type: "cart", Value: "x"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if err := um.ConvertToRegistered(ctx, g, "promoted", "p@x.com", "Abcdef1!"); err != nil {
		t.Fatalf("ConvertToRegistered: %v", err)
	}
	reloaded, _ := um.FindByID(ctx, id)
	if reloaded == nil || reloaded.IsAnonymous || reloaded.UserName != "promoted" {
		t.Fatalf("converted user wrong: %+v", reloaded)
	}

	// Purge: an old guest with a claim is removed (cascade); a fresh one stays.
	old, _ := um.CreateAnonymous(ctx)
	old.CreatedAt = time.Now().Add(-48 * time.Hour)
	_ = um.Store.Update(ctx, old)
	_ = um.AddClaims(ctx, old, identity.Claim{Type: "cart", Value: "y"})
	fresh, _ := um.CreateAnonymous(ctx)

	n, err := um.PurgeAnonymousUsers(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PurgeAnonymousUsers: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged, got %d", n)
	}
	if got, _ := um.FindByID(ctx, old.ID); got != nil {
		t.Fatal("stale guest should be purged")
	}
	if got, _ := um.FindByID(ctx, fresh.ID); got == nil {
		t.Fatal("fresh guest should remain")
	}
	// Cascade: the purged guest's claim row is gone.
	var claimRows int64
	if err := db.Table("identity_user_claims").Where("user_id = ?", old.ID).Count(&claimRows).Error; err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if claimRows != 0 {
		t.Fatalf("purged guest claims should cascade, got %d rows", claimRows)
	}
}
