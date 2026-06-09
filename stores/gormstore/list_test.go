package gormstore_test

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// TestListUsers exercises the GORM store's UserLister: search filter, total
// count and page bounds.
func TestListUsers(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())

	for _, name := range []string{"alice", "bob", "carol", "dave"} {
		u := &identity.User{UserName: name, Email: name + "@x.com"}
		if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	// Unfiltered: all four, paged.
	page, total, err := um.ListUsers(ctx, identity.ListFilter{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 4 {
		t.Fatalf("expected total 4, got %d", total)
	}
	if len(page) != 2 {
		t.Fatalf("expected page size 2, got %d", len(page))
	}

	// Second page.
	page2, _, _ := um.ListUsers(ctx, identity.ListFilter{Limit: 2, Offset: 2})
	if len(page2) != 2 || page2[0].UserName == page[0].UserName {
		t.Fatalf("second page should hold the remaining distinct users, got %d", len(page2))
	}

	// Search narrows by normalized name/email (case-insensitive).
	hits, n, err := um.ListUsers(ctx, identity.ListFilter{Search: "carol"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if n != 1 || len(hits) != 1 || hits[0].UserName != "carol" {
		t.Fatalf("expected exactly carol, got n=%d page=%d", n, len(hits))
	}
}
