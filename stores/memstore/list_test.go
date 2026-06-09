package memstore_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func TestListUsersPagination(t *testing.T) {
	ctx := context.Background()
	um := identity.NewUserManager(memstore.New().Users(), identity.DefaultOptions())

	for i := 0; i < 25; i++ {
		u := &identity.User{UserName: fmt.Sprintf("user%02d", i), Email: fmt.Sprintf("u%02d@corp.com", i)}
		if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	// First page.
	page, total, err := um.ListUsers(ctx, identity.ListFilter{Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 25 || len(page) != 10 {
		t.Fatalf("expected total=25 page=10, got total=%d page=%d", total, len(page))
	}

	// Last partial page.
	page, total, _ = um.ListUsers(ctx, identity.ListFilter{Limit: 10, Offset: 20})
	if total != 25 || len(page) != 5 {
		t.Fatalf("expected total=25 page=5, got total=%d page=%d", total, len(page))
	}

	// Search filter (case-insensitive).
	page, total, _ = um.ListUsers(ctx, identity.ListFilter{Search: "USER0"})
	if total != 10 { // user00..user09
		t.Fatalf("expected 10 matches for 'USER0', got %d", total)
	}
	for _, u := range page {
		if u.UserName[:5] != "user0" {
			t.Fatalf("unexpected match: %s", u.UserName)
		}
	}
}

func TestListNotSupported(t *testing.T) {
	// A store without ListUsers yields ErrListNotSupported.
	um := identity.NewUserManager(noListStore{}, identity.DefaultOptions())
	if _, _, err := um.ListUsers(context.Background(), identity.ListFilter{}); err != identity.ErrListNotSupported {
		t.Fatalf("expected ErrListNotSupported, got %v", err)
	}
}

// noListStore implements DefaultUserStore by embedding the in-memory store but is
// declared as the bare interface so it does NOT expose UserLister... actually we
// just wrap memstore and shadow nothing; instead use a minimal stub.
type noListStore struct{ identity.DefaultUserStore }
