package memstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

// TestGuestLifecycle covers CreateAnonymous, token issuance, ConvertToRegistered
// (ID preserved, data carried over) and that a converted guest no longer purges.
func TestGuestLifecycle(t *testing.T) {
	ctx := context.Background()
	h := newHarness()

	g, err := h.users.CreateAnonymous(ctx)
	if err != nil {
		t.Fatalf("CreateAnonymous: %v", err)
	}
	if !h.users.IsAnonymous(g) || g.UserName == "" || g.PasswordHash != "" {
		t.Fatalf("guest should be anonymous, named, password-less: %+v", g)
	}
	guestID := g.ID

	// A guest can hold a token and data (claims), like any user.
	if _, err := h.tokens.IssuePair(ctx, g); err != nil {
		t.Fatalf("issue token for guest: %v", err)
	}
	if err := h.users.AddClaims(ctx, g, identity.Claim{Type: "cart", Value: "item-1"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}

	// Convert to a full account — same ID, claims survive.
	if err := h.users.ConvertToRegistered(ctx, g, "real_user", "real@x.com", "Abcdef1!"); err != nil {
		t.Fatalf("ConvertToRegistered: %v", err)
	}
	if g.ID != guestID {
		t.Fatal("conversion must preserve the user ID")
	}
	if h.users.IsAnonymous(g) {
		t.Fatal("converted user must no longer be anonymous")
	}
	if !h.users.CheckPassword(ctx, g, "Abcdef1!") {
		t.Fatal("converted user should authenticate with the new password")
	}
	if claims, _ := h.users.GetClaims(ctx, g); len(claims) != 1 || claims[0].Value != "item-1" {
		t.Fatalf("claims should carry over the conversion, got %v", claims)
	}
	if found, _ := h.users.FindByName(ctx, "real_user"); found == nil || found.ID != guestID {
		t.Fatal("converted user findable by new name, same ID")
	}

	// Converting a non-guest is rejected.
	if err := h.users.ConvertToRegistered(ctx, g, "again", "a@x.com", "Abcdef1!"); !errors.Is(err, identity.ErrNotAnonymous) {
		t.Fatalf("expected ErrNotAnonymous, got %v", err)
	}
}

// TestPurgeAnonymousUsers covers the GC sweep: only stale guests are removed,
// cascading their satellite rows; full users and fresh guests are kept.
func TestPurgeAnonymousUsers(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	rm := identity.NewRoleManager(st.Roles())
	_ = rm.Create(ctx, &identity.Role{Name: "Admin"})

	// A full (non-guest) user — must survive any purge.
	full := &identity.User{UserName: "real", Email: "real@x.com"}
	if err := um.CreateWithPassword(ctx, full, "Abcdef1!"); err != nil {
		t.Fatalf("create full: %v", err)
	}

	// An old guest with satellite rows (role + claim).
	oldGuest, _ := um.CreateAnonymous(ctx)
	oldGuest.CreatedAt = time.Now().Add(-48 * time.Hour)
	_ = um.Store.Update(ctx, oldGuest)
	_ = um.AddToRole(ctx, oldGuest, "Admin")
	_ = um.AddClaims(ctx, oldGuest, identity.Claim{Type: "cart", Value: "x"})

	// A fresh guest — must survive a purge of >24h-old guests.
	freshGuest, _ := um.CreateAnonymous(ctx)

	cutoff := time.Now().Add(-24 * time.Hour)
	n, err := um.PurgeAnonymousUsers(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeAnonymousUsers: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 guest purged, got %d", n)
	}
	if got, _ := um.FindByID(ctx, oldGuest.ID); got != nil {
		t.Fatal("stale guest should be gone")
	}
	if got, _ := um.FindByID(ctx, freshGuest.ID); got == nil {
		t.Fatal("fresh guest should remain")
	}
	if got, _ := um.FindByID(ctx, full.ID); got == nil {
		t.Fatal("full user must never be purged")
	}
	// Satellite rows of the purged guest are gone (cascade).
	if claims, _ := um.GetClaims(ctx, oldGuest); len(claims) != 0 {
		t.Fatalf("purged guest claims should cascade, got %v", claims)
	}
}
