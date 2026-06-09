package gormstore_test

import (
	"context"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// Option C: schema-less custom data via the Attributes JSON column.
func TestAttributesColumn(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)

	u := &identity.User{UserName: "owen"}
	u.SetAttribute("tenant", "acme")
	u.SetAttribute("plan", "pro")
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Round-trips through the DB.
	got, err := um.FindByName(ctx, "owen")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if v, ok := got.GetAttribute("tenant"); !ok || v != "acme" {
		t.Fatalf("tenant attribute lost: %q (%v)", v, ok)
	}
	if v, _ := got.GetAttribute("plan"); v != "pro" {
		t.Fatalf("plan attribute lost: %q", v)
	}

	// Mutate and persist.
	got.SetAttribute("plan", "enterprise")
	if err := um.Store.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	reloaded, _ := um.FindByName(ctx, "owen")
	if v, _ := reloaded.GetAttribute("plan"); v != "enterprise" {
		t.Fatalf("attribute update lost: %q", v)
	}
}
