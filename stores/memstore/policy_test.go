package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

// TestAllowedUserNameCharacters verifies the configured username allow-list is
// actually enforced on creation (previously a no-op).
func TestAllowedUserNameCharacters(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())

	// Disallowed characters (space, angle brackets) must be rejected.
	for _, bad := range []string{"évil", "has space", "a<b>", ""} {
		if err := um.CreateWithPassword(ctx, &identity.User{UserName: bad}, "Abcdef1!"); !errors.Is(err, identity.ErrInvalidUserName) {
			t.Fatalf("username %q should be rejected, got %v", bad, err)
		}
	}
	// A name within the default allow-list succeeds.
	if err := um.CreateWithPassword(ctx, &identity.User{UserName: "good.user-1@x"}, "Abcdef1!"); err != nil {
		t.Fatalf("allowed username should be accepted: %v", err)
	}

	// An empty allow-list disables the character check (but blank is still rejected).
	opts := identity.DefaultOptions()
	opts.User.AllowedUserNameCharacters = ""
	um2 := identity.NewUserManager(memstore.New().Users(), opts)
	if err := um2.CreateWithPassword(ctx, &identity.User{UserName: "anything goes!"}, "Abcdef1!"); err != nil {
		t.Fatalf("empty allow-list should permit any non-blank name: %v", err)
	}
}

// TestRequiredUniqueChars verifies the distinct-character password policy is
// enforced (previously a no-op).
func TestRequiredUniqueChars(t *testing.T) {
	opts := identity.DefaultOptions()
	opts.Password.RequiredUniqueChars = 5
	um := identity.NewUserManager(memstore.New().Users(), opts)

	// "Aaaa1!" has only 4 distinct runes -> rejected.
	if err := um.ValidatePassword("Aaaa1!"); !errors.Is(err, identity.ErrPasswordRequiresUnique) {
		t.Fatalf("expected ErrPasswordRequiresUnique, got %v", err)
	}
	// "Abcd1!" has 6 distinct runes -> accepted.
	if err := um.ValidatePassword("Abcd1!"); err != nil {
		t.Fatalf("password with enough distinct chars should pass: %v", err)
	}
}
