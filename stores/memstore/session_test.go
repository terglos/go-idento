package memstore_test

import (
	"context"
	"testing"
)

// TestSecurityStampSessionFlow covers ValidateSecurityStamp, RefreshSignIn and
// UpdateSecurityStamp (sign-out-everywhere).
func TestSecurityStampSessionFlow(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "sam", "Abcdef1!")
	stamp := h.users.GetSecurityStamp(u)

	// A current stamp validates and refreshes.
	if _, ok := h.signIn.ValidateSecurityStamp(ctx, u.ID, stamp); !ok {
		t.Fatal("current stamp should validate")
	}
	if res, _ := h.signIn.RefreshSignIn(ctx, u.ID, stamp); !res.Succeeded {
		t.Fatalf("refresh should succeed, got %+v", res)
	}

	// Sign-out-everywhere rotates the stamp; the old one is now invalid.
	if err := h.users.UpdateSecurityStamp(ctx, u); err != nil {
		t.Fatalf("UpdateSecurityStamp: %v", err)
	}
	if _, ok := h.signIn.ValidateSecurityStamp(ctx, u.ID, stamp); ok {
		t.Fatal("stale stamp must not validate after rotation")
	}
	if res, _ := h.signIn.RefreshSignIn(ctx, u.ID, stamp); res.Succeeded {
		t.Fatal("refresh with stale stamp must fail")
	}
	// The new stamp works.
	if _, ok := h.signIn.ValidateSecurityStamp(ctx, u.ID, h.users.GetSecurityStamp(u)); !ok {
		t.Fatal("rotated stamp should validate")
	}
}

// TestRememberTwoFactorClient covers skipping 2FA with a valid remember token.
func TestRememberTwoFactorClient(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "tina", "Abcdef1!")
	if err := h.users.SetTwoFactorEnabled(ctx, u, true); err != nil {
		t.Fatalf("enable 2FA: %v", err)
	}

	// Without a remember token, sign-in requires the second factor.
	if res, _ := h.signIn.PasswordSignInRemembering(ctx, "tina", "Abcdef1!", true, ""); !res.RequiresTwoFactor {
		t.Fatalf("expected RequiresTwoFactor, got %+v", res)
	}

	// Issue a remember token for this device; now 2FA is skipped.
	token := h.users.GenerateTwoFactorRememberToken(u)
	if res, _ := h.signIn.PasswordSignInRemembering(ctx, "tina", "Abcdef1!", true, token); !res.Succeeded {
		t.Fatalf("valid remember token should skip 2FA, got %+v", res)
	}

	// A bogus token does not skip 2FA.
	if res, _ := h.signIn.PasswordSignInRemembering(ctx, "tina", "Abcdef1!", true, "bogus"); !res.RequiresTwoFactor {
		t.Fatalf("bogus token must not skip 2FA, got %+v", res)
	}

	// Rotating the security stamp (e.g. password change) invalidates the token.
	if err := h.users.UpdateSecurityStamp(ctx, u); err != nil {
		t.Fatalf("rotate stamp: %v", err)
	}
	reloaded, _ := h.users.FindByID(ctx, u.ID)
	if h.signIn.IsTwoFactorClientRemembered(reloaded, token) {
		t.Fatal("remember token must die when the security stamp rotates")
	}
}
