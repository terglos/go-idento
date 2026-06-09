package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/terglos/go-idento/identity"
)

// TestPhoneChangeFlow covers SetPhoneNumber and the token-based phone change.
func TestPhoneChangeFlow(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "phil", "Abcdef1!")

	// SetPhoneNumber sets an unconfirmed number and rotates the stamp.
	oldStamp := u.SecurityStamp
	if err := h.users.SetPhoneNumber(ctx, u, "+15550001111"); err != nil {
		t.Fatalf("SetPhoneNumber: %v", err)
	}
	if u.PhoneNumber != "+15550001111" || h.users.GetPhoneNumberConfirmed(u) || u.SecurityStamp == oldStamp {
		t.Fatal("phone should be set unconfirmed with rotated stamp")
	}

	// Issue a change token for a NEW number.
	const newPhone = "+15550002222"
	code, err := h.users.GenerateChangePhoneNumberToken(ctx, u, newPhone)
	if err != nil {
		t.Fatalf("GenerateChangePhoneNumberToken: %v", err)
	}

	// A correct code but for the WRONG number must fail (token is number-bound).
	if err := h.users.ChangePhoneNumber(ctx, u, "+15559999999", code); !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("code must not work for a different number, got %v", err)
	}
	// Wrong code for the right number also fails.
	if err := h.users.ChangePhoneNumber(ctx, u, newPhone, "000000"); !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("wrong code should fail, got %v", err)
	}

	// Correct code + correct number succeeds and confirms.
	if err := h.users.ChangePhoneNumber(ctx, u, newPhone, code); err != nil {
		t.Fatalf("ChangePhoneNumber: %v", err)
	}
	if u.PhoneNumber != newPhone || !h.users.GetPhoneNumberConfirmed(u) {
		t.Fatalf("phone should be changed and confirmed, got %q confirmed=%v", u.PhoneNumber, u.PhoneNumberConfirmed)
	}

	// Token is single-use.
	if err := h.users.ChangePhoneNumber(ctx, u, newPhone, code); !errors.Is(err, identity.ErrInvalidToken) {
		t.Fatalf("change token must be single-use, got %v", err)
	}
}

// TestPhoneCodeBruteForceCap verifies a code is invalidated after too many wrong
// guesses, so the 6-digit space can't be brute-forced within the TTL.
func TestPhoneCodeBruteForceCap(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "phoebe", "Abcdef1!")
	_ = h.users.SetPhoneNumber(ctx, u, "+15550003333")

	code, err := h.users.GeneratePhoneToken(ctx, u)
	if err != nil {
		t.Fatalf("GeneratePhoneToken: %v", err)
	}

	// Exhaust the attempt budget with wrong codes.
	for i := 0; i < identity.PhoneTokenMaxAttempts; i++ {
		if ok, _ := h.users.VerifyPhoneToken(ctx, u, "999999"); ok {
			t.Fatal("wrong code must not verify")
		}
	}
	// Even the CORRECT code is now rejected — the token was invalidated.
	if ok, _ := h.users.VerifyPhoneToken(ctx, u, code); ok {
		t.Fatal("token should be invalidated after exceeding the attempt cap")
	}
}
