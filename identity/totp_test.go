package identity

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	totp := DefaultTOTP()
	secret := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)

	code, err := totp.Code(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if !totp.Validate(secret, code, now) {
		t.Fatal("freshly generated code should validate")
	}
	// Within skew window (one step later).
	if !totp.Validate(secret, code, now.Add(30*time.Second)) {
		t.Fatal("code should validate within ±1 step")
	}
	// Far outside the window must fail.
	if totp.Validate(secret, code, now.Add(5*time.Minute)) {
		t.Fatal("stale code should not validate")
	}
}
