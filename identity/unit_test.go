package identity

import (
	"encoding/base64"
	"testing"
	"time"
)

// withFrozenClock runs fn with nowFn pinned to t, restoring it afterwards.
func withFrozenClock(at time.Time, fn func()) {
	saved := nowFn
	nowFn = func() time.Time { return at }
	defer func() { nowFn = saved }()
	fn()
}

func TestValidatePasswordTable(t *testing.T) {
	m := &UserManager{Options: DefaultOptions()}
	cases := []struct {
		name string
		pw   string
		want *IdentityError
	}{
		{"too short", "Ab1!", ErrPasswordTooShort},
		{"no digit", "Abcdef!", ErrPasswordRequiresDigit},
		{"no upper", "abcdef1!", ErrPasswordRequiresUpper},
		{"no lower", "ABCDEF1!", ErrPasswordRequiresLower},
		{"no symbol", "Abcdef12", ErrPasswordRequiresNonAlpha},
		{"valid", "Abcdef1!", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.ValidatePassword(tc.pw)
			if tc.want == nil && err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
			if tc.want != nil && err != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestHasherNeedsRehashOnWeakerParams(t *testing.T) {
	// A hash made with fewer iterations must verify but request a rehash under
	// the stronger current defaults.
	weak := &pbkdf2Hasher{iterations: 1000, saltLen: 16, subkeyLen: 32, prf: prfSHA256}
	strong := NewPasswordHasher()
	enc := weak.Hash(&User{}, "Abcdef1!")

	ok, needsRehash := strong.Verify(&User{}, enc, "Abcdef1!")
	if !ok {
		t.Fatal("weak hash should still verify")
	}
	if !needsRehash {
		t.Fatal("weaker params should request a rehash")
	}
}

func TestHasherRejectsGarbage(t *testing.T) {
	h := NewPasswordHasher()
	if ok, _ := h.Verify(&User{}, "not-base64!!", "x"); ok {
		t.Fatal("invalid base64 must not verify")
	}
	// Valid base64 but wrong version marker.
	bad := base64.StdEncoding.EncodeToString([]byte{0x99, 0, 0, 0})
	if ok, _ := h.Verify(&User{}, bad, "x"); ok {
		t.Fatal("unknown version marker must not verify")
	}
}

func TestDataTokenProviderExpiryAndTamper(t *testing.T) {
	p := NewDataTokenProvider([]byte("secret-key"), time.Hour)
	u := &User{ID: "u1", SecurityStamp: "stamp-1"}

	base := time.Unix(1_700_000_000, 0)
	var token string
	withFrozenClock(base, func() { token = p.Generate("Purpose", u) })

	// Valid within the window.
	withFrozenClock(base.Add(30*time.Minute), func() {
		if !p.Validate("Purpose", token, u) {
			t.Fatal("token should be valid within lifespan")
		}
	})
	// Expired after the window.
	withFrozenClock(base.Add(2*time.Hour), func() {
		if p.Validate("Purpose", token, u) {
			t.Fatal("token should be expired")
		}
	})
	// Wrong purpose.
	withFrozenClock(base, func() {
		if p.Validate("Other", token, u) {
			t.Fatal("token bound to a different purpose must fail")
		}
	})
	// Security stamp changed -> token invalidated.
	withFrozenClock(base, func() {
		u2 := &User{ID: "u1", SecurityStamp: "stamp-2"}
		if p.Validate("Purpose", token, u2) {
			t.Fatal("changing the security stamp must invalidate the token")
		}
	})
}

func TestRecoveryCodeFormat(t *testing.T) {
	c := randomRecoveryCode()
	if len(c) != 11 || c[5] != '-' { // xxxxx-xxxxx
		t.Fatalf("unexpected recovery code format: %q", c)
	}
}
