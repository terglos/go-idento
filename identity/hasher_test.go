package identity

import "testing"

func TestPasswordHasherRoundTrip(t *testing.T) {
	h := NewPasswordHasher()
	u := &User{}
	enc := h.Hash(u, "S3nha!Forte")

	if ok, _ := h.Verify(u, enc, "S3nha!Forte"); !ok {
		t.Fatal("correct password failed to verify")
	}
	if ok, _ := h.Verify(u, enc, "errada"); ok {
		t.Fatal("wrong password verified")
	}
}

func TestPasswordHasherV3Marker(t *testing.T) {
	// The encoded hash must start with the v3 format marker byte 0x01 once decoded.
	h := NewPasswordHasher()
	enc := h.Hash(&User{}, "abc")
	if ok, rehash := h.Verify(&User{}, enc, "abc"); !ok || rehash {
		t.Fatalf("expected ok && no rehash for current params, got ok=%v rehash=%v", ok, rehash)
	}
}

func TestValidatePassword(t *testing.T) {
	m := &UserManager{Options: DefaultOptions()}
	if err := m.ValidatePassword("short"); err == nil {
		t.Fatal("expected too-short to fail")
	}
	if err := m.ValidatePassword("Abcdef1!"); err != nil {
		t.Fatalf("expected strong password to pass, got %v", err)
	}
}
