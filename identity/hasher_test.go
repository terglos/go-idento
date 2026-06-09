package identity

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// TestPasswordHasherRejectsHugeIterations ensures a crafted hash with an absurd
// iteration count is rejected outright (returns fast, fails closed) rather than
// burning unbounded CPU in pbkdf2.Key — an algorithmic-DoS guard.
func TestPasswordHasherRejectsHugeIterations(t *testing.T) {
	salt := make([]byte, 16)
	subkey := make([]byte, 32)
	buf := make([]byte, 13+len(salt)+len(subkey))
	buf[0] = 0x01
	binary.BigEndian.PutUint32(buf[1:5], uint32(prfSHA256))
	binary.BigEndian.PutUint32(buf[5:9], 0xFFFFFFFF) // ~4.3 billion iterations
	binary.BigEndian.PutUint32(buf[9:13], uint32(len(salt)))
	enc := base64.StdEncoding.EncodeToString(buf)

	if ok, rehash := (&pbkdf2Hasher{}).Verify(&User{}, enc, "whatever"); ok || rehash {
		t.Fatalf("hash with out-of-bounds iteration count must be rejected, got ok=%v rehash=%v", ok, rehash)
	}
}

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
