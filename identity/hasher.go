package identity

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// PasswordHasher is the abstraction over password hashing.
type PasswordHasher interface {
	// Hash returns the encoded hash for the given plaintext password.
	Hash(user *User, password string) string
	// Verify checks password against encoded. needsRehash is true when the
	// stored hash used weaker parameters and should be upgraded on next login.
	Verify(user *User, encoded, password string) (ok, needsRehash bool)
}

// PRF identifies the pseudo-random function; the values are part of the encoded
// hash format.
type PRF uint32

const (
	prfSHA1   PRF = 0
	prfSHA256 PRF = 1
	prfSHA512 PRF = 2
)

// pbkdf2Hasher implements a versioned PBKDF2 hash format. The encoded value is:
//
//	{ 0x01, prf (uint32 BE), iterCount (uint32 BE), saltLen (uint32 BE), salt, subkey }
//
// base64-encoded for storage. The leading version byte lets the parameters
// evolve over time while old hashes keep verifying (and get rehashed on login).
type pbkdf2Hasher struct {
	iterations int
	saltLen    int
	subkeyLen  int
	prf        PRF
}

// NewPasswordHasher returns the default hasher: PBKDF2/HMAC-SHA256, 100000
// iterations, 128-bit salt, 256-bit subkey.
func NewPasswordHasher() PasswordHasher {
	return &pbkdf2Hasher{iterations: 100_000, saltLen: 16, subkeyLen: 32, prf: prfSHA256}
}

func newHash(p PRF) func() hash.Hash {
	switch p {
	case prfSHA512:
		return sha512.New
	case prfSHA256:
		return sha256.New
	default:
		return sha1.New
	}
}

func (h *pbkdf2Hasher) Hash(_ *User, password string) string {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("identity: cannot read random salt: " + err.Error())
	}
	subkey := pbkdf2.Key([]byte(password), salt, h.iterations, h.subkeyLen, newHash(h.prf))

	out := make([]byte, 13+len(salt)+len(subkey))
	out[0] = 0x01 // version marker (v3)
	binary.BigEndian.PutUint32(out[1:5], uint32(h.prf))
	binary.BigEndian.PutUint32(out[5:9], uint32(h.iterations))
	binary.BigEndian.PutUint32(out[9:13], uint32(len(salt)))
	copy(out[13:], salt)
	copy(out[13+len(salt):], subkey)
	return base64.StdEncoding.EncodeToString(out)
}

func (h *pbkdf2Hasher) Verify(_ *User, encoded, password string) (ok, needsRehash bool) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || data[0] != 0x01 {
		return false, false
	}
	if len(data) < 13 {
		return false, false
	}
	prf := PRF(binary.BigEndian.Uint32(data[1:5]))
	iter := int(binary.BigEndian.Uint32(data[5:9]))
	saltLen := int(binary.BigEndian.Uint32(data[9:13]))
	if saltLen < 8 || len(data) < 13+saltLen+1 {
		return false, false
	}
	salt := data[13 : 13+saltLen]
	subkey := data[13+saltLen:]

	derived := pbkdf2.Key([]byte(password), salt, iter, len(subkey), newHash(prf))
	if subtle.ConstantTimeCompare(derived, subkey) != 1 {
		return false, false
	}
	// Upgrade if stored params are weaker than our current defaults.
	needsRehash = iter < h.iterations || prf != h.prf || saltLen != h.saltLen || len(subkey) != h.subkeyLen
	return true, needsRehash
}
