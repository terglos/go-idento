package identity

import (
	"crypto/rsa"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// Signer abstracts JWT signing/verification so the token service can use
// symmetric (HS256) or asymmetric (RS256/ES256) keys, with key rotation via the
// "kid" header, so resource servers can validate tokens via a JWKS endpoint.
type Signer interface {
	// Method is the JWT signing algorithm.
	Method() jwt.SigningMethod
	// SignKey returns the active key id (may be "") and the signing key.
	SignKey() (kid string, key any)
	// Keyfunc resolves the verification key for a parsed token (looks up kid).
	Keyfunc(token *jwt.Token) (any, error)
}

// hmacSigner signs with a shared secret (HS256) — the default.
type hmacSigner struct{ key []byte }

// NewHMACSigner returns a symmetric HS256 signer.
func NewHMACSigner(key []byte) Signer { return &hmacSigner{key: key} }

func (s *hmacSigner) Method() jwt.SigningMethod { return jwt.SigningMethodHS256 }
func (s *hmacSigner) SignKey() (string, any)    { return "", s.key }
func (s *hmacSigner) Keyfunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, ErrInvalidToken
	}
	return s.key, nil
}

// RSAKeyring is an RS256 signer holding multiple keys identified by kid, so
// tokens signed with a retired key keep verifying while new tokens use the
// active key. Safe for concurrent use.
type RSAKeyring struct {
	mu     sync.RWMutex
	method jwt.SigningMethod
	active string
	keys   map[string]*rsa.PrivateKey
}

// NewRSAKeyring creates a keyring with an initial active key.
func NewRSAKeyring(activeKID string, key *rsa.PrivateKey) *RSAKeyring {
	return &RSAKeyring{
		method: jwt.SigningMethodRS256,
		active: activeKID,
		keys:   map[string]*rsa.PrivateKey{activeKID: key},
	}
}

// Add registers an additional key. If makeActive, new tokens use it; the
// previous key stays available for verification (graceful rotation).
func (k *RSAKeyring) Add(kid string, key *rsa.PrivateKey, makeActive bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[kid] = key
	if makeActive {
		k.active = kid
	}
}

// Remove retires a key from the ring (call once no live tokens reference it).
func (k *RSAKeyring) Remove(kid string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, kid)
}

func (k *RSAKeyring) Method() jwt.SigningMethod { return k.method }

func (k *RSAKeyring) SignKey() (string, any) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active, k.keys[k.active]
}

func (k *RSAKeyring) Keyfunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, ErrInvalidToken
	}
	kid, _ := t.Header["kid"].(string)
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[kid]
	if !ok {
		return nil, ErrInvalidToken
	}
	return &key.PublicKey, nil
}
