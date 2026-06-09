package identity

import (
	"crypto/ecdsa"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// ECDSAKeyring is an ES256 signer holding multiple P-256 keys identified by kid,
// the elliptic-curve counterpart of [RSAKeyring]. Tokens signed with a retired
// key keep verifying while new tokens use the active key. Safe for concurrent use.
type ECDSAKeyring struct {
	mu     sync.RWMutex
	method jwt.SigningMethod
	active string
	keys   map[string]*ecdsa.PrivateKey
}

// NewECDSAKeyring creates a keyring with an initial active P-256 key (ES256).
func NewECDSAKeyring(activeKID string, key *ecdsa.PrivateKey) *ECDSAKeyring {
	return &ECDSAKeyring{
		method: jwt.SigningMethodES256,
		active: activeKID,
		keys:   map[string]*ecdsa.PrivateKey{activeKID: key},
	}
}

// Add registers an additional key. If makeActive, new tokens use it; the
// previous key stays available for verification (graceful rotation).
func (k *ECDSAKeyring) Add(kid string, key *ecdsa.PrivateKey, makeActive bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[kid] = key
	if makeActive {
		k.active = kid
	}
}

// Remove retires a key from the ring (call once no live tokens reference it).
func (k *ECDSAKeyring) Remove(kid string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, kid)
}

func (k *ECDSAKeyring) Method() jwt.SigningMethod { return k.method }

func (k *ECDSAKeyring) SignKey() (string, any) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active, k.keys[k.active]
}

func (k *ECDSAKeyring) Keyfunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
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
