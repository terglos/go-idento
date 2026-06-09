package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terglos/go-idento/identity"
)

// signWith builds a minimal JWT signed by the keyring's active key (with kid).
func signWith(t *testing.T, s identity.Signer) string {
	t.Helper()
	tok := jwt.NewWithClaims(s.Method(), jwt.MapClaims{"sub": "u1"})
	kid, key := s.SignKey()
	if kid != "" {
		tok.Header["kid"] = kid
	}
	out, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out
}

func TestECDSAKeyringSignRotateJWKS(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring := identity.NewECDSAKeyring("ec1", k1)

	tok1 := signWith(t, ring)
	if _, err := jwt.Parse(tok1, ring.Keyfunc, jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("ES256 token should validate: %v", err)
	}

	// Rotate: old token still verifies; after Remove it fails.
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring.Add("ec2", k2, true)
	if _, err := jwt.Parse(tok1, ring.Keyfunc, jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("retired-key token should still validate: %v", err)
	}
	ring.Remove("ec1")
	if _, err := jwt.Parse(tok1, ring.Keyfunc, jwt.WithValidMethods([]string{"ES256"})); err == nil {
		t.Fatal("removed-key token must fail")
	}

	// JWKS must expose the active EC key, and a pubkey rebuilt from it must
	// verify a token signed by the ring.
	set := ring.JWKS()
	jwk := findKID(t, set, "ec2")
	if jwk.Kty != "EC" || jwk.Alg != "ES256" || jwk.Crv != "P-256" {
		t.Fatalf("unexpected EC JWK: %+v", jwk)
	}
	pub := rebuildEC(t, jwk)
	tok2 := signWith(t, ring)
	if _, err := jwt.Parse(tok2, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("token must verify against pubkey rebuilt from JWKS: %v", err)
	}
}

func TestRSAKeyringJWKS(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	ring := identity.NewRSAKeyring("rs1", k1)

	set := ring.JWKS()
	jwk := findKID(t, set, "rs1")
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.N == "" || jwk.E == "" {
		t.Fatalf("unexpected RSA JWK: %+v", jwk)
	}
	pub := rebuildRSA(t, jwk)
	tok := signWith(t, ring)
	if _, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("token must verify against pubkey rebuilt from JWKS: %v", err)
	}
}

func findKID(t *testing.T, set identity.JWKSet, kid string) identity.JWK {
	t.Helper()
	for _, k := range set.Keys {
		if k.Kid == kid {
			return k
		}
	}
	t.Fatalf("kid %q not found in JWKS (%d keys)", kid, len(set.Keys))
	return identity.JWK{}
}

func rebuildEC(t *testing.T, jwk identity.JWK) *ecdsa.PublicKey {
	t.Helper()
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

func rebuildRSA(t *testing.T, jwk identity.JWK) *rsa.PublicKey {
	t.Helper()
	n, _ := base64.RawURLEncoding.DecodeString(jwk.N)
	e, _ := base64.RawURLEncoding.DecodeString(jwk.E)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}
