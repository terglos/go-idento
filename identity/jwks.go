package identity

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
)

// JWK is a single JSON Web Key (public). Only the fields relevant to RSA and
// EC signing keys are included. See RFC 7517 / RFC 7518.
type JWK struct {
	Kty string `json:"kty"`           // "RSA" or "EC"
	Use string `json:"use"`           // "sig"
	Kid string `json:"kid"`           // key id (matches the JWT "kid" header)
	Alg string `json:"alg"`           // "RS256" or "ES256"
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC curve, e.g. "P-256"
	X   string `json:"x,omitempty"`   // EC x coordinate (base64url)
	Y   string `json:"y,omitempty"`   // EC y coordinate (base64url)
}

// JWKSet is a JSON Web Key Set, the payload of a JWKS endpoint.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSProvider is implemented by signers that can publish their public keys as a
// JWKS (RSAKeyring, ECDSAKeyring). The HTTP handler lives in package auth.
type JWKSProvider interface {
	JWKS() JWKSet
}

var (
	_ JWKSProvider = (*RSAKeyring)(nil)
	_ JWKSProvider = (*ECDSAKeyring)(nil)
)

// JWKS returns the public keys of the ring as a JWK set.
func (k *RSAKeyring) JWKS() JWKSet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	set := JWKSet{Keys: make([]JWK, 0, len(k.keys))}
	for kid, key := range k.keys {
		pub := key.PublicKey
		eBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(eBuf, uint32(pub.E))
		eBuf = trimLeadingZeros(eBuf)
		set.Keys = append(set.Keys, JWK{
			Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(eBuf),
		})
	}
	return set
}

// JWKS returns the public keys of the ring as a JWK set.
func (k *ECDSAKeyring) JWKS() JWKSet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	set := JWKSet{Keys: make([]JWK, 0, len(k.keys))}
	for kid, key := range k.keys {
		set.Keys = append(set.Keys, ecJWK(kid, &key.PublicKey))
	}
	return set
}

func ecJWK(kid string, pub *ecdsa.PublicKey) JWK {
	size := (pub.Curve.Params().BitSize + 7) / 8 // 32 for P-256
	x := make([]byte, size)
	y := make([]byte, size)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return JWK{
		Kty: "EC", Use: "sig", Kid: kid, Alg: "ES256", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(x),
		Y: base64.RawURLEncoding.EncodeToString(y),
	}
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}
