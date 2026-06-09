package auth

import (
	"encoding/json"
	"net/http"

	"github.com/terglos/go-idento/identity"
)

// JWKSHandler serves the public keys of an asymmetric signer (RSAKeyring or
// ECDSAKeyring) as a JWKS document, so resource servers and gateways can
// validate go-idento JWTs without sharing a secret. Mount it at, e.g.,
// /.well-known/jwks.json.
//
//	mux.Handle("/.well-known/jwks.json", auth.JWKSHandler(ring))
func JWKSHandler(p identity.JWKSProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(p.JWKS())
	})
}
