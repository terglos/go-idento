package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
)

func TestJWKSHandler(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring := identity.NewECDSAKeyring("ec1", k)

	rr := httptest.NewRecorder()
	auth.JWKSHandler(ring).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected JSON content-type, got %q", ct)
	}
	var set identity.JWKSet
	if err := json.Unmarshal(rr.Body.Bytes(), &set); err != nil {
		t.Fatalf("invalid JWKS JSON: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != "ec1" || set.Keys[0].Kty != "EC" {
		t.Fatalf("unexpected JWKS payload: %+v", set)
	}
}
