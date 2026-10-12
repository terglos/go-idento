package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func jwkJSON(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseJWKS(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p, _ := ec.PublicKey.Bytes()
	rsaJWK := func(k *rsa.PublicKey, extra map[string]any) map[string]any {
		m := map[string]any{"kty": "RSA", "kid": "r", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}
		for a, v := range extra {
			m[a] = v
		}
		return m
	}
	ecJWK := map[string]any{"kty": "EC", "kid": "e", "crv": "P-256", "x": enc(p[1:33]), "y": enc(p[33:])}

	keys, err := parseJWKS(jwkJSON(t, rsaJWK(&rsa2048.PublicKey, nil), ecJWK,
		rsaJWK(&rsa1024.PublicKey, map[string]any{"kid": "weak"}),                 // < 2048 bits: skipped
		rsaJWK(&rsa2048.PublicKey, map[string]any{"kid": "enc", "use": "enc"}),    // not a signing key: skipped
		map[string]any{"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"},         // unsupported curve: skipped
		map[string]any{"kty": "oct", "k": "c2VjcmV0"},                             // symmetric: skipped
		map[string]any{"kty": "EC", "crv": "P-256", "x": enc(p[1:33]), "y": "AA"}, // not on the curve: skipped
	))
	if err != nil || len(keys) != 2 || keys[0].kid != "r" || keys[1].kid != "e" {
		t.Fatalf("want the RSA-2048 and P-256 keys only, got %+v %v", keys, err)
	}
	if !keys[0].fits("RS256") || keys[0].fits("ES256") || !keys[1].fits("ES256") || keys[1].fits("RS256") {
		t.Fatal("keys must only fit their own algorithm")
	}
	pinned := clientKey{alg: "RS256", key: &ec.PublicKey}
	if pinned.fits("ES256") {
		t.Fatal("a key's declared alg must be honored")
	}
	if _, err := parseJWKS(jwkJSON(t, map[string]any{"kty": "RSA", "n": "AA", "e": "AQAB", "d": "AA"})); err == nil {
		t.Fatal("private key material must be refused")
	}
	if _, err := parseJWKS(jwkJSON(t, rsaJWK(&rsa1024.PublicKey, nil))); err == nil {
		t.Fatal("a set with no usable key must be refused")
	}
	if _, err := parseJWKS([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON must be refused")
	}
}

func TestJWKSFetchProtections(t *testing.T) {
	ctx := context.Background()
	// Default fetcher: special-use addresses are refused at dial time (draft
	// §8.6 covers every URL found in a metadata document, jwks_uri included).
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("x", 70*1024) + `"}`))
			return
		}
		http.Redirect(w, r, "/big", http.StatusFound)
	}))
	defer ts.Close()
	if _, err := NewCIMDFetcher().jwks(ctx, ts.URL+"/jwks.json", false); err == nil || !strings.Contains(err.Error(), "special-use") {
		t.Fatalf("loopback jwks_uri must be refused by default, got %v", err)
	}
	if _, err := NewCIMDFetcher().jwks(ctx, "https://169.254.169.254/jwks.json", false); err == nil {
		t.Fatal("the cloud metadata address must be refused")
	}
	f := NewCIMDFetcher()
	f.AllowPrivateNetworks = true
	f.TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig
	if _, err := f.jwks(ctx, ts.URL+"/jwks.json", false); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirects must not be followed, got %v", err)
	}
	if _, err := f.jwks(ctx, ts.URL+"/big", false); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized jwks must be refused, got %v", err)
	}
	if _, err := f.jwks(ctx, "http://keys.example/jwks.json", false); err == nil {
		t.Fatal("non-https jwks_uri must be refused")
	}
}
