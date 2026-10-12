package oauthtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terglos/go-idento/oauth"
)

// clientSite is an HTTPS site publishing Client ID Metadata Documents and JWK
// Sets, standing in for a client such as ChatGPT
// (https://chatgpt.com/oauth/client.json + jwks_uri).
type clientSite struct {
	ts   *httptest.Server
	mu   sync.Mutex
	docs map[string]any // path -> JSON body
}

func newClientSite(t *testing.T) *clientSite {
	t.Helper()
	cs := &clientSite{docs: map[string]any{}}
	cs.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		body, ok := cs.docs[r.URL.Path]
		cs.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(cs.ts.Close)
	return cs
}

func (cs *clientSite) url(path string) string { return cs.ts.URL + path }

func (cs *clientSite) set(path string, body any) {
	cs.mu.Lock()
	cs.docs[path] = body
	cs.mu.Unlock()
}

// options lets the authorization server fetch from the (loopback, self-signed)
// test site; JWKSMinRefresh is shortened so key rotation is observable.
func (cs *clientSite) options(o *oauth.Options) {
	f := oauth.NewCIMDFetcher()
	f.AllowPrivateNetworks = true
	f.TLSClientConfig = cs.ts.Client().Transport.(*http.Transport).TLSClientConfig
	f.JWKSMinRefresh = time.Nanosecond
	o.AllowCIMD = true
	o.CIMD = f
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, k *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes())}
}

func ecJWK(kid string, k *ecdsa.PublicKey) map[string]any {
	p, _ := k.Bytes() // 0x04 || X || Y
	return map[string]any{"kty": "EC", "kid": kid, "crv": "P-256", "x": b64u(p[1:33]), "y": b64u(p[33:])}
}

func jwkSet(keys ...map[string]any) map[string]any { return map[string]any{"keys": keys} }

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// assertionClaims is a valid RFC 7523 client assertion body for clientID, with
// a random jti (a timestamp is not unique enough: back-to-back assertions
// would collide and be refused as replays).
func assertionClaims(clientID, aud string) jwt.MapClaims {
	now := time.Now()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	return jwt.MapClaims{"iss": clientID, "sub": clientID, "aud": aud, "jti": b64u(jti),
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix()}
}

func signAssertion(t *testing.T, m jwt.SigningMethod, key crypto.Signer, kid string, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(m, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func withAssertion(f url.Values, assertion string) url.Values {
	out := url.Values{}
	for k, v := range f {
		out[k] = append([]string(nil), v...)
	}
	out.Set("client_assertion_type", oauth.ClientAssertionTypeJWTBearer)
	out.Set("client_assertion", assertion)
	return out
}

func (h *harness) revoke(f url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.serve(r)
}

// authorizeCode runs authorize → consent for clientID and returns the code
// and PKCE verifier.
func (h *harness) authorizeCode(clientID, scope string) (code, verifier string) {
	h.t.Helper()
	verifier, challenge := pkce()
	h.consent = nil
	rec := h.authorize(authzQuery(clientID, clientCB, challenge, scope, resourceA), true)
	if rec.Code != http.StatusOK || h.consent == nil {
		h.t.Fatalf("expected the consent page for %s, got %d: %s", clientID, rec.Code, rec.Body.String())
	}
	return h.redirectParams(h.decide("approve"), clientCB).Get("code"), verifier
}

// runPrivateKeyJWT: a CIMD client declaring private_key_jwt + RS256 + jwks_uri
// (the shape ChatGPT publishes) must authenticate every token and revocation
// request with an RFC 7523 assertion, and every malformed, foreign, expired,
// overlong or replayed assertion is refused with invalid_client.
func runPrivateKeyJWT(t *testing.T, newEnv EnvFactory) {
	site := newClientSite(t)
	key := newRSAKey(t)
	clientID, jwksURI := site.url("/oauth/client.json"), site.url("/oauth/jwks.json")
	site.set("/oauth/client.json", map[string]any{
		"client_id": clientID, "client_name": "ChatGPT", "redirect_uris": []string{clientCB},
		"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "RS256",
		"jwks_uri": jwksURI, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
	})
	site.set("/oauth/jwks.json", jwkSet(rsaJWK("k1", &key.PublicKey)))
	h := newHarness(t, newEnv, site.options)
	tokenEP, revokeEP := issuer+"/oauth/token", issuer+"/oauth/revoke"
	sign := func(c jwt.MapClaims) string { return signAssertion(t, jwt.SigningMethodRS256, key, "k1", c) }

	// Metadata advertises the method and its algorithms.
	m := decode(t, h.serve(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)))
	for _, field := range []string{"token_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"} {
		if b, _ := json.Marshal(m[field]); !strings.Contains(string(b), `"private_key_jwt"`) {
			t.Fatalf("%s must list private_key_jwt: %s", field, b)
		}
	}
	for _, field := range []string{"token_endpoint_auth_signing_alg_values_supported", "revocation_endpoint_auth_signing_alg_values_supported"} {
		if b, _ := json.Marshal(m[field]); string(b) != `["RS256","ES256"]` {
			t.Fatalf("%s = %s, want RS256 and ES256", field, b)
		}
	}

	code, verifier := h.authorizeCode(clientID, "read offline_access")
	if h.consent.ClientHost != hostOf(clientID) {
		t.Fatalf("consent must show the client_id host, got %q", h.consent.ClientHost)
	}
	exch := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {clientCB}, "resource": {resourceA}}

	// No assertion: the document registered private_key_jwt, so none/secret
	// authentication is refused (draft §8.2).
	noAuth := url.Values{"client_id": {clientID}}
	for k, v := range exch {
		noAuth[k] = v
	}
	wantOAuthError(t, h.token(noAuth, "", ""), http.StatusUnauthorized, "invalid_client")

	other := newRSAKey(t)
	ec := newECKey(t)
	expired := assertionClaims(clientID, tokenEP)
	expired["iat"], expired["exp"] = time.Now().Add(-10*time.Minute).Unix(), time.Now().Add(-5*time.Minute).Unix()
	foreignIss := assertionClaims(clientID, tokenEP)
	foreignIss["iss"] = "https://evil.example/client.json"
	tooLong := assertionClaims(clientID, tokenEP)
	tooLong["exp"] = time.Now().Add(2 * time.Hour).Unix()
	noJTI := assertionClaims(clientID, tokenEP)
	delete(noJTI, "jti")
	future := assertionClaims(clientID, tokenEP)
	future["iat"] = time.Now().Add(10 * time.Minute).Unix()
	unsignedHdr := b64u([]byte(`{"alg":"none","typ":"JWT"}`))
	unsignedBody, _ := json.Marshal(assertionClaims(clientID, tokenEP))
	for name, a := range map[string]string{
		"wrong audience":          sign(assertionClaims(clientID, "https://other-as.example/token")),
		"expired":                 sign(expired),
		"iss differs from sub":    sign(foreignIss),
		"exp beyond max":          sign(tooLong),
		"missing jti":             sign(noJTI),
		"issued in the future":    sign(future),
		"unknown key":             signAssertion(t, jwt.SigningMethodRS256, other, "k1", assertionClaims(clientID, tokenEP)),
		"undeclared algorithm":    signAssertion(t, jwt.SigningMethodES256, ec, "k1", assertionClaims(clientID, tokenEP)),
		"unsigned (alg none)":     unsignedHdr + "." + b64u(unsignedBody) + ".",
		"not a JWT":               "garbage",
		"client_id param differs": sign(assertionClaims(clientID, tokenEP)),
	} {
		f := withAssertion(exch, a)
		if name == "client_id param differs" {
			f.Set("client_id", "https://another.example/client.json")
		}
		if rec := h.token(f, "", ""); rec.Code != http.StatusUnauthorized || decode(t, rec)["error"] != "invalid_client" {
			t.Fatalf("%s: want 401 invalid_client, got %d %s", name, rec.Code, rec.Body.String())
		}
	}
	badType := withAssertion(exch, sign(assertionClaims(clientID, tokenEP)))
	badType.Set("client_assertion_type", "urn:example:other")
	wantOAuthError(t, h.token(badType, "", ""), http.StatusUnauthorized, "invalid_client")
	mixed := withAssertion(exch, sign(assertionClaims(clientID, tokenEP)))
	mixed.Set("client_secret", "x")
	wantOAuthError(t, h.token(mixed, "", ""), http.StatusBadRequest, "invalid_request")

	// A valid assertion (aud = token endpoint, client_id sent) exchanges the code.
	good := sign(assertionClaims(clientID, tokenEP))
	f := withAssertion(exch, good)
	f.Set("client_id", clientID)
	tr := h.token(f, "", "")
	if tr.Code != http.StatusOK {
		t.Fatalf("code exchange with private_key_jwt: %d %s", tr.Code, tr.Body.String())
	}
	tok := decode(t, tr)
	at, rt := tok["access_token"].(string), tok["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("want access and refresh tokens: %v", tok)
	}
	if rec := h.call("/v1/mcp", at); rec.Code != http.StatusOK || decode(t, rec)["client"] != clientID {
		t.Fatalf("resource call: %d %s", rec.Code, rec.Body.String())
	}

	// The same assertion can't be replayed; refresh needs a fresh one.
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	wantOAuthError(t, h.token(withAssertion(refresh, good), "", ""), http.StatusUnauthorized, "invalid_client")
	wantOAuthError(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}, "", ""),
		http.StatusUnauthorized, "invalid_client")
	rr := h.token(withAssertion(refresh, sign(assertionClaims(clientID, issuer))), "", "") // aud = issuer
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh with a fresh assertion (aud = issuer): %d %s", rr.Code, rr.Body.String())
	}
	rt = decode(t, rr)["refresh_token"].(string)

	// Key rotation: the client publishes k2 and drops k1; an assertion naming
	// the unknown kid makes the server re-fetch jwks_uri.
	key2 := newRSAKey(t)
	site.set("/oauth/jwks.json", jwkSet(rsaJWK("k2", &key2.PublicKey)))
	refresh.Set("refresh_token", rt)
	rr = h.token(withAssertion(refresh, signAssertion(t, jwt.SigningMethodRS256, key2, "k2", assertionClaims(clientID, tokenEP))), "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("assertion signed with the rotated key: %d %s", rr.Code, rr.Body.String())
	}
	rt = decode(t, rr)["refresh_token"].(string)
	refresh.Set("refresh_token", rt)
	wantOAuthError(t, h.token(withAssertion(refresh, sign(assertionClaims(clientID, tokenEP))), "", ""),
		http.StatusUnauthorized, "invalid_client") // k1 is gone

	// Revocation authenticates the same way (aud = revocation endpoint).
	wantOAuthError(t, h.revoke(url.Values{"token": {rt}, "client_id": {clientID}}), http.StatusUnauthorized, "invalid_client")
	rv := h.revoke(withAssertion(url.Values{"token": {rt}},
		signAssertion(t, jwt.SigningMethodRS256, key2, "k2", assertionClaims(clientID, revokeEP))))
	if rv.Code != http.StatusOK {
		t.Fatalf("revoke with private_key_jwt: %d %s", rv.Code, rv.Body.String())
	}
	wantOAuthError(t, h.token(withAssertion(refresh, signAssertion(t, jwt.SigningMethodRS256, key2, "k2",
		assertionClaims(clientID, tokenEP))), "", ""), http.StatusBadRequest, "invalid_grant")
}

// runPrivateKeyJWTInline: keys inline in the document (jwks), ES256, no
// declared algorithm, assertion without kid; and an assertion is refused for a
// client that did not register private_key_jwt.
func runPrivateKeyJWTInline(t *testing.T, newEnv EnvFactory) {
	site := newClientSite(t)
	key := newECKey(t)
	clientID := site.url("/inline/client.json")
	site.set("/inline/client.json", map[string]any{
		"client_id": clientID, "client_name": "Inline Keys", "redirect_uris": []string{clientCB},
		"token_endpoint_auth_method": "private_key_jwt", "jwks": jwkSet(ecJWK("ec1", &key.PublicKey)),
	})
	h := newHarness(t, newEnv, site.options)

	code, verifier := h.authorizeCode(clientID, "read")
	exch := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
	tr := h.token(withAssertion(exch, signAssertion(t, jwt.SigningMethodES256, key, "", assertionClaims(clientID, issuer))), "", "")
	if tr.Code != http.StatusOK {
		t.Fatalf("ES256 assertion with inline jwks: %d %s", tr.Code, tr.Body.String())
	}
	if at, _ := decode(t, tr)["access_token"].(string); h.call("/v1/mcp", at).Code != http.StatusOK {
		t.Fatal("access token from an inline-keys client must work at the resource")
	}

	// A public DCR client can't switch to assertions.
	pub := h.registerPublic(clientCB)
	code, verifier = h.authorizeCode(pub, "read")
	exch = url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
	wantOAuthError(t, h.token(withAssertion(exch, signAssertion(t, jwt.SigningMethodES256, key, "",
		assertionClaims(pub, issuer+"/oauth/token"))), "", ""), http.StatusUnauthorized, "invalid_client")
}

func hostOf(s string) string {
	u, _ := url.Parse(s)
	return u.Host
}
