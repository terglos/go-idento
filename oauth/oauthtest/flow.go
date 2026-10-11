package oauthtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
)

const (
	issuer    = "https://as.example.com"
	resourceA = "https://api.example.com/v1/mcp"
	resourceB = "https://api.example.com/other"
	clientCB  = "https://client.example/callback"
)

type harness struct {
	t       *testing.T
	srv     *oauth.Server
	mux     *http.ServeMux
	um      *identity.UserManager
	tokens  *identity.TokenService
	user    *identity.User
	consent *oauth.ConsentRequest
	clock   time.Duration // added to time.Now (purge tests)
}

func newHarness(t *testing.T, newEnv EnvFactory) *harness {
	t.Helper()
	st, um := newEnv(t)
	tokens := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("oauth-e2e-signing-key-00000000000"), "go-idento", "app"))
	h := &harness{t: t, um: um, tokens: tokens}
	srv, err := oauth.NewServer(um, tokens, st, oauth.Options{
		Issuer:        issuer,
		Resources:     []string{resourceA, resourceB},
		Scopes:        []string{"read", "write", oauth.ScopeOfflineAccess},
		DefaultScopes: []string{"read"},
		AllowDCR:      true,
		RegisterLimit: -1,
		CurrentUser: func(r *http.Request) (string, bool) {
			id := r.Header.Get("X-Test-User")
			return id, id != ""
		},
		LoginURL: func(_ *http.Request, returnTo string) string {
			return "https://app.example.com/login?return_to=" + url.QueryEscape(returnTo)
		},
		RenderConsent: func(w http.ResponseWriter, _ *http.Request, c oauth.ConsentRequest) {
			h.consent = &c
			_, _ = w.Write([]byte("consent page"))
		},
		Now: func() time.Time { return time.Now().Add(h.clock) },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h.srv = srv
	h.mux = http.NewServeMux()
	srv.Routes(h.mux)
	metaA, _ := oauth.ResourceMetadataURL(resourceA)
	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"user": p.User.ID, "client": p.ClientID,
			"oauth": p.ViaOAuth, "scopes": p.Scopes})
	})
	mw := func(res string) func(http.Handler) http.Handler {
		return auth.Middleware(tokens, nil, auth.WithOAuthResource(srv, res))
	}
	h.mux.Handle("/v1/mcp", mw(resourceA)(oauth.RequireScopes(metaA, "read")(who)))
	h.mux.Handle("/v1/mcp/write", mw(resourceA)(oauth.RequireScopes(metaA, "write")(who)))
	metaB, _ := oauth.ResourceMetadataURL(resourceB)
	h.mux.Handle("/other", mw(resourceB)(oauth.RequireScopes(metaB, "read")(who)))
	h.user = mustUser(t, um, uniq("owner"))
	return h
}

func (h *harness) serve(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rec.Code, rec.Body.String())
	}
	return m
}

func pkce() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (h *harness) register(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return h.serve(r)
}

func (h *harness) registerPublic(redirects ...string) string {
	h.t.Helper()
	b, _ := json.Marshal(map[string]any{"redirect_uris": redirects, "token_endpoint_auth_method": "none",
		"grant_types": []string{"authorization_code", "refresh_token"}, "client_name": "E2E Client"})
	rec := h.register(string(b))
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	return decode(h.t, rec)["client_id"].(string)
}

func authzQuery(clientID, redirect, challenge, scope, resource string) url.Values {
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"state": {"st-123"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if scope != "" {
		q.Set("scope", scope)
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	return q
}

func (h *harness) authorize(q url.Values, signedIn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	if signedIn {
		r.Header.Set("X-Test-User", h.user.ID)
	}
	return h.serve(r)
}

func (h *harness) decide(decision string) *httptest.ResponseRecorder {
	h.t.Helper()
	if h.consent == nil {
		h.t.Fatal("no consent page was rendered")
	}
	f := url.Values{}
	for k, v := range h.consent.Fields {
		f[k] = v
	}
	f.Set("decision", decision)
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Test-User", h.user.ID)
	return h.serve(r)
}

// redirectParams parses the client redirect and checks state/iss echo.
func (h *harness) redirectParams(rec *httptest.ResponseRecorder, wantPrefix string) url.Values {
	h.t.Helper()
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		h.t.Fatalf("expected a redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, wantPrefix) {
		h.t.Fatalf("redirect to %q, want prefix %q", loc, wantPrefix)
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	if q.Get("state") != "st-123" || q.Get("iss") != issuer {
		h.t.Fatalf("redirect must echo state and carry iss: %s", loc)
	}
	return q
}

func (h *harness) token(form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		r.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	return h.serve(r)
}

// connect runs authorize (consenting if asked) → code exchange and returns the
// token response.
func (h *harness) connect(clientID, redirect, scope, resource string) map[string]any {
	h.t.Helper()
	verifier, challenge := pkce()
	h.consent = nil
	rec := h.authorize(authzQuery(clientID, redirect, challenge, scope, resource), true)
	if rec.Code == http.StatusOK {
		rec = h.decide("approve")
	}
	code := h.redirectParams(rec, redirect).Get("code")
	if code == "" {
		h.t.Fatal("no code in redirect")
	}
	tr := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource}}, "", "")
	if tr.Code != http.StatusOK {
		h.t.Fatalf("code exchange: %d %s", tr.Code, tr.Body.String())
	}
	return decode(h.t, tr)
}

func (h *harness) call(path, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.serve(r)
}

func (h *harness) refresh(clientID, rt string) *httptest.ResponseRecorder {
	return h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}, "", "")
}

func wantOAuthError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("want HTTP %d %s, got %d: %s", status, code, rec.Code, rec.Body.String())
	}
	if got := decode(t, rec)["error"]; got != code {
		t.Fatalf("want error %q, got %v", code, got)
	}
}

// RunEndToEnd drives the authorization server and a protected resource
// through the full OAuth 2.1 profile used by MCP clients.
func RunEndToEnd(t *testing.T, newEnv EnvFactory) {
	t.Run("Metadata", func(t *testing.T) {
		h := newHarness(t, newEnv)
		rec := h.serve(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("metadata: %d cors=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
		}
		m := decode(t, rec)
		if m["issuer"] != issuer || m["token_endpoint"] != issuer+"/oauth/token" ||
			m["registration_endpoint"] != issuer+"/oauth/register" {
			t.Fatalf("metadata endpoints: %v", m)
		}
		methods, _ := json.Marshal(m["code_challenge_methods_supported"])
		auths, _ := json.Marshal(m["token_endpoint_auth_methods_supported"])
		if string(methods) != `["S256"]` || !strings.Contains(string(auths), `"none"`) {
			t.Fatalf("PKCE S256 and auth method none must be advertised: %s %s", methods, auths)
		}
		pre := httptest.NewRequest(http.MethodOptions, "/oauth/token", nil)
		if rec := h.serve(pre); rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Fatalf("CORS preflight on token endpoint: %d", rec.Code)
		}
	})

	t.Run("FullFlowRefreshRotationAndReuse", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)

		// Anonymous → login redirect carrying the authorize URL.
		_, challenge := pkce()
		rec := h.authorize(authzQuery(clientID, clientCB, challenge, "read offline_access", resourceA), false)
		if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://app.example.com/login?return_to=") ||
			!strings.Contains(rec.Header().Get("Location"), url.QueryEscape(issuer+"/oauth/authorize?")) {
			t.Fatalf("anonymous authorize must redirect to login: %d %s", rec.Code, rec.Header().Get("Location"))
		}

		tok := h.connect(clientID, clientCB, "read offline_access", resourceA)
		if h.consent == nil || h.consent.RedirectHost != "client.example" || h.consent.ClientName != "E2E Client" {
			t.Fatalf("consent must show the client and redirect host: %+v", h.consent)
		}
		if tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || tok["scope"] != "read offline_access" ||
			tok["expires_in"].(float64) <= 0 {
			t.Fatalf("token response: %v", tok)
		}
		at, rt := tok["access_token"].(string), tok["refresh_token"].(string)

		// The resource accepts it and exposes OAuth identity.
		res := h.call("/v1/mcp", at)
		if res.Code != http.StatusOK {
			t.Fatalf("resource call: %d %s", res.Code, res.Body.String())
		}
		if p := decode(t, res); p["oauth"] != true || p["client"] != clientID || p["user"] != h.user.ID {
			t.Fatalf("principal: %v", p)
		}

		// Refresh rotates; the old refresh token is now a reuse → whole grant revoked.
		r2 := h.refresh(clientID, rt)
		if r2.Code != http.StatusOK {
			t.Fatalf("refresh: %d %s", r2.Code, r2.Body.String())
		}
		tok2 := decode(t, r2)
		rt2, at2 := tok2["refresh_token"].(string), tok2["access_token"].(string)
		if rt2 == rt || !strings.HasPrefix(rt2, strings.SplitN(rt, ".", 2)[0]+".") {
			t.Fatal("refresh must rotate within the same grant")
		}
		if h.call("/v1/mcp", at2).Code != http.StatusOK {
			t.Fatal("refreshed access token must work")
		}
		wantOAuthError(t, h.refresh(clientID, rt), http.StatusBadRequest, "invalid_grant")
		wantOAuthError(t, h.refresh(clientID, rt2), http.StatusBadRequest, "invalid_grant")
		if h.call("/v1/mcp", at2).Code != http.StatusUnauthorized {
			t.Fatal("refresh-token reuse must revoke the grant's access tokens immediately")
		}
	})

	t.Run("RevokeEndpointAndConsentMemory", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		h.connect(clientID, clientCB, "read", resourceA)

		// Same scopes again: consent remembered, no page.
		h.consent = nil
		tok := h.connect(clientID, clientCB, "read", resourceA)
		if h.consent != nil {
			t.Fatal("a remembered consent must skip the consent page")
		}
		at, rt := tok["access_token"].(string), tok["refresh_token"].(string)

		form := url.Values{"token": {rt}, "client_id": {clientID}}
		r := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if rec := h.serve(r); rec.Code != http.StatusOK {
			t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
		}
		wantOAuthError(t, h.refresh(clientID, rt), http.StatusBadRequest, "invalid_grant")
		if h.call("/v1/mcp", at).Code != http.StatusUnauthorized {
			t.Fatal("revocation must kill the grant's access tokens")
		}

		// Broader scopes than consented → the page is shown again.
		h.consent = nil
		_, challenge := pkce()
		if rec := h.authorize(authzQuery(clientID, clientCB, challenge, "read write", resourceA), true); rec.Code != http.StatusOK || h.consent == nil {
			t.Fatalf("new scopes must ask for consent again: %d", rec.Code)
		}
		// Deny → access_denied redirect.
		q := h.redirectParams(h.decide("deny"), clientCB)
		if q.Get("error") != "access_denied" {
			t.Fatalf("deny must redirect access_denied: %v", q)
		}
	})

	t.Run("CodeReplayRevokesGrant", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		verifier, challenge := pkce()
		rec := h.authorize(authzQuery(clientID, clientCB, challenge, "read", resourceA), true)
		code := h.redirectParams(h.decide("approve"), clientCB).Get("code")
		if rec.Code != http.StatusOK {
			t.Fatalf("authorize: %d", rec.Code)
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "client_id": {clientID}}
		first := h.token(form, "", "")
		if first.Code != http.StatusOK {
			t.Fatalf("first exchange: %d %s", first.Code, first.Body.String())
		}
		at := decode(t, first)["access_token"].(string)
		wantOAuthError(t, h.token(form, "", ""), http.StatusBadRequest, "invalid_grant")
		if h.call("/v1/mcp", at).Code != http.StatusUnauthorized {
			t.Fatal("a replayed code must revoke the tokens issued from it")
		}
	})

	t.Run("PKCEAndRequestValidation", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)

		// Missing / plain PKCE → error redirected to the (valid) client.
		q := authzQuery(clientID, clientCB, "", "read", resourceA)
		if e := h.redirectParams(h.authorize(q, true), clientCB).Get("error"); e != "invalid_request" {
			t.Fatalf("missing PKCE must be invalid_request, got %q", e)
		}
		_, challenge := pkce()
		q = authzQuery(clientID, clientCB, challenge, "read", resourceA)
		q.Set("code_challenge_method", "plain")
		if e := h.redirectParams(h.authorize(q, true), clientCB).Get("error"); e != "invalid_request" {
			t.Fatalf("plain PKCE must be rejected, got %q", e)
		}
		// Unknown scope / resource.
		if e := h.redirectParams(h.authorize(authzQuery(clientID, clientCB, challenge, "admin", resourceA), true), clientCB).Get("error"); e != "invalid_scope" {
			t.Fatalf("unknown scope must be invalid_scope, got %q", e)
		}
		if e := h.redirectParams(h.authorize(authzQuery(clientID, clientCB, challenge, "read", "https://evil.example/mcp"), true), clientCB).Get("error"); e != "invalid_target" {
			t.Fatalf("unknown resource must be invalid_target, got %q", e)
		}
		// Unregistered redirect → error page, never a redirect.
		rec := h.authorize(authzQuery(clientID, "https://attacker.example/cb", challenge, "read", resourceA), true)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("unregistered redirect_uri must not redirect: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		// Wrong verifier → invalid_grant.
		h.consent = nil
		rec = h.authorize(authzQuery(clientID, clientCB, challenge, "read", resourceA), true)
		if rec.Code == http.StatusOK {
			rec = h.decide("approve")
		}
		code := h.redirectParams(rec, clientCB).Get("code")
		other, _ := pkce()
		wantOAuthError(t, h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {other}, "client_id": {clientID}}, "", ""), http.StatusBadRequest, "invalid_grant")
		// Token endpoint only speaks form encoding.
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
		r.Header.Set("Content-Type", "application/json")
		wantOAuthError(t, h.serve(r), http.StatusBadRequest, "invalid_request")
	})

	t.Run("LoopbackRedirectAnyPort", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic("http://127.0.0.1/callback")
		tok := h.connect(clientID, "http://127.0.0.1:54321/callback", "read", resourceA)
		if tok["access_token"] == nil {
			t.Fatal("loopback redirect on an ephemeral port must be accepted")
		}
		if !h.consent.LoopbackOnly {
			t.Fatal("consent must flag loopback-only clients")
		}
		_, challenge := pkce()
		for _, bad := range []string{"http://localhost:54321/callback", "http://127.0.0.1:54321/other", "https://127.0.0.1/callback"} {
			if rec := h.authorize(authzQuery(clientID, bad, challenge, "read", resourceA), true); rec.Code != http.StatusBadRequest {
				t.Fatalf("redirect %q must be refused, got %d", bad, rec.Code)
			}
		}
	})

	t.Run("ConfidentialClient", func(t *testing.T) {
		h := newHarness(t, newEnv)
		rec := h.register(`{"redirect_uris":["https://client.example/callback"],"token_endpoint_auth_method":"client_secret_basic","grant_types":["authorization_code","refresh_token"]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register confidential: %d %s", rec.Code, rec.Body.String())
		}
		reg := decode(t, rec)
		id, secret := reg["client_id"].(string), reg["client_secret"].(string)
		if secret == "" {
			t.Fatal("confidential registration must return a secret")
		}
		verifier, challenge := pkce()
		h.authorize(authzQuery(id, clientCB, challenge, "read", resourceA), true)
		code := h.redirectParams(h.decide("approve"), clientCB).Get("code")
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
		bad := h.token(form, id, "wrong-secret")
		wantOAuthError(t, bad, http.StatusUnauthorized, "invalid_client")
		if !strings.HasPrefix(bad.Header().Get("WWW-Authenticate"), "Basic") {
			t.Fatal("invalid_client over Basic must challenge with WWW-Authenticate: Basic")
		}
		if ok := h.token(form, id, secret); ok.Code != http.StatusOK {
			t.Fatalf("client_secret_basic exchange: %d %s", ok.Code, ok.Body.String())
		}
		// Unsupported DCR metadata is rejected.
		if rec := h.register(`{"redirect_uris":["http://evil.example/cb"]}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("non-loopback http redirect must be rejected at registration: %d", rec.Code)
		}
	})

	t.Run("AudienceAndTokenSeparation", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		at := h.connect(clientID, clientCB, "read", resourceA)["access_token"].(string)
		if h.call("/other", at).Code != http.StatusUnauthorized {
			t.Fatal("a token for resource A must be rejected by resource B (audience binding)")
		}
		if _, _, err := h.tokens.ValidateAccessToken(context.Background(), at); err == nil {
			t.Fatal("an OAuth access token must not validate as an app session token")
		}
		pair, err := h.tokens.IssuePair(context.Background(), h.user)
		if err != nil {
			t.Fatalf("session pair: %v", err)
		}
		if _, _, err := h.srv.ValidateResourceToken(context.Background(), pair.AccessToken, resourceA); err == nil {
			t.Fatal("an app session token must not validate as an OAuth resource token")
		}
	})

	t.Run("SecurityStampRevokesGrants", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		tok := h.connect(clientID, clientCB, "read", resourceA)
		u, _ := h.um.FindByID(context.Background(), h.user.ID)
		if err := h.um.UpdateSecurityStamp(context.Background(), u); err != nil {
			t.Fatalf("UpdateSecurityStamp: %v", err)
		}
		if h.call("/v1/mcp", tok["access_token"].(string)).Code != http.StatusUnauthorized {
			t.Fatal("a security-stamp change must revoke OAuth access tokens")
		}
		wantOAuthError(t, h.refresh(clientID, tok["refresh_token"].(string)), http.StatusBadRequest, "invalid_grant")
	})

	t.Run("ChallengeAndStepUp", func(t *testing.T) {
		h := newHarness(t, newEnv)
		rec := h.call("/v1/mcp", "")
		if rec.Code != http.StatusUnauthorized ||
			rec.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/v1/mcp", scope="read"` {
			t.Fatalf("anonymous call must get the 401 challenge: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
		clientID := h.registerPublic(clientCB)
		at := h.connect(clientID, clientCB, "read", resourceA)["access_token"].(string)
		rec = h.call("/v1/mcp/write", at)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) ||
			!strings.Contains(rec.Header().Get("WWW-Authenticate"), `scope="read write"`) {
			t.Fatalf("missing scope must answer 403 insufficient_scope: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("ScopeNarrowingOnRefresh", func(t *testing.T) {
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		tok := h.connect(clientID, clientCB, "read write", resourceA)
		r := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
			"client_id": {clientID}, "scope": {"read"}}, "", "")
		if r.Code != http.StatusOK || decode(t, r)["scope"] != "read" {
			t.Fatalf("narrowed refresh: %d %s", r.Code, r.Body.String())
		}
		tok2 := decode(t, r)
		wantOAuthError(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2["refresh_token"].(string)},
			"client_id": {clientID}, "scope": {"read write offline_access"}}, "", ""), http.StatusBadRequest, "invalid_scope")
	})

	t.Run("ConnectedAppsAndPurge", func(t *testing.T) {
		ctx := context.Background()
		h := newHarness(t, newEnv)
		clientID := h.registerPublic(clientCB)
		tok := h.connect(clientID, clientCB, "read", resourceA)
		grants, err := h.srv.ListGrants(ctx, h.user.ID)
		if err != nil || len(grants) != 1 || grants[0].ClientID != clientID || grants[0].Resource != resourceA {
			t.Fatalf("ListGrants: %+v err=%v", grants, err)
		}
		if err := h.srv.RevokeClient(ctx, h.user.ID, clientID); err != nil {
			t.Fatalf("RevokeClient: %v", err)
		}
		if h.call("/v1/mcp", tok["access_token"].(string)).Code != http.StatusUnauthorized {
			t.Fatal("disconnecting the app must kill its access tokens")
		}
		h.consent = nil
		_, challenge := pkce()
		if h.authorize(authzQuery(clientID, clientCB, challenge, "read", resourceA), true); h.consent == nil {
			t.Fatal("disconnecting the app must forget the consent")
		}
		// A never-used client registered now is purged once it is old enough.
		stale := h.registerPublic("https://stale.example/cb")
		h.clock = 40 * 24 * time.Hour
		if n, err := h.srv.PurgeStaleClients(ctx, time.Now().Add(h.clock-24*time.Hour)); err != nil || n < 1 {
			t.Fatalf("PurgeStaleClients: n=%d err=%v", n, err)
		}
		_, challenge = pkce()
		if rec := h.authorize(authzQuery(stale, "https://stale.example/cb", challenge, "read", resourceA), true); rec.Code != http.StatusBadRequest {
			t.Fatal("a purged client must be unknown")
		}
		if _, _, err := h.srv.PurgeExpired(ctx); err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
	})
}
