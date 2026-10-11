package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/stores/memstore"
)

func newServer(t *testing.T, mutate func(*oauth.Options)) (*oauth.Server, *http.ServeMux, *identity.User, *oauth.ConsentRequest) {
	t.Helper()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	tokens := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("oauth-unit-signing-key-0000000000"), "go-idento", "app"))
	u := &identity.User{UserName: "owner", Email: "owner@example.com"}
	if err := um.CreateWithPassword(context.Background(), u, "Abcdef1!"); err != nil {
		t.Fatal(err)
	}
	consent := &oauth.ConsentRequest{}
	opts := oauth.Options{
		Issuer:    "https://as.example.com",
		Resources: []string{"https://api.example.com/v1/mcp"},
		Scopes:    []string{"read", oauth.ScopeOfflineAccess},
		AllowDCR:  true,
		AllowCIMD: true,
		CurrentUser: func(r *http.Request) (string, bool) {
			id := r.Header.Get("X-Test-User")
			return id, id != ""
		},
		LoginURL: func(_ *http.Request, rt string) string { return "/login?return_to=" + url.QueryEscape(rt) },
		RenderConsent: func(w http.ResponseWriter, _ *http.Request, c oauth.ConsentRequest) {
			*consent = c
			_, _ = w.Write([]byte("consent"))
		},
	}
	if mutate != nil {
		mutate(&opts)
	}
	srv, err := oauth.NewServer(um, tokens, st.OAuth(), opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	mux := http.NewServeMux()
	srv.Routes(mux)
	return srv, mux, u, consent
}

func pkcePair() (string, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

// cimdServer hosts metadata documents over TLS on loopback.
func cimdServer(t *testing.T) (*httptest.Server, *oauth.CIMDFetcher) {
	t.Helper()
	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	doc := func(clientID string, extra map[string]any) []byte {
		m := map[string]any{"client_id": clientID, "client_name": "Claude Code",
			"redirect_uris":              []string{"http://localhost/callback", "http://127.0.0.1/callback"},
			"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return b
	}
	mux.HandleFunc("/client.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc(ts.URL+"/client.json", nil))
	})
	mux.HandleFunc("/mismatch.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc("https://other.example/client.json", nil))
	})
	mux.HandleFunc("/secret.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc(ts.URL+"/secret.json", map[string]any{"client_secret": "x"}))
	})
	mux.HandleFunc("/basic.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc(ts.URL+"/basic.json", map[string]any{"token_endpoint_auth_method": "client_secret_basic"}))
	})
	mux.HandleFunc("/redirect.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/client.json", http.StatusFound)
	})
	mux.HandleFunc("/big.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(doc(ts.URL+"/big.json", map[string]any{"padding": strings.Repeat("x", 10*1024)}))
	})
	f := oauth.NewCIMDFetcher()
	f.AllowPrivateNetworks = true // the test server listens on loopback
	f.TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig
	return ts, f
}

func TestCIMDFlow(t *testing.T) {
	ts, fetcher := cimdServer(t)
	_, mux, u, consent := newServer(t, func(o *oauth.Options) { o.CIMD = fetcher })
	clientID := ts.URL + "/client.json"
	verifier, challenge := pkcePair()
	redirect := "http://127.0.0.1:61234/callback" // ephemeral loopback port
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"read offline_access"}}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-Test-User", u.ID)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CIMD authorize: %d %s", rec.Code, rec.Body.String())
	}
	if consent.ClientHost != strings.TrimPrefix(ts.URL, "https://") || consent.ClientName != "Claude Code" || !consent.LoopbackOnly {
		t.Fatalf("consent must show the client_id host (not just the self-asserted name) and warn on loopback: %+v", consent)
	}
	f := url.Values{}
	for k, v := range consent.Fields {
		f[k] = v
	}
	f.Set("decision", "approve")
	req = httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-User", u.ID)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("approve must redirect with a code: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {"https://api.example.com/v1/mcp"}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "refresh_token") {
		t.Fatalf("CIMD token exchange: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCIMDRejections(t *testing.T) {
	ts, fetcher := cimdServer(t)
	ctx := context.Background()
	for path, why := range map[string]string{
		"/mismatch.json": "document client_id must equal the URL",
		"/secret.json":   "documents must not carry a client secret",
		"/basic.json":    "shared-secret auth methods are forbidden",
		"/redirect.json": "redirects must not be followed",
		"/big.json":      "documents over 5 KB are refused",
		"/missing.json":  "non-200 responses are errors",
	} {
		if _, err := fetcher.Resolve(ctx, ts.URL+path); err == nil {
			t.Errorf("%s: %s", path, why)
		}
	}
	for _, bad := range []string{"http://example.com/c.json", "https://example.com", "https://example.com/",
		"https://user@example.com/c.json", "https://example.com/a/../c.json", "https://example.com/c.json#f"} {
		if _, err := fetcher.Resolve(ctx, bad); err == nil {
			t.Errorf("client_id URL %q must be rejected", bad)
		}
	}
}

func TestCIMDBlocksPrivateNetworks(t *testing.T) {
	ts, _ := cimdServer(t)
	f := oauth.NewCIMDFetcher() // production defaults: special-use IPs refused at dial time
	_, err := f.Resolve(context.Background(), ts.URL+"/client.json")
	if err == nil || !strings.Contains(err.Error(), "special-use") {
		t.Fatalf("a loopback client_id URL must be refused by the default fetcher, got %v", err)
	}
	if _, err := f.Resolve(context.Background(), "https://169.254.169.254/latest/meta-data.json"); err == nil {
		t.Fatal("the cloud metadata address must be refused")
	}
}

func TestDCRRateLimit(t *testing.T) {
	_, mux, _, _ := newServer(t, func(o *oauth.Options) { o.RegisterLimit = 2 })
	body := `{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"none"}`
	codes := []int{}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if fmt.Sprint(codes) != "[201 201 429]" {
		t.Fatalf("DCR must be rate-limited per IP, got %v", codes)
	}
}

func TestNewServerValidation(t *testing.T) {
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	tokens := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("k-000000000000000000000000000000"), "i", "a"))
	base := oauth.Options{Issuer: "https://as.example.com", Resources: []string{"https://api.example.com/mcp"},
		CurrentUser: func(*http.Request) (string, bool) { return "", false },
		LoginURL:    func(*http.Request, string) string { return "/login" }}
	for name, mutate := range map[string]func(*oauth.Options){
		"http issuer":       func(o *oauth.Options) { o.Issuer = "http://as.example.com" },
		"no resources":      func(o *oauth.Options) { o.Resources = nil },
		"fragment resource": func(o *oauth.Options) { o.Resources = []string{"https://api.example.com/mcp#x"} },
		"no CurrentUser":    func(o *oauth.Options) { o.CurrentUser = nil },
		"bad default scope": func(o *oauth.Options) { o.Scopes = []string{"a"}; o.DefaultScopes = []string{"b"} },
	} {
		o := base
		mutate(&o)
		if _, err := oauth.NewServer(um, tokens, st.OAuth(), o); err == nil {
			t.Errorf("%s: NewServer must fail", name)
		}
	}
	dev := base
	dev.Issuer = "http://localhost:8080"
	if _, err := oauth.NewServer(um, tokens, st.OAuth(), dev); err != nil {
		t.Errorf("http issuer on loopback must be allowed for development: %v", err)
	}
}

func TestResourceMetadataHelpers(t *testing.T) {
	u, err := oauth.ResourceMetadataURL("https://api.example.com/v1/mcp")
	if err != nil || u != "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp" {
		t.Fatalf("metadata URL: %q %v", u, err)
	}
	h := oauth.ProtectedResourceHandler(oauth.ProtectedResourceMetadata{Resource: "https://api.example.com/v1/mcp",
		AuthorizationServers: []string{"https://api.example.com"}, ScopesSupported: []string{"read"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/v1/mcp", nil))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 || m["resource"] != "https://api.example.com/v1/mcp" || fmt.Sprint(m["bearer_methods_supported"]) != "[header]" {
		t.Fatalf("protected resource metadata: %d %v", rec.Code, m)
	}
}

func TestChallengeKeepsAppExposeHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
	oauth.Challenge(rec, "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp", "mcp:read")
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "Mcp-Session-Id, WWW-Authenticate" {
		t.Fatalf("expose headers = %q", got)
	}
	rec = httptest.NewRecorder()
	oauth.InsufficientScope(rec, "https://x/.well-known/oauth-protected-resource", "a", "")
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "WWW-Authenticate" || rec.Code != http.StatusForbidden {
		t.Fatalf("expose headers = %q code %d", got, rec.Code)
	}
}

func TestDCRGrantTypesDefault(t *testing.T) {
	srv, _, _, _ := newServer(t, nil)
	ctx := context.Background()
	reg, err := srv.RegisterClient(ctx, oauth.ClientMetadata{RedirectURIs: []string{"https://c.example/cb"}, TokenEndpointAuthMethod: oauth.AuthMethodNone})
	if err != nil || fmt.Sprint(reg.GrantTypes) != "[authorization_code refresh_token]" {
		t.Fatalf("omitted grant_types must register code+refresh, got %v %v", reg, err)
	}
	reg, err = srv.RegisterClient(ctx, oauth.ClientMetadata{RedirectURIs: []string{"https://c.example/cb"},
		TokenEndpointAuthMethod: oauth.AuthMethodNone, GrantTypes: []string{oauth.GrantTypeAuthorizationCode}})
	if err != nil || fmt.Sprint(reg.GrantTypes) != "[authorization_code]" {
		t.Fatalf("explicit grant_types must be kept, got %v %v", reg, err)
	}
}
