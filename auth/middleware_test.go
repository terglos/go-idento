package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func setup(t *testing.T) (*identity.UserManager, *identity.TokenService, *auth.CookieAuth) {
	t.Helper()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	rm := identity.NewRoleManager(st.Roles())
	if err := rm.Create(context.Background(), &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("role: %v", err)
	}
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("middleware-signing-key-0000000000"), "go-idento", "api"))
	cookies := auth.DefaultCookieAuth()
	cookies.Secure = false
	return um, ts, cookies
}

func tokenFor(t *testing.T, um *identity.UserManager, ts *identity.TokenService, roles ...string) string {
	t.Helper()
	ctx := context.Background()
	u := &identity.User{UserName: "user-" + time.Now().Format("150405.000000")}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, r := range roles {
		if err := um.AddToRole(ctx, u, r); err != nil {
			t.Fatalf("role: %v", err)
		}
	}
	pair, err := ts.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return pair.AccessToken
}

// serve runs a request through the auth middleware wrapping handler.
func serve(ts *identity.TokenService, cookies *auth.CookieAuth, handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	auth.Middleware(ts, cookies)(handler).ServeHTTP(rr, req)
	return rr
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestRequireAuthBearer(t *testing.T) {
	um, ts, cookies := setup(t)
	h := auth.RequireAuth(okHandler())

	// No token -> 401.
	if rr := serve(ts, cookies, h, httptest.NewRequest("GET", "/", nil)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon expected 401, got %d", rr.Code)
	}
	// Valid bearer -> 200.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts))
	if rr := serve(ts, cookies, h, req); rr.Code != http.StatusOK {
		t.Fatalf("valid bearer expected 200, got %d", rr.Code)
	}
	// Garbage token -> 401.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer not.a.jwt")
	if rr := serve(ts, cookies, h, req2); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token expected 401, got %d", rr.Code)
	}
}

func TestCookieAuthentication(t *testing.T) {
	um, ts, cookies := setup(t)
	h := auth.RequireAuth(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: cookies.Name, Value: tokenFor(t, um, ts)})
	if rr := serve(ts, cookies, h, req); rr.Code != http.StatusOK {
		t.Fatalf("cookie auth expected 200, got %d", rr.Code)
	}
}

func TestRequireRole(t *testing.T) {
	um, ts, cookies := setup(t)
	h := auth.RequireRole("Admin")(okHandler())

	// Has role -> 200.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts, "Admin"))
	if rr := serve(ts, cookies, h, req); rr.Code != http.StatusOK {
		t.Fatalf("admin expected 200, got %d", rr.Code)
	}
	// Lacks role -> 403.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts))
	if rr := serve(ts, cookies, h, req2); rr.Code != http.StatusForbidden {
		t.Fatalf("non-admin expected 403, got %d", rr.Code)
	}
	// Anonymous -> 401.
	if rr := serve(ts, cookies, h, httptest.NewRequest("GET", "/", nil)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon expected 401, got %d", rr.Code)
	}
}

func TestRequirePolicy(t *testing.T) {
	um, ts, cookies := setup(t)
	policy := auth.NewPolicy("AdminOnly").RequireRole("Admin")
	h := auth.RequirePolicy(policy)(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts, "Admin"))
	if rr := serve(ts, cookies, h, req); rr.Code != http.StatusOK {
		t.Fatalf("policy pass expected 200, got %d", rr.Code)
	}
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts))
	if rr := serve(ts, cookies, h, req2); rr.Code != http.StatusForbidden {
		t.Fatalf("policy fail expected 403, got %d", rr.Code)
	}
}

func TestPrincipalExposedToHandler(t *testing.T) {
	um, ts, cookies := setup(t)
	var sawUser string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := auth.PrincipalFrom(r.Context()); ok {
			sawUser = p.User.UserName
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, um, ts))
	serve(ts, cookies, auth.RequireAuth(handler), req)
	if sawUser == "" {
		t.Fatal("handler should see the authenticated principal in context")
	}
}
