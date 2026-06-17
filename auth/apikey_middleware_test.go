package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

// TestMiddlewareAPIKey verifies an API key on the Bearer header authenticates
// through the middleware and resolves the owner's roles, so RequireRole works
// identically to a JWT — the client's core acceptance criterion.
func TestMiddlewareAPIKey(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	rm := identity.NewRoleManager(st.Roles())
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("apikey-mw-signing-key-00000000000"), "go-idento", "api"))
	km := identity.NewAPIKeyManager(st.APIKeys(), um)

	_ = rm.Create(ctx, &identity.Role{Name: "Admin"})
	u := &identity.User{UserName: "gateway"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = um.AddToRole(ctx, u, "Admin")

	secret, key, err := km.CreateAPIKey(ctx, u, identity.APIKeyOptions{Name: "partner", Scopes: []string{"payments:write"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	// A handler that requires the Admin role and asserts the principal carries
	// the API-key scope.
	var sawScope bool
	h := auth.Middleware(ts, nil, auth.WithAPIKeys(km))(
		auth.RequireRole("Admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p, ok := auth.PrincipalFrom(r.Context()); ok {
				sawScope = p.ViaAPIKey && p.HasScope("payments:write")
			}
			w.WriteHeader(http.StatusOK)
		})),
	)

	// Valid API key → 200 and scope visible.
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid API key should pass RequireRole(Admin), got %d", rec.Code)
	}
	if !sawScope {
		t.Fatal("principal should be flagged ViaAPIKey and carry the key's scope")
	}

	// No credential → 401.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous should be 401, got %d", rec.Code)
	}

	// Revoked key → 401.
	_ = km.RevokeAPIKey(ctx, key.ID)
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked API key should be 401, got %d", rec.Code)
	}
}
