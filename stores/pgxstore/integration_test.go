package pgxstore_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/pgxstore"
)

// TestPgxIntegration runs the full flow against a real PostgreSQL when
// GOIDENTITY_PG_DSN is set, e.g.:
//
//	GOIDENTITY_PG_DSN="postgres://postgres:123@localhost:5432/identity_test?sslmode=disable" go test ./stores/pgxstore/
//
// It is skipped otherwise so the default `go test ./...` needs no database.
func TestPgxIntegration(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_DSN to run the pgx integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pgxstore.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	truncate := func() {
		_, _ = pool.Exec(ctx, `TRUNCATE identity_users, identity_roles, identity_user_roles,
			identity_user_claims, identity_role_claims, identity_user_logins, identity_user_tokens`)
	}
	truncate() // start clean even if a previous run left data behind
	t.Cleanup(truncate)

	um := identity.NewUserManager(pgxstore.NewUserStore(pool), identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte("pg-int-secret"), time.Hour))
	rm := identity.NewRoleManager(pgxstore.NewRoleStore(pool))
	sm := identity.NewSignInManager(um)
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("pg-int-signing-key-00000000000000"), "go-identity", "api"))

	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Create with custom attributes (Option C / jsonb).
	u := &identity.User{UserName: "pg_jane", Email: "pg@example.com"}
	u.SetAttribute("tenant", "acme")
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}

	// Attributes round-trip through jsonb.
	got, err := um.FindByName(ctx, "pg_jane")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if v, ok := got.GetAttribute("tenant"); !ok || v != "acme" {
		t.Fatalf("jsonb attribute lost: %q (%v)", v, ok)
	}

	// Sign-in + JWT with role claim.
	res, signed := sm.PasswordSignIn(ctx, "pg_jane", "Abcdef1!", true)
	if !res.Succeeded {
		t.Fatalf("sign-in failed: %+v", res)
	}
	pair, err := ts.IssuePair(ctx, signed)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, claims, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("validate: %v", err)
	} else if _, ok := claims[identity.ClaimRole]; !ok {
		t.Fatal("role claim missing from token")
	}

	// Refresh rotation.
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err == nil {
		t.Fatal("old refresh token must be rejected after rotation")
	}

	// External login.
	if err := um.AddLogin(ctx, signed, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-9", ProviderDisplayName: "GitHub"}); err != nil {
		t.Fatalf("add login: %v", err)
	}
	if r, f := sm.ExternalLoginSignIn(ctx, "GitHub", "gh-9"); !r.Succeeded || f == nil || f.ID != signed.ID {
		t.Fatalf("external login failed: %+v", r)
	}
}
