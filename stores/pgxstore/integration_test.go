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
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("pg-int-signing-key-00000000000000"), "go-idento", "api"))

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

	// Optimistic concurrency against real Postgres: stale write loses.
	a, _ := um.FindByID(ctx, signed.ID)
	b, _ := um.FindByID(ctx, signed.ID)
	a.SetAttribute("k", "1")
	if err := um.Store.Update(ctx, a); err != nil {
		t.Fatalf("first update should win: %v", err)
	}
	b.SetAttribute("k", "2")
	if err := um.Store.Update(ctx, b); err != identity.ErrConcurrencyFailure {
		t.Fatalf("stale update must fail with ErrConcurrencyFailure, got %v", err)
	}

	// Paged listing against real Postgres.
	page, total, err := um.ListUsers(ctx, identity.ListFilter{Limit: 10})
	if err != nil || total < 1 || len(page) < 1 {
		t.Fatalf("list users: err=%v total=%d page=%d", err, total, len(page))
	}

	// Store behavioral contract against real Postgres.
	if err := um.AddToRole(ctx, signed, "ghost"); err != identity.ErrRoleNotFound {
		t.Fatalf("AddToRole(missing role) must be ErrRoleNotFound, got %v", err)
	}
	if err := um.RemoveFromRole(ctx, signed, "ghost"); err != nil {
		t.Fatalf("RemoveFromRole(missing role) must be a no-op, got %v", err)
	}
	if got, err := um.FindByEmail(ctx, ""); got != nil || err != identity.ErrNotFound {
		t.Fatalf("FindByEmail(\"\") must be ErrNotFound, got user=%v err=%v", got, err)
	}

	// Reverse queries against real Postgres: users by role and by claim.
	if err := um.AddClaims(ctx, signed, identity.Claim{Type: "tenant", Value: "acme"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if us, err := um.GetUsersInRole(ctx, "Admin"); err != nil || len(us) != 1 || us[0].ID != signed.ID {
		t.Fatalf("GetUsersInRole: err=%v n=%d", err, len(us))
	}
	if us, err := um.GetUsersForClaim(ctx, "tenant", "acme"); err != nil || len(us) != 1 || us[0].ID != signed.ID {
		t.Fatalf("GetUsersForClaim: err=%v n=%d", err, len(us))
	}
	if us, _ := um.GetUsersForClaim(ctx, "tenant", "nope"); len(us) != 0 {
		t.Fatalf("non-matching claim should be empty, got %d", len(us))
	}

	// Role optimistic concurrency against real Postgres.
	r1, _ := rm.FindByName(ctx, "Admin")
	r2, _ := rm.FindByName(ctx, "Admin")
	r1.Name = "Administrators"
	if err := rm.Update(ctx, r1); err != nil {
		t.Fatalf("first role update should win: %v", err)
	}
	r2.Name = "Superusers"
	if err := rm.Update(ctx, r2); err != identity.ErrConcurrencyFailure {
		t.Fatalf("stale role update must fail with ErrConcurrencyFailure, got %v", err)
	}
}

// TestPgxCustomSchemaAndPrefix verifies a fully custom physical layout (custom
// schema + table prefix) works end to end, and that ON DELETE CASCADE keeps
// referential integrity. Runs only when GOIDENTITY_PG_DSN is set.
func TestPgxCustomSchemaAndPrefix(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_DSN to run the pgx custom-schema test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	opts := []pgxstore.Option{pgxstore.WithSchema("idflex"), pgxstore.WithTablePrefix("app_")}
	_, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS idflex CASCADE")
	if err := pgxstore.Migrate(ctx, pool, opts...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS idflex CASCADE") })

	// Tables must exist under idflex with the app_ prefix.
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables
		WHERE table_schema='idflex' AND table_name='app_identity_users')`).Scan(&exists); err != nil || !exists {
		t.Fatalf("expected table idflex.app_identity_users to exist (err=%v exists=%v)", err, exists)
	}

	um := identity.NewUserManager(pgxstore.NewUserStore(pool, opts...), identity.DefaultOptions())
	rm := identity.NewRoleManager(pgxstore.NewRoleStore(pool, opts...))

	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := &identity.User{UserName: "flex"}
	u.SetAttribute("tenant", "acme")
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if in, _ := um.IsInRole(ctx, u, "Admin"); !in {
		t.Fatal("expected user in Admin role (join across renamed tables)")
	}

	// Referential integrity: deleting the user cascades to the membership row.
	if err := um.Store.Delete(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var memberships int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM idflex.app_identity_user_roles WHERE user_id=$1`, u.ID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberships != 0 {
		t.Fatalf("ON DELETE CASCADE failed: %d orphan membership rows", memberships)
	}
}
