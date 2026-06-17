package pgxsqlc_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/pgxsqlc"
)

// TestSqlcIntegration runs the full flow against a real PostgreSQL when
// GOIDENTITY_PG_SQLC_DSN is set, e.g.:
//
//	GOIDENTITY_PG_SQLC_DSN="postgres://postgres:123@localhost:5432/idento_sqlc_test?sslmode=disable" \
//	  go test ./stores/pgxsqlc/
//
// Use a dedicated database: this store's schema declares the string columns
// NOT NULL, which differs from the hand-written pgxstore schema.
func TestSqlcIntegration(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_SQLC_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_SQLC_DSN to run the sqlc integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Start from a clean slate (this store owns its schema variant).
	_, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS identity_users, identity_roles, identity_user_roles,
		identity_user_claims, identity_role_claims, identity_user_logins, identity_user_tokens CASCADE`)
	if err := pgxsqlc.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	um := identity.NewUserManager(pgxsqlc.NewUserStore(pool), identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte("sqlc-secret"), time.Hour))
	rm := identity.NewRoleManager(pgxsqlc.NewRoleStore(pool))
	sm := identity.NewSignInManager(um)
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("sqlc-signing-key-000000000000000!"), "go-idento", "api"))

	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	u := &identity.User{UserName: "sqlc_jane", Email: "sqlc@example.com"}
	u.SetAttribute("tenant", "acme")
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add role: %v", err)
	}

	got, err := um.FindByName(ctx, "sqlc_jane")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if v, ok := got.GetAttribute("tenant"); !ok || v != "acme" {
		t.Fatalf("jsonb attribute lost: %q (%v)", v, ok)
	}

	res, signed := sm.PasswordSignIn(ctx, "sqlc_jane", "Abcdef1!", true)
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
		t.Fatal("role claim missing")
	}
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err == nil {
		t.Fatal("old refresh token must be rejected after rotation")
	}

	// External login through the sqlc store.
	if err := um.AddLogin(ctx, signed, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-1"}); err != nil {
		t.Fatalf("add login: %v", err)
	}
	if r, f := sm.ExternalLoginSignIn(ctx, "GitHub", "gh-1"); !r.Succeeded || f == nil {
		t.Fatalf("external login failed: %+v", r)
	}

	// Optimistic concurrency + paged listing via the sqlc store.
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
	if page, total, err := um.ListUsers(ctx, identity.ListFilter{Search: "sqlc"}); err != nil || total < 1 || len(page) < 1 {
		t.Fatalf("list users: err=%v total=%d page=%d", err, total, len(page))
	}

	// Guest identity through the sqlc store: create, convert, purge (FK cascade).
	guest, err := um.CreateAnonymous(ctx)
	if err != nil {
		t.Fatalf("CreateAnonymous: %v", err)
	}
	if !guest.IsAnonymous {
		t.Fatal("guest should be anonymous")
	}
	gid := guest.ID
	if err := um.ConvertToRegistered(ctx, guest, "sqlc_promoted", "promoted@x.com", "Abcdef1!"); err != nil {
		t.Fatalf("ConvertToRegistered: %v", err)
	}
	if reload, _ := um.FindByID(ctx, gid); reload == nil || reload.IsAnonymous || reload.ID != gid {
		t.Fatalf("conversion must preserve id and clear anonymous: %+v", reload)
	}
	stale, _ := um.CreateAnonymous(ctx)
	if _, err := pool.Exec(ctx, `UPDATE identity_users SET created_at = now() - interval '48 hours' WHERE id=$1`, stale.ID); err != nil {
		t.Fatalf("age the guest: %v", err)
	}
	fresh, _ := um.CreateAnonymous(ctx)
	purged, err := um.PurgeAnonymousUsers(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || purged != 1 {
		t.Fatalf("PurgeAnonymousUsers: purged=%d err=%v", purged, err)
	}
	if got, _ := um.FindByID(ctx, stale.ID); got != nil {
		t.Fatal("stale guest should be purged")
	}
	if got, _ := um.FindByID(ctx, fresh.ID); got == nil {
		t.Fatal("fresh guest should remain")
	}

	// API keys through the sqlc store: create, verify (owner+scopes), revoke.
	keys := identity.NewAPIKeyManager(pgxsqlc.NewAPIKeyStore(pool), um)
	apiSecret, apiKey, err := keys.CreateAPIKey(ctx, signed, identity.APIKeyOptions{Name: "pos", Scopes: []string{"pay:write"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if owner, vk, err := keys.VerifyAPIKey(ctx, apiSecret); err != nil || owner.ID != signed.ID || len(vk.Scopes) != 1 {
		t.Fatalf("VerifyAPIKey: owner=%v err=%v", owner, err)
	}
	if err := keys.RevokeAPIKey(ctx, apiKey.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := keys.VerifyAPIKey(ctx, apiSecret); err != identity.ErrInvalidAPIKey {
		t.Fatalf("revoked key must be ErrInvalidAPIKey, got %v", err)
	}

	// Store behavioral contract through the sqlc store.
	if err := um.AddToRole(ctx, signed, "ghost"); err != identity.ErrRoleNotFound {
		t.Fatalf("AddToRole(missing role) must be ErrRoleNotFound, got %v", err)
	}
	if err := um.RemoveFromRole(ctx, signed, "ghost"); err != nil {
		t.Fatalf("RemoveFromRole(missing role) must be a no-op, got %v", err)
	}
	if got, err := um.FindByEmail(ctx, ""); got != nil || err != identity.ErrNotFound {
		t.Fatalf("FindByEmail(\"\") must be ErrNotFound, got user=%v err=%v", got, err)
	}

	// Reverse queries: users by role and by claim.
	if err := um.AddClaims(ctx, signed, identity.Claim{Type: "tenant", Value: "acme"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if us, err := um.GetUsersInRole(ctx, "Admin"); err != nil || len(us) != 1 || us[0].ID != signed.ID {
		t.Fatalf("GetUsersInRole: err=%v n=%d", err, len(us))
	}
	if us, err := um.GetUsersForClaim(ctx, "tenant", "acme"); err != nil || len(us) != 1 || us[0].ID != signed.ID {
		t.Fatalf("GetUsersForClaim: err=%v n=%d", err, len(us))
	}

	// Role optimistic concurrency through the sqlc store.
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

	// Delete cascades to satellite rows via the ON DELETE CASCADE FKs.
	if err := um.AddClaims(ctx, signed, identity.Claim{Type: "dept", Value: "eng"}); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	if err := um.Delete(ctx, signed); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := um.FindByID(ctx, signed.ID); got != nil {
		t.Fatal("user should be deleted")
	}
	for _, q := range []struct {
		table string
		sql   string
	}{
		{"identity_user_roles", "SELECT count(*) FROM identity_user_roles WHERE user_id = $1"},
		{"identity_user_claims", "SELECT count(*) FROM identity_user_claims WHERE user_id = $1"},
		{"identity_user_logins", "SELECT count(*) FROM identity_user_logins WHERE user_id = $1"},
		{"identity_user_tokens", "SELECT count(*) FROM identity_user_tokens WHERE user_id = $1"},
	} {
		var n int64
		if err := pool.QueryRow(ctx, q.sql, signed.ID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", q.table, err)
		}
		if n != 0 {
			t.Fatalf("%s should cascade-delete, got %d rows", q.table, n)
		}
	}
}
