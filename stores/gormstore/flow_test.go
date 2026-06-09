package gormstore_test

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite" // pure-Go SQLite driver (no CGO)
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

func setup(t *testing.T) (*identity.UserManager, *identity.RoleManager, *identity.TokenService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	um := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
	rm := identity.NewRoleManager(gormstore.NewRoleStore(db))
	ts := identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("test-signing-key-32-bytes-long!!"), "go-identity", "api"))
	return um, rm, ts
}

func TestFullFlow(t *testing.T) {
	ctx := context.Background()
	um, rm, ts := setup(t)

	// Create role + user with password.
	if err := rm.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := &identity.User{UserName: "jane", Email: "jane@example.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := um.AddToRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("add to role: %v", err)
	}

	// Duplicate username is rejected.
	if err := um.CreateWithPassword(ctx, &identity.User{UserName: "JANE"}, "Abcdef1!"); err != identity.ErrDuplicateUserName {
		t.Fatalf("expected duplicate username error, got %v", err)
	}

	// Sign in.
	sm := identity.NewSignInManager(um)
	res, signed := sm.PasswordSignIn(ctx, "jane", "Abcdef1!", true)
	if !res.Succeeded {
		t.Fatalf("expected sign-in to succeed, got %+v", res)
	}

	// Issue + validate JWT, roles must round-trip.
	pair, err := ts.IssuePair(ctx, signed)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	validated, claims, err := ts.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if validated.ID != u.ID {
		t.Fatal("validated user mismatch")
	}
	if _, ok := claims[identity.ClaimRole]; !ok {
		t.Fatal("expected role claim in token")
	}

	// Refresh rotates the token.
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Old refresh token is now invalid.
	if _, err := ts.Refresh(ctx, signed, pair.RefreshToken); err == nil {
		t.Fatal("expected old refresh token to be rejected after rotation")
	}

	// Changing password bumps the security stamp -> old access token revoked.
	if err := um.ChangePassword(ctx, signed, "Abcdef1!", "Zxcvbn2@"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("expected access token to be revoked after password change")
	}
}

func TestLockout(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)
	sm := identity.NewSignInManager(um)

	u := &identity.User{UserName: "bob"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// 5 failed attempts (default MaxFailedAccessAttempts) -> locked out.
	var res identity.SignInResult
	for i := 0; i < 5; i++ {
		res, _ = sm.PasswordSignIn(ctx, "bob", "wrong", true)
	}
	if !res.IsLockedOut {
		t.Fatalf("expected lockout after 5 failures, got %+v", res)
	}
}
