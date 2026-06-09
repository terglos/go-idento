// Package genericuser demonstrates Option D from the design doc: a custom user
// type with first-class custom columns, managed by the generic UserManagerOf[T].
package genericuser_test

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

// AppUser extends the built-in user with domain columns. Embedding identity.User
// promotes Base() (satisfying identity.UserModel) AND TableName(), so AppUser
// maps to the same identity_users table with TenantID/FullName as extra columns.
type AppUser struct {
	identity.User
	TenantID string `gorm:"index"`
	FullName string
}

func newManagers(t *testing.T) (*identity.UserManagerOf[AppUser, *AppUser], *identity.SignInManagerOf[AppUser, *AppUser], *identity.TokenServiceOf[AppUser, *AppUser]) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := gormstore.MigrateOf[AppUser](db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := gormstore.NewUserStoreOf[AppUser](db)
	um := identity.NewUserManagerOf[AppUser](store, identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte("generic-secret"), time.Hour))
	sm := identity.NewSignInManagerOf[AppUser](um)
	ts := identity.NewTokenServiceOf[AppUser](um, identity.DefaultTokenOptions([]byte("generic-signing-key-0000000000000"), "go-idento", "api"))
	return um, sm, ts
}

func TestGenericCustomColumns(t *testing.T) {
	ctx := context.Background()
	um, sm, ts := newManagers(t)

	// Create an extended user — custom fields are set on the same struct.
	u := &AppUser{
		User:     identity.User{UserName: "jane", Email: "jane@x.com"},
		TenantID: "acme",
		FullName: "Jane D.",
	}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Custom columns persist on the user row and round-trip through the manager.
	got, err := um.FindByName(ctx, "jane")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.TenantID != "acme" || got.FullName != "Jane D." {
		t.Fatalf("custom columns lost: %+v", got)
	}
	// The base identity fields are intact too.
	if got.Base().NormalizedUserName != "JANE" {
		t.Fatalf("base fields broken: %q", got.Base().NormalizedUserName)
	}

	// All the core flows work on the extended type.
	res, signed := sm.PasswordSignIn(ctx, "jane", "Abcdef1!", true)
	if !res.Succeeded || signed.TenantID != "acme" {
		t.Fatalf("sign-in failed or lost custom data: %+v / %v", res, signed)
	}
	pair, err := ts.IssuePair(ctx, signed)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	back, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil || back.TenantID != "acme" {
		t.Fatalf("token validation lost the custom type: %v / %+v", err, back)
	}

	// Update a custom column.
	signed.FullName = "Jane Doe"
	if err := um.Store.Update(ctx, signed); err != nil {
		t.Fatalf("update: %v", err)
	}
	reloaded, _ := um.FindByID(ctx, signed.Base().ID)
	if reloaded.FullName != "Jane Doe" {
		t.Fatalf("custom column update lost: %q", reloaded.FullName)
	}
}

func TestGenericTwoFactorAndReset(t *testing.T) {
	ctx := context.Background()
	um, sm, _ := newManagers(t)
	u := &AppUser{User: identity.User{UserName: "nina", Email: "nina@x.com"}, TenantID: "acme"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// 2FA works on the custom type.
	_ = um.SetTwoFactorEnabled(ctx, u, true)
	res, signed := sm.PasswordSignIn(ctx, "nina", "Abcdef1!", true)
	if !res.RequiresTwoFactor {
		t.Fatalf("expected 2FA required, got %+v", res)
	}
	key, _ := um.GetAuthenticatorKey(ctx, signed)
	code, _ := identity.DefaultTOTP().Code(key, time.Now())
	if r := sm.TwoFactorAuthenticatorSignIn(ctx, signed, code); !r.Succeeded {
		t.Fatalf("2FA sign-in failed: %+v", r)
	}

	// Password reset token provider works on the custom type.
	tok := um.GeneratePasswordResetToken(signed)
	if err := um.ResetPassword(ctx, signed, tok, "Newpass1!"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !um.CheckPassword(ctx, signed, "Newpass1!") {
		t.Fatal("password reset did not apply")
	}
}
