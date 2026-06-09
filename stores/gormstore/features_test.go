package gormstore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
)

func TestTwoFactorAndRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)
	sm := identity.NewSignInManager(um)

	u := &identity.User{UserName: "tina"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := um.SetTwoFactorEnabled(ctx, u, true); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}

	// Password sign-in now requires a second factor.
	res, signed := sm.PasswordSignIn(ctx, "tina", "Abcdef1!", true)
	if !res.RequiresTwoFactor {
		t.Fatalf("expected RequiresTwoFactor, got %+v", res)
	}

	// Authenticator code completes sign-in.
	key, err := um.GetAuthenticatorKey(ctx, signed)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	code, _ := identity.DefaultTOTP().Code(key, time.Now())
	if r := sm.TwoFactorAuthenticatorSignIn(ctx, signed, code); !r.Succeeded {
		t.Fatalf("expected 2fa sign-in to succeed, got %+v", r)
	}

	// Recovery codes: one-time use.
	codes, err := um.GenerateRecoveryCodes(ctx, signed, 3)
	if err != nil {
		t.Fatalf("gen recovery: %v", err)
	}
	if r := sm.TwoFactorRecoveryCodeSignIn(ctx, signed, codes[0]); !r.Succeeded {
		t.Fatal("expected recovery code to succeed")
	}
	if r := sm.TwoFactorRecoveryCodeSignIn(ctx, signed, codes[0]); r.Succeeded {
		t.Fatal("recovery code must not be reusable")
	}
	if n, _ := um.CountRecoveryCodes(ctx, signed); n != 2 {
		t.Fatalf("expected 2 remaining recovery codes, got %d", n)
	}
}

func TestEmailConfirmationAndPasswordReset(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)
	um.WithTokenProvider(identity.NewDataTokenProvider([]byte("token-secret"), time.Hour))

	u := &identity.User{UserName: "emo", Email: "emo@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Email confirmation.
	tok := um.GenerateEmailConfirmationToken(u)
	if err := um.ConfirmEmail(ctx, u, tok); err != nil {
		t.Fatalf("confirm email: %v", err)
	}
	if !u.EmailConfirmed {
		t.Fatal("email should be confirmed")
	}
	// Tampered token rejected.
	if err := um.ConfirmEmail(ctx, u, tok+"x"); err == nil {
		t.Fatal("tampered token should fail")
	}

	// Password reset.
	reset := um.GeneratePasswordResetToken(u)
	if err := um.ResetPassword(ctx, u, reset, "Newpass1!"); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if !um.CheckPassword(ctx, u, "Newpass1!") {
		t.Fatal("new password should work after reset")
	}
	// Reset token is single-use: stamp changed, so reusing it fails.
	if err := um.ResetPassword(ctx, u, reset, "Another1!"); err == nil {
		t.Fatal("reset token should be invalid after use")
	}
}

func TestExternalLogin(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)
	sm := identity.NewSignInManager(um)

	u := &identity.User{UserName: "oauthy", Email: "o@x.com"}
	if err := um.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	login := identity.UserLoginInfo{LoginProvider: "Google", ProviderKey: "google-123", ProviderDisplayName: "Google"}
	if err := um.AddLogin(ctx, u, login); err != nil {
		t.Fatalf("add login: %v", err)
	}

	res, found := sm.ExternalLoginSignIn(ctx, "Google", "google-123")
	if !res.Succeeded || found == nil || found.ID != u.ID {
		t.Fatalf("expected external sign-in to succeed, got %+v", res)
	}
	// Unknown login -> no user, generic failure.
	if r, f := sm.ExternalLoginSignIn(ctx, "Google", "nope"); r.Succeeded || f != nil {
		t.Fatal("unknown external login should not sign in")
	}
}

func TestRSAKeyRotation(t *testing.T) {
	ctx := context.Background()
	um, _, _ := setup(t)

	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	ring := identity.NewRSAKeyring("key-1", k1)
	ts := identity.NewTokenService(um, identity.TokenOptions{
		Signer: ring, Issuer: "go-identity", Audience: "api",
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: time.Hour,
	})

	u := &identity.User{UserName: "rs"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	pair, err := ts.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Rotate in a new active key; the old token must still verify.
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	ring.Add("key-2", k2, true)
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("token signed with retired key should still validate: %v", err)
	}
	// New tokens use key-2 and validate too.
	pair2, _ := ts.IssuePair(ctx, u)
	if _, _, err := ts.ValidateAccessToken(ctx, pair2.AccessToken); err != nil {
		t.Fatalf("token with new active key should validate: %v", err)
	}
	// Removing key-1 invalidates the first token only.
	ring.Remove("key-1")
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("token signed with removed key must fail")
	}
	if _, _, err := ts.ValidateAccessToken(ctx, pair2.AccessToken); err != nil {
		t.Fatalf("key-2 token should still validate: %v", err)
	}
}
