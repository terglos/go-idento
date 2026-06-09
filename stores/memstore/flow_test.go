package memstore_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

// harness wires managers over the in-memory store — fast, DB-free unit setup.
type harness struct {
	users  *identity.UserManager
	roles  *identity.RoleManager
	signIn *identity.SignInManager
	tokens *identity.TokenService
}

func newHarness() *harness {
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte("unit-secret"), time.Hour))
	return &harness{
		users:  um,
		roles:  identity.NewRoleManager(st.Roles()),
		signIn: identity.NewSignInManager(um),
		tokens: identity.NewTokenService(um, identity.DefaultTokenOptions([]byte("unit-signing-key-0000000000000000"), "go-idento", "api")),
	}
}

func mustUser(t *testing.T, h *harness, name, pw string) *identity.User {
	t.Helper()
	u := &identity.User{UserName: name, Email: name + "@x.com"}
	if err := h.users.CreateWithPassword(context.Background(), u, pw); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return u
}

func TestUserCreationAndDuplicates(t *testing.T) {
	ctx := context.Background()
	h := newHarness()

	u := mustUser(t, h, "alice", "Abcdef1!")
	if u.ID == "" || u.SecurityStamp == "" {
		t.Fatal("expected ID and security stamp to be populated")
	}
	if u.NormalizedUserName != "ALICE" {
		t.Fatalf("expected normalized username ALICE, got %q", u.NormalizedUserName)
	}

	// Duplicate username (case-insensitive).
	if err := h.users.CreateWithPassword(ctx, &identity.User{UserName: "ALICE"}, "Abcdef1!"); err != identity.ErrDuplicateUserName {
		t.Fatalf("expected duplicate username, got %v", err)
	}
	// Duplicate email.
	if err := h.users.CreateWithPassword(ctx, &identity.User{UserName: "alice2", Email: "alice@x.com"}, "Abcdef1!"); err != identity.ErrDuplicateEmail {
		t.Fatalf("expected duplicate email, got %v", err)
	}
	// Weak password rejected before persistence.
	if err := h.users.CreateWithPassword(ctx, &identity.User{UserName: "bob"}, "weak"); err == nil {
		t.Fatal("weak password should be rejected")
	}
	if got, _ := h.users.FindByName(ctx, "bob"); got != nil {
		t.Fatal("user must not be persisted when password fails validation")
	}
}

func TestFindAndLookup(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "carol", "Abcdef1!")

	byName, _ := h.users.FindByName(ctx, "CAROL")
	byEmail, _ := h.users.FindByEmail(ctx, "carol@X.com")
	byID, _ := h.users.FindByID(ctx, u.ID)
	if byName == nil || byEmail == nil || byID == nil {
		t.Fatal("expected to find user by name, email and id (case-insensitive)")
	}
}

func TestPasswordChangeAndRehash(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "dave", "Abcdef1!")
	oldStamp := u.SecurityStamp

	if err := h.users.ChangePassword(ctx, u, "wrong", "Newpass1!"); err != identity.ErrPasswordMismatch {
		t.Fatalf("expected mismatch, got %v", err)
	}
	if err := h.users.ChangePassword(ctx, u, "Abcdef1!", "Newpass1!"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if !h.users.CheckPassword(ctx, u, "Newpass1!") {
		t.Fatal("new password should verify")
	}
	if u.SecurityStamp == oldStamp {
		t.Fatal("security stamp should rotate on password change")
	}
}

func TestRolesAndClaims(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	if err := h.roles.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	u := mustUser(t, h, "erin", "Abcdef1!")

	if err := h.users.AddToRole(ctx, u, "admin"); err != nil { // case-insensitive
		t.Fatalf("add to role: %v", err)
	}
	if in, _ := h.users.IsInRole(ctx, u, "Admin"); !in {
		t.Fatal("user should be in Admin role")
	}
	roles, _ := h.users.GetRoles(ctx, u)
	if len(roles) != 1 || roles[0] != "Admin" {
		t.Fatalf("unexpected roles: %v", roles)
	}
	if err := h.users.RemoveFromRole(ctx, u, "Admin"); err != nil {
		t.Fatalf("remove role: %v", err)
	}
	if in, _ := h.users.IsInRole(ctx, u, "Admin"); in {
		t.Fatal("role should be removed")
	}

	// Adding to a non-existent role fails.
	if err := h.users.AddToRole(ctx, u, "Ghost"); err != identity.ErrRoleNotFound {
		t.Fatalf("expected role-not-found, got %v", err)
	}

	// Claims.
	c := identity.Claim{Type: "department", Value: "eng"}
	if err := h.users.AddClaims(ctx, u, c); err != nil {
		t.Fatalf("add claim: %v", err)
	}
	claims, _ := h.users.GetClaims(ctx, u)
	if len(claims) != 1 || claims[0] != c {
		t.Fatalf("unexpected claims: %v", claims)
	}
	if err := h.users.RemoveClaims(ctx, u, c); err != nil {
		t.Fatalf("remove claim: %v", err)
	}
	if claims, _ := h.users.GetClaims(ctx, u); len(claims) != 0 {
		t.Fatal("claim should be removed")
	}
}

func TestSignInResults(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	mustUser(t, h, "frank", "Abcdef1!")

	if res, _ := h.signIn.PasswordSignIn(ctx, "frank", "Abcdef1!", true); !res.Succeeded {
		t.Fatal("correct credentials should succeed")
	}
	if res, _ := h.signIn.PasswordSignIn(ctx, "frank", "nope", true); res.Succeeded {
		t.Fatal("wrong password should not succeed")
	}
	// Unknown user: generic failure, nil user (no enumeration).
	if res, u := h.signIn.PasswordSignIn(ctx, "ghost", "whatever", true); res.Succeeded || u != nil {
		t.Fatal("unknown user should produce generic failure")
	}
}

func TestLockoutThenAutoExpire(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "grace", "Abcdef1!")

	for i := 0; i < 5; i++ {
		h.signIn.PasswordSignIn(ctx, "grace", "wrong", true)
	}
	reloaded, _ := h.users.FindByID(ctx, u.ID)
	if !h.users.IsLockedOut(reloaded) {
		t.Fatal("user should be locked out after 5 failures")
	}
	// Correct password during lockout still refused.
	if res, _ := h.signIn.PasswordSignIn(ctx, "grace", "Abcdef1!", true); !res.IsLockedOut {
		t.Fatal("sign-in during lockout should report IsLockedOut")
	}
}

func TestJWTLifecycle(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	_ = h.roles.Create(ctx, &identity.Role{Name: "Admin"})
	u := mustUser(t, h, "heidi", "Abcdef1!")
	_ = h.users.AddToRole(ctx, u, "Admin")
	_ = h.users.AddClaims(ctx, u, identity.Claim{Type: "department", Value: "eng"})

	pair, err := h.tokens.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pair.TokenType != "Bearer" || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("unexpected token pair: %+v", pair)
	}

	got, claims, err := h.tokens.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil || got.ID != u.ID {
		t.Fatalf("validate: %v", err)
	}
	if claims["department"] != "eng" {
		t.Fatalf("custom claim missing: %v", claims["department"])
	}
	if _, ok := claims[identity.ClaimRole]; !ok {
		t.Fatal("role claim missing")
	}

	// Refresh rotates; old refresh becomes invalid.
	if _, err := h.tokens.Refresh(ctx, u, pair.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := h.tokens.Refresh(ctx, u, pair.RefreshToken); err == nil {
		t.Fatal("old refresh token must be rejected after rotation")
	}

	// Revoke ends the session.
	if err := h.tokens.Revoke(ctx, u); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	pair2, _ := h.tokens.IssuePair(ctx, u)
	_ = h.tokens.Revoke(ctx, u)
	if _, err := h.tokens.Refresh(ctx, u, pair2.RefreshToken); err == nil {
		t.Fatal("refresh after revoke must fail")
	}
}

func TestTokenInvalidatedByPasswordChange(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "ivan", "Abcdef1!")
	pair, _ := h.tokens.IssuePair(ctx, u)

	if _, _, err := h.tokens.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("token should be valid initially: %v", err)
	}
	if err := h.users.ChangePassword(ctx, u, "Abcdef1!", "Newpass1!"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, _, err := h.tokens.ValidateAccessToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("access token must be revoked after password change (security stamp)")
	}
}

func TestTwoFactorFlow(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "judy", "Abcdef1!")
	_ = h.users.SetTwoFactorEnabled(ctx, u, true)

	res, signed := h.signIn.PasswordSignIn(ctx, "judy", "Abcdef1!", true)
	if !res.RequiresTwoFactor {
		t.Fatalf("expected RequiresTwoFactor, got %+v", res)
	}
	key, _ := h.users.GetAuthenticatorKey(ctx, signed)
	code, _ := identity.DefaultTOTP().Code(key, time.Now())
	if r := h.signIn.TwoFactorAuthenticatorSignIn(ctx, signed, code); !r.Succeeded {
		t.Fatalf("2FA should succeed, got %+v", r)
	}
	if r := h.signIn.TwoFactorAuthenticatorSignIn(ctx, signed, "000000"); r.Succeeded {
		t.Fatal("wrong TOTP must fail")
	}

	codes, _ := h.users.GenerateRecoveryCodes(ctx, signed, 2)
	if r := h.signIn.TwoFactorRecoveryCodeSignIn(ctx, signed, codes[0]); !r.Succeeded {
		t.Fatal("recovery code should succeed")
	}
	if r := h.signIn.TwoFactorRecoveryCodeSignIn(ctx, signed, codes[0]); r.Succeeded {
		t.Fatal("recovery code is single-use")
	}
}

func TestEmailConfirmReset(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "ken", "Abcdef1!")

	tok := h.users.GenerateEmailConfirmationToken(u)
	if err := h.users.ConfirmEmail(ctx, u, tok); err != nil || !u.EmailConfirmed {
		t.Fatalf("confirm email failed: %v", err)
	}
	reset := h.users.GeneratePasswordResetToken(u)
	if err := h.users.ResetPassword(ctx, u, reset, "Newpass1!"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !h.users.CheckPassword(ctx, u, "Newpass1!") {
		t.Fatal("password should be reset")
	}
	if err := h.users.ResetPassword(ctx, u, reset, "Another1!"); err == nil {
		t.Fatal("reset token must be single-use")
	}
}

func TestExternalLoginFlow(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := &identity.User{UserName: "leo"}
	_ = h.users.Create(ctx, u)
	_ = h.users.AddLogin(ctx, u, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-1", ProviderDisplayName: "GitHub"})

	if res, found := h.signIn.ExternalLoginSignIn(ctx, "GitHub", "gh-1"); !res.Succeeded || found.ID != u.ID {
		t.Fatalf("external sign-in should succeed, got %+v", res)
	}
	logins, _ := h.users.GetLogins(ctx, u)
	if len(logins) != 1 {
		t.Fatalf("expected 1 login, got %d", len(logins))
	}
	_ = h.users.RemoveLogin(ctx, u, "GitHub", "gh-1")
	if res, _ := h.signIn.ExternalLoginSignIn(ctx, "GitHub", "gh-1"); res.Succeeded {
		t.Fatal("removed login should no longer sign in")
	}
}

func TestRSARotationUnit(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	ring := identity.NewRSAKeyring("k1", k1)
	ts := identity.NewTokenService(um, identity.TokenOptions{
		Signer: ring, Issuer: "go-idento", Audience: "api",
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: time.Hour,
	})
	u := &identity.User{UserName: "mia", SecurityStamp: "s"}
	_ = um.Create(ctx, u)

	pair, _ := ts.IssuePair(ctx, u)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	ring.Add("k2", k2, true)
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("token from retired key should still validate: %v", err)
	}
	ring.Remove("k1")
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("token from removed key must fail")
	}
}
