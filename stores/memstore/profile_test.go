package memstore_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func TestReplaceClaim(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "rita", "Abcdef1!")

	_ = h.users.AddClaims(ctx, u, identity.Claim{Type: "dept", Value: "eng"})
	if err := h.users.ReplaceClaim(ctx, u, identity.Claim{Type: "dept", Value: "eng"}, identity.Claim{Type: "dept", Value: "ops"}); err != nil {
		t.Fatalf("ReplaceClaim: %v", err)
	}
	claims, _ := h.users.GetClaims(ctx, u)
	if len(claims) != 1 || claims[0].Value != "ops" {
		t.Fatalf("expected single dept=ops claim, got %v", claims)
	}

	// Role claim replace.
	r := &identity.Role{Name: "Admin"}
	_ = h.roles.Create(ctx, r)
	_ = h.roles.AddClaim(ctx, r, identity.Claim{Type: "scope", Value: "read"})
	if err := h.roles.ReplaceClaim(ctx, r, identity.Claim{Type: "scope", Value: "read"}, identity.Claim{Type: "scope", Value: "write"}); err != nil {
		t.Fatalf("role ReplaceClaim: %v", err)
	}
	rc, _ := h.roles.GetClaims(ctx, r)
	if len(rc) != 1 || rc[0].Value != "write" {
		t.Fatalf("expected single scope=write role claim, got %v", rc)
	}
}

func TestSetEmailAndUserName(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	a := mustUser(t, h, "amy", "Abcdef1!")
	_ = mustUser(t, h, "ben", "Abcdef1!") // owns ben@x.com / username ben

	// SetEmail rejects a collision and clears confirmation on success.
	a.EmailConfirmed = true
	_ = h.users.Store.Update(ctx, a)
	if err := h.users.SetEmail(ctx, a, "ben@x.com"); !errors.Is(err, identity.ErrDuplicateEmail) {
		t.Fatalf("expected ErrDuplicateEmail, got %v", err)
	}
	if err := h.users.SetEmail(ctx, a, "amy2@x.com"); err != nil {
		t.Fatalf("SetEmail: %v", err)
	}
	if a.Email != "amy2@x.com" || a.EmailConfirmed {
		t.Fatalf("email should change and be unconfirmed, got %q confirmed=%v", a.Email, a.EmailConfirmed)
	}

	// SetUserName validates chars and rejects duplicates.
	if err := h.users.SetUserName(ctx, a, "has space"); !errors.Is(err, identity.ErrInvalidUserName) {
		t.Fatalf("expected ErrInvalidUserName, got %v", err)
	}
	if err := h.users.SetUserName(ctx, a, "ben"); !errors.Is(err, identity.ErrDuplicateUserName) {
		t.Fatalf("expected ErrDuplicateUserName, got %v", err)
	}
	if err := h.users.SetUserName(ctx, a, "amy_renamed"); err != nil {
		t.Fatalf("SetUserName: %v", err)
	}
	if got, _ := h.users.FindByName(ctx, "amy_renamed"); got == nil || got.ID != a.ID {
		t.Fatal("renamed user should be findable by the new name")
	}
}

func TestEmailSender(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	var gotTo, gotSubject, gotBody string
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte("secret"), 0)).
		WithEmailSender(identity.EmailSenderFunc(func(_ context.Context, to, subject, body string) error {
			gotTo, gotSubject, gotBody = to, subject, body
			return nil
		}))
	u := &identity.User{UserName: "evan", Email: "evan@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := um.SendEmailConfirmation(ctx, u, "Confirm", func(tok string) string { return "link?token=" + tok }); err != nil {
		t.Fatalf("SendEmailConfirmation: %v", err)
	}
	if gotTo != "evan@x.com" || gotSubject != "Confirm" || !strings.HasPrefix(gotBody, "link?token=") {
		t.Fatalf("email not delivered as expected: to=%q subj=%q body=%q", gotTo, gotSubject, gotBody)
	}
	// The emitted token actually confirms the email.
	tok := strings.TrimPrefix(gotBody, "link?token=")
	if err := um.ConfirmEmail(ctx, u, tok); err != nil || !u.EmailConfirmed {
		t.Fatalf("token from email should confirm: %v", err)
	}
}

func TestPluggableTwoFactorProviders(t *testing.T) {
	ctx := context.Background()
	h := newHarness()
	u := mustUser(t, h, "vic", "Abcdef1!")

	// No phone, no authenticator key yet -> no valid providers.
	if ps, _ := h.users.GetValidTwoFactorProviders(ctx, u); len(ps) != 0 {
		t.Fatalf("expected no valid providers, got %v", ps)
	}

	// Establish an authenticator key and a phone number.
	if _, err := h.users.GetAuthenticatorKey(ctx, u); err != nil {
		t.Fatalf("authenticator key: %v", err)
	}
	if err := h.users.SetPhoneNumber(ctx, u, "+15550001111"); err != nil {
		t.Fatalf("set phone: %v", err)
	}
	ps, _ := h.users.GetValidTwoFactorProviders(ctx, u)
	sort.Strings(ps)
	if strings.Join(ps, ",") != "Authenticator,Phone" {
		t.Fatalf("expected Authenticator,Phone, got %v", ps)
	}

	// GenerateUserToken/VerifyUserToken via the named Phone provider round-trips.
	code, err := h.users.GenerateUserToken(ctx, u, identity.TwoFactorProviderPhone)
	if err != nil {
		t.Fatalf("GenerateUserToken: %v", err)
	}
	if ok, err := h.users.VerifyUserToken(ctx, u, identity.TwoFactorProviderPhone, code); err != nil || !ok {
		t.Fatalf("VerifyUserToken should accept the issued code: ok=%v err=%v", ok, err)
	}
	// Unknown provider errors.
	if _, err := h.users.GenerateUserToken(ctx, u, "Nope"); err == nil {
		t.Fatal("unknown provider should error")
	}
}
