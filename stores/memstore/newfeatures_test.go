package memstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func TestES256TokenServiceRotation(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())

	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring := identity.NewECDSAKeyring("ec1", k1)
	ts := identity.NewTokenService(um, identity.TokenOptions{
		Signer: ring, Issuer: "go-idento", Audience: "api",
		AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: time.Hour,
	})

	u := &identity.User{UserName: "es", SecurityStamp: "s"}
	if err := um.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	pair, err := ts.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("ES256 token should validate: %v", err)
	}

	// Rotate to a new active key; the old token still verifies.
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ring.Add("ec2", k2, true)
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("retired-key token should still validate: %v", err)
	}
	ring.Remove("ec1")
	if _, _, err := ts.ValidateAccessToken(ctx, pair.AccessToken); err == nil {
		t.Fatal("removed-key token must fail")
	}
}

func TestPhoneTwoFactor(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()

	var sent struct {
		phone, msg string
		count      int
	}
	sender := identity.SMSSenderFunc(func(_ context.Context, phone, msg string) error {
		sent.phone, sent.msg, sent.count = phone, msg, sent.count+1
		return nil
	})

	um := identity.NewUserManager(st.Users(), identity.DefaultOptions()).WithSMSSender(sender)
	sm := identity.NewSignInManager(um)

	u := &identity.User{UserName: "phil", PhoneNumber: "+15551234567"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = um.SetTwoFactorEnabled(ctx, u, true)

	// Password sign-in requires the second factor.
	res, signed := sm.PasswordSignIn(ctx, "phil", "Abcdef1!", true)
	if !res.RequiresTwoFactor {
		t.Fatalf("expected RequiresTwoFactor, got %+v", res)
	}

	// Deliver an SMS code.
	if err := um.SendPhoneToken(ctx, signed); err != nil {
		t.Fatalf("send: %v", err)
	}
	if sent.count != 1 || sent.phone != "+15551234567" {
		t.Fatalf("SMS not sent correctly: %+v", sent)
	}
	// Extract the 6-digit code from the message ("...code is 123456").
	code := sent.msg[len(sent.msg)-6:]

	// Wrong code fails; correct code completes the sign-in.
	if r := sm.TwoFactorPhoneSignIn(ctx, signed, "000000"); r.Succeeded {
		t.Fatal("wrong SMS code must not succeed")
	}
	// Re-issue (the failed attempt consumed nothing since codes only clear on success).
	code2, err := um.GeneratePhoneToken(ctx, signed)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if r := sm.TwoFactorPhoneSignIn(ctx, signed, code2); !r.Succeeded {
		t.Fatalf("correct SMS code should succeed, got %+v", r)
	}
	// One-time use: the consumed code no longer works.
	if r := sm.TwoFactorPhoneSignIn(ctx, signed, code2); r.Succeeded {
		t.Fatal("SMS code must be single-use")
	}
	_ = code
}

func TestPhoneTokenExpiry(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	u := &identity.User{UserName: "pat", PhoneNumber: "+1999"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}

	code, err := um.GeneratePhoneToken(ctx, u)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	ok, err := um.VerifyPhoneToken(ctx, u, code)
	if err != nil || !ok {
		t.Fatalf("fresh code should verify: ok=%v err=%v", ok, err)
	}
}
