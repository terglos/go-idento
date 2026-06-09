package identity

import (
	"context"
	"testing"
	"time"
)

// tokenFakeStore implements just the slice of UserStore that the token service
// touches; the embedded interface panics on anything else (so the test fails
// loudly if the service starts calling more).
type tokenFakeStore struct {
	UserStore[User, *User]
	tokens map[string]string
}

func (s *tokenFakeStore) GetRoles(context.Context, *User) ([]string, error) { return nil, nil }
func (s *tokenFakeStore) GetClaims(context.Context, *User) ([]Claim, error) { return nil, nil }
func (s *tokenFakeStore) SetToken(_ context.Context, _ *User, p, n, v string) error {
	s.tokens[p+"|"+n] = v
	return nil
}
func (s *tokenFakeStore) GetToken(_ context.Context, _ *User, p, n string) (string, error) {
	return s.tokens[p+"|"+n], nil
}

// TestRefreshTokenTTLEnforced pins that RefreshTokenTTL is enforced server-side:
// an unexpired token rotates, an expired one is rejected, and rotation re-stamps
// the window (sliding expiration).
func TestRefreshTokenTTLEnforced(t *testing.T) {
	ctx := context.Background()
	store := &tokenFakeStore{tokens: map[string]string{}}
	um := &UserManagerOf[User, *User]{Store: store}
	ts := NewTokenService(um, DefaultTokenOptions([]byte("ttl-test-signing-key-000000000000"), "iss", "aud"))
	u := &User{ID: "u1", UserName: "ttl", SecurityStamp: "s"}

	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	var pair *TokenPair
	withFrozenClock(t0, func() {
		var err error
		pair, err = ts.IssuePair(ctx, u)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
	})

	// Within the 7-day TTL: refresh succeeds and rotates (re-stamps the window).
	var pair2 *TokenPair
	withFrozenClock(t0.Add(6*24*time.Hour), func() {
		var err error
		pair2, err = ts.Refresh(ctx, u, pair.RefreshToken)
		if err != nil {
			t.Fatalf("refresh within TTL should succeed: %v", err)
		}
	})

	// 6 days after the rotation (12 days after t0): still inside the slid window.
	withFrozenClock(t0.Add(12*24*time.Hour), func() {
		var err error
		pair2, err = ts.Refresh(ctx, u, pair2.RefreshToken)
		if err != nil {
			t.Fatalf("refresh within slid window should succeed: %v", err)
		}
	})

	// 8 days after the last rotation: past the TTL — rejected.
	withFrozenClock(t0.Add(20*24*time.Hour), func() {
		if _, err := ts.Refresh(ctx, u, pair2.RefreshToken); err == nil {
			t.Fatal("expired refresh token must be rejected")
		}
	})

	// Legacy stored format (bare hash, no expiry) fails closed.
	store.tokens[refreshTokenProvider+"|"+refreshTokenName] = hashRefresh("legacy-token")
	withFrozenClock(t0, func() {
		if _, err := ts.Refresh(ctx, u, "legacy-token"); err == nil {
			t.Fatal("legacy (expiry-less) refresh token must be rejected")
		}
	})
}
