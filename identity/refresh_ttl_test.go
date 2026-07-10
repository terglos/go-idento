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
func (s *tokenFakeStore) RemoveToken(_ context.Context, _ *User, p, n string) error {
	delete(s.tokens, p+"|"+n)
	return nil
}

// fakeSessionStore is a map-backed RefreshTokenStore for clock-frozen tests.
type fakeSessionStore struct{ sessions map[string]*RefreshToken }

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{sessions: map[string]*RefreshToken{}}
}

func (s *fakeSessionStore) CreateRefreshToken(_ context.Context, rt *RefreshToken) error {
	c := *rt
	s.sessions[rt.SessionID] = &c
	return nil
}
func (s *fakeSessionStore) GetRefreshTokenBySession(_ context.Context, id string) (*RefreshToken, error) {
	rt, ok := s.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *rt
	return &c, nil
}
func (s *fakeSessionStore) UpdateRefreshToken(_ context.Context, rt *RefreshToken) error {
	if _, ok := s.sessions[rt.SessionID]; !ok {
		return ErrNotFound
	}
	c := *rt
	s.sessions[rt.SessionID] = &c
	return nil
}
func (s *fakeSessionStore) DeleteRefreshToken(_ context.Context, id string) error {
	delete(s.sessions, id)
	return nil
}
func (s *fakeSessionStore) DeleteUserRefreshTokens(_ context.Context, userID string) (int64, error) {
	var n int64
	for id, rt := range s.sessions {
		if rt.UserID == userID {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}
func (s *fakeSessionStore) DeleteExpiredRefreshTokens(_ context.Context, before time.Time) (int64, error) {
	var n int64
	for id, rt := range s.sessions {
		if rt.ExpiresAt.Before(before) {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}
func (s *fakeSessionStore) ListUserRefreshTokens(_ context.Context, userID string) ([]RefreshToken, error) {
	var out []RefreshToken
	for _, rt := range s.sessions {
		if rt.UserID == userID {
			out = append(out, *rt)
		}
	}
	return out, nil
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

// TestSessionRefreshTTL pins the per-session sliding TTL: an actively-refreshed
// session slides its window while a dormant session dies at the TTL, and the
// opportunistic GC removes the dead row when another session is issued.
func TestSessionRefreshTTL(t *testing.T) {
	ctx := context.Background()
	store := &tokenFakeStore{tokens: map[string]string{}}
	sessions := newFakeSessionStore()
	um := &UserManagerOf[User, *User]{Store: store}
	ts := NewTokenService(um, DefaultTokenOptions([]byte("session-ttl-key-00000000000000000"), "iss", "aud")).
		WithSessionStore(sessions)
	u := &User{ID: "u1", UserName: "ttl", SecurityStamp: "s"}

	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	var active, dormant *TokenPair
	withFrozenClock(t0, func() {
		active, _ = ts.IssuePair(ctx, u)
		dormant, _ = ts.IssuePair(ctx, u)
	})

	// Day 6: the active session refreshes (slides); the dormant one is untouched.
	withFrozenClock(t0.Add(6*24*time.Hour), func() {
		var err error
		active, err = ts.Refresh(ctx, u, active.RefreshToken)
		if err != nil {
			t.Fatalf("active session should slide: %v", err)
		}
	})

	// Day 10: dormant (issued day 0, 7-day TTL) is dead; active (slid to day 13) lives.
	withFrozenClock(t0.Add(10*24*time.Hour), func() {
		if _, err := ts.Refresh(ctx, u, dormant.RefreshToken); err == nil {
			t.Fatal("dormant session must die at its TTL")
		}
		if _, err := ts.Refresh(ctx, u, active.RefreshToken); err != nil {
			t.Fatalf("active session must still be alive: %v", err)
		}
		// A new issuance runs the opportunistic GC: the expired dormant row goes.
		if _, err := ts.IssuePair(ctx, u); err != nil {
			t.Fatalf("issue: %v", err)
		}
		for id, rt := range sessions.sessions {
			if rt.ExpiresAt.Before(t0.Add(10 * 24 * time.Hour)) {
				t.Fatalf("expired session %s should have been GC'd", id)
			}
		}
	})
}
