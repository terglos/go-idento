package memstore_test

import (
	"context"
	"strings"
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/memstore"
)

func newSessionHarness(t *testing.T, maxSessions int) (*identity.TokenService, *identity.UserManager, *identity.User) {
	t.Helper()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	opts := identity.DefaultTokenOptions([]byte("sessions-signing-key-000000000000"), "go-idento", "api")
	opts.MaxSessions = maxSessions
	ts := identity.NewTokenService(um, opts).WithSessionStore(st.RefreshTokens())
	u := &identity.User{UserName: "multi", Email: "multi@x.com"}
	if err := um.CreateWithPassword(context.Background(), u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	return ts, um, u
}

// TestConcurrentSessions pins the client's core acceptance criteria: two logins
// hold independent refresh tokens, and rotating one session does not invalidate
// the other (the v0.5.0 single-slot behavior overwrote them).
func TestConcurrentSessions(t *testing.T) {
	ctx := context.Background()
	ts, _, u := newSessionHarness(t, 0)

	// Device A and device B log in.
	pairA, err := ts.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue A: %v", err)
	}
	pairB, err := ts.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("issue B: %v", err)
	}
	if !strings.Contains(pairA.RefreshToken, ".") || pairA.RefreshToken == pairB.RefreshToken {
		t.Fatal("session tokens should be distinct and carry a session id")
	}

	// Both redeem independently — B's login did NOT kill A.
	pairA2, err := ts.Refresh(ctx, u, pairA.RefreshToken)
	if err != nil {
		t.Fatalf("refresh A must survive B's login: %v", err)
	}
	// Rotating A did not invalidate B.
	pairB2, err := ts.Refresh(ctx, u, pairB.RefreshToken)
	if err != nil {
		t.Fatalf("refresh B must survive A's rotation: %v", err)
	}
	// Rotation still invalidates the OLD token of the SAME session.
	if _, err := ts.Refresh(ctx, u, pairA.RefreshToken); err == nil {
		t.Fatal("rotated-away token of session A must be rejected")
	}
	// And the rotated tokens keep their session identity (same prefix).
	sidA := strings.SplitN(pairA.RefreshToken, ".", 2)[0]
	if !strings.HasPrefix(pairA2.RefreshToken, sidA+".") {
		t.Fatal("rotation must stay within the same session")
	}
	_ = pairB2
}

// TestRevokeSessionAndGlobal: RevokeSession kills one device; Revoke kills all.
func TestRevokeSessionAndGlobal(t *testing.T) {
	ctx := context.Background()
	ts, _, u := newSessionHarness(t, 0)

	pairA, _ := ts.IssuePair(ctx, u)
	pairB, _ := ts.IssuePair(ctx, u)

	// Revoke only session A.
	if err := ts.RevokeSession(ctx, u, pairA.RefreshToken); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := ts.Refresh(ctx, u, pairA.RefreshToken); err == nil {
		t.Fatal("revoked session A must not refresh")
	}
	if _, err := ts.Refresh(ctx, u, pairB.RefreshToken); err != nil {
		t.Fatalf("session B must survive A's revocation: %v", err)
	}

	// Global revoke kills everything.
	pairC, _ := ts.IssuePair(ctx, u)
	if err := ts.Revoke(ctx, u); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := ts.Refresh(ctx, u, pairC.RefreshToken); err == nil {
		t.Fatal("global revoke must kill every session")
	}
	if sessions, _ := ts.ListSessions(ctx, u); len(sessions) != 0 {
		t.Fatalf("no sessions should remain after global revoke, got %d", len(sessions))
	}
}

// TestMaxSessionsOne restores the legacy single-session behavior on demand:
// a second login evicts the first.
func TestMaxSessionsOne(t *testing.T) {
	ctx := context.Background()
	ts, _, u := newSessionHarness(t, 1)

	pairA, _ := ts.IssuePair(ctx, u)
	pairB, _ := ts.IssuePair(ctx, u) // evicts A (MaxSessions: 1)

	if _, err := ts.Refresh(ctx, u, pairA.RefreshToken); err == nil {
		t.Fatal("with MaxSessions=1, the second login must evict the first session")
	}
	if _, err := ts.Refresh(ctx, u, pairB.RefreshToken); err != nil {
		t.Fatalf("the newest session must remain valid: %v", err)
	}
	if sessions, _ := ts.ListSessions(ctx, u); len(sessions) != 1 {
		t.Fatalf("expected exactly 1 session, got %d", len(sessions))
	}
}

// TestLegacyTokenMigration: a token issued WITHOUT the session store (v0.5.0
// format, no session id) keeps redeeming after the store is enabled, and its
// rotation lands in a session.
func TestLegacyTokenMigration(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	um := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	opts := identity.DefaultTokenOptions([]byte("legacy-signing-key-0000000000000!"), "go-idento", "api")
	tsLegacy := identity.NewTokenService(um, opts) // no session store: single slot
	u := &identity.User{UserName: "legacy", Email: "l@x.com"}
	if err := um.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		t.Fatalf("create: %v", err)
	}
	oldPair, err := tsLegacy.IssuePair(ctx, u)
	if err != nil {
		t.Fatalf("legacy issue: %v", err)
	}
	if strings.Contains(oldPair.RefreshToken, ".") {
		t.Fatal("precondition: legacy token must have no session id")
	}

	// The app upgrades: same options, now with a session store.
	ts := identity.NewTokenService(um, opts).WithSessionStore(st.RefreshTokens())
	newPair, err := ts.Refresh(ctx, u, oldPair.RefreshToken)
	if err != nil {
		t.Fatalf("legacy token must keep redeeming after upgrade: %v", err)
	}
	if !strings.Contains(newPair.RefreshToken, ".") {
		t.Fatal("legacy rotation must migrate into a session token")
	}
	// The legacy slot is retired: the old token no longer redeems.
	if _, err := ts.Refresh(ctx, u, oldPair.RefreshToken); err == nil {
		t.Fatal("legacy token must be single-use across the migration")
	}
	// GC also cleans sessions when the user is deleted (cascade).
	if err := um.Delete(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if sessions, _ := ts.ListSessions(ctx, u); len(sessions) != 0 {
		t.Fatalf("sessions must cascade with the user, got %d", len(sessions))
	}
}
