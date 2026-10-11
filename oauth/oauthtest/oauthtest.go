// Package oauthtest provides reusable test suites for the oauth package: a
// store conformance suite (run it against any oauth.Store implementation) and
// an end-to-end protocol test that drives the real HTTP handlers. The bundled
// stores run both.
package oauthtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
)

// EnvFactory builds a fresh store plus a user manager over the same database
// (the store's user-scoped rows reference real users).
type EnvFactory func(t *testing.T) (oauth.Store, *identity.UserManager)

func mustUser(t *testing.T, um *identity.UserManager, name string) *identity.User {
	t.Helper()
	u := &identity.User{UserName: name, Email: name + "@example.com"}
	if err := um.CreateWithPassword(context.Background(), u, "Abcdef1!"); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func uniq(prefix string) string { return prefix + "_" + time.Now().Format("150405.000000000") }

// RunStoreConformance checks an oauth.Store implementation's contract.
func RunStoreConformance(t *testing.T, newEnv EnvFactory) {
	t.Run("Clients", func(t *testing.T) {
		ctx := context.Background()
		st, _ := newEnv(t)
		now := time.Now().UTC().Truncate(time.Second)
		c := &oauth.Client{ClientID: uniq("client"), Name: "Test", SecretHash: "h",
			RedirectURIs:            oauth.StringList{"https://a.example/cb", "http://127.0.0.1/cb"},
			TokenEndpointAuthMethod: oauth.AuthMethodClientSecretBasic,
			GrantTypes:              oauth.StringList{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken},
			CreatedAt:               now}
		if err := st.CreateClient(ctx, c); err != nil {
			t.Fatalf("CreateClient: %v", err)
		}
		got, err := st.GetClient(ctx, c.ClientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got.Name != "Test" || got.SecretHash != "h" || len(got.RedirectURIs) != 2 ||
			got.RedirectURIs[1] != "http://127.0.0.1/cb" || len(got.GrantTypes) != 2 ||
			got.TokenEndpointAuthMethod != oauth.AuthMethodClientSecretBasic || got.LastUsedAt != nil {
			t.Fatalf("client round-trip mismatch: %+v", got)
		}
		if _, err := st.GetClient(ctx, "missing"); !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("GetClient(missing) must be ErrNotFound, got %v", err)
		}
		if err := st.TouchClient(ctx, c.ClientID, now); err != nil {
			t.Fatalf("TouchClient: %v", err)
		}
		if got, _ := st.GetClient(ctx, c.ClientID); got.LastUsedAt == nil {
			t.Fatal("TouchClient must set LastUsedAt")
		}
	})

	t.Run("StaleClients", func(t *testing.T) {
		ctx := context.Background()
		st, um := newEnv(t)
		u := mustUser(t, um, uniq("stale"))
		old := time.Now().UTC().Add(-48 * time.Hour)
		mk := func(id string, created time.Time) {
			if err := st.CreateClient(ctx, &oauth.Client{ClientID: id, RedirectURIs: oauth.StringList{"https://x/cb"},
				TokenEndpointAuthMethod: oauth.AuthMethodNone, CreatedAt: created}); err != nil {
				t.Fatalf("create %s: %v", id, err)
			}
		}
		abandoned, withGrant, fresh := uniq("abandoned"), uniq("withgrant"), uniq("fresh")
		mk(abandoned, old)
		mk(withGrant, old)
		mk(fresh, time.Now().UTC())
		if err := st.CreateGrant(ctx, &oauth.Grant{ID: identity.NewConcurrencyStamp(), UserID: u.ID, ClientID: withGrant,
			Resource: "https://r.example", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		n, err := st.DeleteStaleClients(ctx, time.Now().UTC().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("DeleteStaleClients: %v", err)
		}
		if n < 1 {
			t.Fatalf("expected the abandoned client to be purged, n=%d", n)
		}
		if _, err := st.GetClient(ctx, abandoned); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("abandoned client must be purged")
		}
		if _, err := st.GetClient(ctx, withGrant); err != nil {
			t.Fatal("a client holding grants must be kept")
		}
		if _, err := st.GetClient(ctx, fresh); err != nil {
			t.Fatal("a recent client must be kept")
		}
	})

	t.Run("Codes", func(t *testing.T) {
		ctx := context.Background()
		st, um := newEnv(t)
		u := mustUser(t, um, uniq("coder"))
		c := &oauth.Code{CodeHash: uniq("hash"), ClientID: "https://client.example/meta.json", UserID: u.ID,
			RedirectURI: "http://127.0.0.1:5555/cb", Scopes: "a b", Resource: "https://r.example/mcp",
			CodeChallenge: "challenge", ExpiresAt: time.Now().Add(time.Minute)}
		if err := st.CreateCode(ctx, c); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}
		got, err := st.GetCode(ctx, c.CodeHash)
		if err != nil || got.UserID != u.ID || got.Scopes != "a b" || got.UsedAt != nil || got.ClientID != c.ClientID {
			t.Fatalf("GetCode mismatch: %+v err=%v", got, err)
		}
		won, err := st.MarkCodeUsed(ctx, c.CodeHash, "grant-1", time.Now())
		if err != nil || !won {
			t.Fatalf("first MarkCodeUsed must win: won=%v err=%v", won, err)
		}
		if won, _ := st.MarkCodeUsed(ctx, c.CodeHash, "grant-2", time.Now()); won {
			t.Fatal("second MarkCodeUsed must lose (single use)")
		}
		if got, _ := st.GetCode(ctx, c.CodeHash); got.UsedAt == nil || got.GrantID != "grant-1" {
			t.Fatalf("used code must record UsedAt and the first grant: %+v", got)
		}
		if _, err := st.GetCode(ctx, "missing"); !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("GetCode(missing) must be ErrNotFound, got %v", err)
		}
		expired := &oauth.Code{CodeHash: uniq("old"), ClientID: "c", UserID: u.ID, RedirectURI: "https://x/cb",
			CodeChallenge: "x", ExpiresAt: time.Now().Add(-time.Minute)}
		_ = st.CreateCode(ctx, expired)
		if n, err := st.DeleteExpiredCodes(ctx, time.Now()); err != nil || n < 1 {
			t.Fatalf("DeleteExpiredCodes: n=%d err=%v", n, err)
		}
		if _, err := st.GetCode(ctx, expired.CodeHash); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("expired code must be purged")
		}
		if _, err := st.GetCode(ctx, c.CodeHash); err != nil {
			t.Fatal("unexpired code must survive the purge")
		}
	})

	t.Run("Consents", func(t *testing.T) {
		ctx := context.Background()
		st, um := newEnv(t)
		u := mustUser(t, um, uniq("consenter"))
		if _, err := st.GetConsent(ctx, u.ID, "client"); !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("missing consent must be ErrNotFound, got %v", err)
		}
		now := time.Now().UTC()
		if err := st.SaveConsent(ctx, &oauth.Consent{UserID: u.ID, ClientID: "client", Scopes: "a", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("SaveConsent: %v", err)
		}
		if err := st.SaveConsent(ctx, &oauth.Consent{UserID: u.ID, ClientID: "client", Scopes: "a b", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("SaveConsent (upsert): %v", err)
		}
		got, err := st.GetConsent(ctx, u.ID, "client")
		if err != nil || got.Scopes != "a b" {
			t.Fatalf("upserted consent mismatch: %+v err=%v", got, err)
		}
		if err := st.DeleteConsent(ctx, u.ID, "client"); err != nil {
			t.Fatalf("DeleteConsent: %v", err)
		}
		if _, err := st.GetConsent(ctx, u.ID, "client"); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("consent must be deleted")
		}
	})

	t.Run("Grants", func(t *testing.T) {
		ctx := context.Background()
		st, um := newEnv(t)
		u := mustUser(t, um, uniq("granter"))
		g := &oauth.Grant{ID: identity.NewConcurrencyStamp(), UserID: u.ID, ClientID: "client-a", Scopes: "a",
			Resource: "https://r.example/mcp", TokenHash: "h1", SecurityStamp: "s",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
		if err := st.CreateGrant(ctx, g); err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		got, err := st.GetGrant(ctx, g.ID)
		if err != nil || got.TokenHash != "h1" || got.Resource != g.Resource || got.SecurityStamp != "s" {
			t.Fatalf("GetGrant mismatch: %+v err=%v", got, err)
		}
		ok, err := st.RotateGrant(ctx, g.ID, "h1", "h2", time.Now().Add(2*time.Hour), time.Now())
		if err != nil || !ok {
			t.Fatalf("RotateGrant with the current hash must succeed: ok=%v err=%v", ok, err)
		}
		got, _ = st.GetGrant(ctx, g.ID)
		if got.TokenHash != "h2" || got.PrevTokenHash != "h1" || got.LastUsedAt == nil {
			t.Fatalf("rotation must move h1 to prev and set last-used: %+v", got)
		}
		if ok, _ := st.RotateGrant(ctx, g.ID, "h1", "h3", time.Now(), time.Now()); ok {
			t.Fatal("RotateGrant with a stale hash must fail (compare-and-swap)")
		}
		g2 := &oauth.Grant{ID: identity.NewConcurrencyStamp(), UserID: u.ID, ClientID: "client-b", Resource: "https://r",
			ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now()}
		_ = st.CreateGrant(ctx, g2)
		list, err := st.ListUserGrants(ctx, u.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListUserGrants: n=%d err=%v", len(list), err)
		}
		if n, err := st.DeleteExpiredGrants(ctx, time.Now()); err != nil || n < 1 {
			t.Fatalf("DeleteExpiredGrants: n=%d err=%v", n, err)
		}
		if _, err := st.GetGrant(ctx, g2.ID); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("expired grant must be purged")
		}
		if n, err := st.DeleteUserClientGrants(ctx, u.ID, "client-a"); err != nil || n != 1 {
			t.Fatalf("DeleteUserClientGrants: n=%d err=%v", n, err)
		}
		if _, err := st.GetGrant(ctx, g.ID); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("client grants must be deleted")
		}
		if err := st.DeleteGrant(ctx, "missing"); err != nil {
			t.Fatalf("deleting a missing grant must be a no-op, got %v", err)
		}
	})

	t.Run("CascadeOnUserDelete", func(t *testing.T) {
		ctx := context.Background()
		st, um := newEnv(t)
		u := mustUser(t, um, uniq("leaver"))
		gid := identity.NewConcurrencyStamp()
		_ = st.CreateGrant(ctx, &oauth.Grant{ID: gid, UserID: u.ID, ClientID: "c", Resource: "https://r",
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()})
		_ = st.SaveConsent(ctx, &oauth.Consent{UserID: u.ID, ClientID: "c", Scopes: "a", CreatedAt: time.Now(), UpdatedAt: time.Now()})
		code := uniq("cascade")
		_ = st.CreateCode(ctx, &oauth.Code{CodeHash: code, ClientID: "c", UserID: u.ID, RedirectURI: "https://x/cb",
			CodeChallenge: "x", ExpiresAt: time.Now().Add(time.Minute)})
		if err := um.Delete(ctx, u); err != nil {
			t.Fatalf("delete user: %v", err)
		}
		if _, err := st.GetGrant(ctx, gid); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("grants must cascade with the user")
		}
		if _, err := st.GetConsent(ctx, u.ID, "c"); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("consents must cascade with the user")
		}
		if _, err := st.GetCode(ctx, code); !errors.Is(err, identity.ErrNotFound) {
			t.Fatal("codes must cascade with the user")
		}
	})
}
