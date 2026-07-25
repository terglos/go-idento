package pgxstore_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/pgxstore"
)

// TestUntypedExecModes guards the jsonb columns against the query exec modes
// that send parameters without type information.
//
// Anyone behind a transaction-pooling proxy (PgBouncer, PSBouncer, …) has to
// run QueryExecModeExec or QueryExecModeSimpleProtocol: every other mode needs
// server-side state to survive between round trips, which such a pooler
// breaks. In those two modes pgx binds a []byte as bytea, so a jsonb column
// answers `invalid input syntax for type json` (SQLSTATE 22P02) — which is
// exactly what took down user sign-up for a caller running behind PSBouncer.
// The stores therefore pass json/jsonb parameters as string.
//
// The default exec mode does NOT reproduce this, which is why the rest of the
// suite stayed green while real deployments failed.
func TestUntypedExecModes(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_DSN to run the pgx exec-mode test")
	}

	for _, tc := range []struct {
		name string
		mode pgx.QueryExecMode
	}{
		{"Exec", pgx.QueryExecModeExec},
		{"SimpleProtocol", pgx.QueryExecModeSimpleProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("parse dsn: %v", err)
			}
			cfg.ConnConfig.DefaultQueryExecMode = tc.mode
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer pool.Close()
			if err := pgxstore.Migrate(ctx, pool); err != nil {
				t.Fatalf("migrate: %v", err)
			}

			users := pgxstore.NewUserStore(pool)

			// The store writes what it is given; normalization is the user
			// manager's job, so fill the unique keys explicitly here.
			newUser := func(tag string) *identity.User {
				name := "execmode-" + tag + "-" + tc.name
				return &identity.User{
					ID: name, UserName: name, NormalizedUserName: strings.ToUpper(name),
					Email: name + "@example.com", NormalizedEmail: strings.ToUpper(name + "@example.com"),
				}
			}

			// No attributes: the "{}" default still crosses the wire.
			plain := newUser("plain")
			if err := users.Create(ctx, plain); err != nil {
				t.Fatalf("create without attributes: %v", err)
			}
			t.Cleanup(func() { _ = users.Delete(ctx, plain) })

			// With attributes: a real marshalled object.
			withAttrs := newUser("attrs")
			withAttrs.Attributes = identity.Attributes{"plan": "pro", "seats": "3"}
			if err := users.Create(ctx, withAttrs); err != nil {
				t.Fatalf("create with attributes: %v", err)
			}
			t.Cleanup(func() { _ = users.Delete(ctx, withAttrs) })

			got, err := users.FindByID(ctx, withAttrs.ID)
			if err != nil {
				t.Fatalf("find: %v", err)
			}
			if got == nil || got.Attributes["plan"] != "pro" {
				t.Fatalf("attributes did not round-trip: %#v", got)
			}

			// Update goes through the same binding.
			got.Attributes["plan"] = "enterprise"
			if err := users.Update(ctx, got); err != nil {
				t.Fatalf("update: %v", err)
			}

			// api_keys.scopes is the other jsonb column.
			keys := pgxstore.NewAPIKeyStore(pool)
			key := &identity.APIKey{
				ID:     "execmode-key-" + tc.name,
				UserID: withAttrs.ID, Name: "execmode", Prefix: "em_" + tc.name,
				KeyHash: "hash-" + tc.name, Scopes: identity.Scopes{"read", "write"},
				CreatedAt: time.Now(),
			}
			if err := keys.CreateAPIKey(ctx, key); err != nil {
				t.Fatalf("create api key: %v", err)
			}
		})
	}
}
