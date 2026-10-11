package pgxstore_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/oauth/oauthtest"
	"github.com/terglos/go-idento/stores/pgxstore"
)

// TestPgxOAuth runs the OAuth store conformance suite and the end-to-end
// protocol suite against real PostgreSQL (opt-in via GOIDENTITY_PG_DSN), with
// the default layout and with a custom schema + table prefix.
func TestPgxOAuth(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_DSN to run the pgx OAuth integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	for name, opts := range map[string][]pgxstore.Option{
		"default":       nil,
		"schema+prefix": {pgxstore.WithSchema("idoauth"), pgxstore.WithTablePrefix("app_")},
	} {
		opts := opts
		t.Run(name, func(t *testing.T) {
			if len(opts) > 0 {
				_, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS idoauth CASCADE")
				t.Cleanup(func() { _, _ = pool.Exec(ctx, "DROP SCHEMA IF EXISTS idoauth CASCADE") })
			}
			if err := pgxstore.Migrate(ctx, pool, opts...); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			env := func(t *testing.T) (oauth.Store, *identity.UserManager) {
				return pgxstore.NewOAuthStore(pool, opts...),
					identity.NewUserManager(pgxstore.NewUserStore(pool, opts...), identity.DefaultOptions())
			}
			oauthtest.RunStoreConformance(t, env)
			oauthtest.RunEndToEnd(t, env)
		})
	}
}

// TestPgxOAuthUntypedExecModes runs the OAuth suites in the exec modes required
// behind a transaction-pooling proxy (PgBouncer and friends), which send
// parameters without type information — see TestUntypedExecModes.
func TestPgxOAuthUntypedExecModes(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_DSN to run the pgx OAuth exec-mode test")
	}
	for name, mode := range map[string]pgx.QueryExecMode{
		"Exec":           pgx.QueryExecModeExec,
		"SimpleProtocol": pgx.QueryExecModeSimpleProtocol,
	} {
		mode := mode
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("parse dsn: %v", err)
			}
			cfg.ConnConfig.DefaultQueryExecMode = mode
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			t.Cleanup(pool.Close)
			if err := pgxstore.Migrate(ctx, pool); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			env := func(t *testing.T) (oauth.Store, *identity.UserManager) {
				return pgxstore.NewOAuthStore(pool),
					identity.NewUserManager(pgxstore.NewUserStore(pool), identity.DefaultOptions())
			}
			oauthtest.RunStoreConformance(t, env)
			oauthtest.RunEndToEnd(t, env)
		})
	}
}
