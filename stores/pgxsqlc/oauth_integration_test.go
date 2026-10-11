package pgxsqlc_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/oauth/oauthtest"
	"github.com/terglos/go-idento/stores/pgxsqlc"
)

// TestSqlcOAuth runs the OAuth store conformance and end-to-end suites against
// real PostgreSQL through the sqlc store (opt-in via GOIDENTITY_PG_SQLC_DSN).
func TestSqlcOAuth(t *testing.T) {
	dsn := os.Getenv("GOIDENTITY_PG_SQLC_DSN")
	if dsn == "" {
		t.Skip("set GOIDENTITY_PG_SQLC_DSN to run the sqlc OAuth integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pgxsqlc.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	env := func(t *testing.T) (oauth.Store, *identity.UserManager) {
		return pgxsqlc.NewOAuthStore(pool), identity.NewUserManager(pgxsqlc.NewUserStore(pool), identity.DefaultOptions())
	}
	oauthtest.RunStoreConformance(t, env)
	oauthtest.RunEndToEnd(t, env)
}
