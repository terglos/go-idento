package gormstore_test

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/oauth/oauthtest"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openMemDB opens an in-memory SQLite database. Every new connection to
// ":memory:" is a separate, empty database, so the pool is pinned to one
// connection (the conformance suite calls the store concurrently).
func openMemDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return db
}

func oauthEnv(t *testing.T) (oauth.Store, *identity.UserManager) {
	t.Helper()
	db := openMemDB(t)
	if err := gormstore.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gormstore.NewOAuthStore(db), identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
}

func TestOAuthStoreConformance(t *testing.T) { oauthtest.RunStoreConformance(t, oauthEnv) }

func TestOAuthEndToEnd(t *testing.T) { oauthtest.RunEndToEnd(t, oauthEnv) }

// TestOAuthCustomNaming runs the conformance suite with a schema-less custom
// prefix, proving the OAuth tables honor WithTablePrefix like the others.
func TestOAuthCustomNaming(t *testing.T) {
	oauthtest.RunStoreConformance(t, func(t *testing.T) (oauth.Store, *identity.UserManager) {
		db := openMemDB(t)
		opt := gormstore.WithTablePrefix("app_")
		if err := gormstore.Migrate(db, opt); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return gormstore.NewOAuthStore(db, opt), identity.NewUserManager(gormstore.NewUserStore(db, opt), identity.DefaultOptions())
	})
}
