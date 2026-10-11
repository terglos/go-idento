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

func oauthEnv(t *testing.T) (oauth.Store, *identity.UserManager) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
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
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		opt := gormstore.WithTablePrefix("app_")
		if err := gormstore.Migrate(db, opt); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return gormstore.NewOAuthStore(db, opt), identity.NewUserManager(gormstore.NewUserStore(db, opt), identity.DefaultOptions())
	})
}
