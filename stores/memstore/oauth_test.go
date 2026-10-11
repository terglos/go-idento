package memstore_test

import (
	"testing"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/oauth/oauthtest"
	"github.com/terglos/go-idento/stores/memstore"
)

func oauthEnv(t *testing.T) (oauth.Store, *identity.UserManager) {
	st := memstore.New()
	return st.OAuth(), identity.NewUserManager(st.Users(), identity.DefaultOptions())
}

func TestOAuthStoreConformance(t *testing.T) { oauthtest.RunStoreConformance(t, oauthEnv) }

func TestOAuthEndToEnd(t *testing.T) { oauthtest.RunEndToEnd(t, oauthEnv) }
