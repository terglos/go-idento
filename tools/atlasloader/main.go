//go:build atlas

// Command atlasloader prints the go-identity GORM schema as SQL for Atlas's
// external_schema provider. It is excluded from normal builds by the `atlas`
// build tag, so it adds no dependencies unless you opt in:
//
//	go get ariga.io/atlas-provider-gorm/gormschema
//	atlas migrate diff <name> --env gorm   # uses atlas.hcl's "gorm" env
//
// Add your own extended user type (e.g. *AppUser) to the Load call so Atlas
// picks up custom columns automatically.
package main

import (
	"io"
	"os"

	"ariga.io/atlas-provider-gorm/gormschema"
	"github.com/terglos/go-idento/identity"
)

func main() {
	stmts, err := gormschema.New("postgres").Load(
		&identity.User{}, &identity.Role{}, &identity.UserRole{},
		&identity.UserClaim{}, &identity.RoleClaim{},
		&identity.UserLogin{}, &identity.UserToken{},
	)
	if err != nil {
		panic(err)
	}
	_, _ = io.WriteString(os.Stdout, stmts)
}
