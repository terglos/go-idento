# Atlas configuration for go-idento (https://atlasgo.io).
#
# Default workflow uses the canonical schema file as the desired state — no Go
# dependencies required:
#
#   atlas migrate diff <name> --env local     # generate a versioned migration
#   atlas migrate apply --env local --url <db-url>
#
# This gives you a migrate-diff workflow: edit the schema (or
# extend it via the generic UserManagerOf[T] + GORM provider, see below), then
# diff to get reviewable, versioned SQL under ./migrations.

env "local" {
  # Desired state: the canonical schema kept in sync with the entities.
  src = "file://identity/migrations/postgres.sql"

  # A throwaway dev database Atlas uses to compute diffs. Requires Docker, or
  # point it at any scratch Postgres via `dev = "postgres://..."`.
  dev = "docker://postgres/16/dev?search_path=public"

  migration {
    dir = "file://migrations"
  }

  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

# Optional: drive the desired state from the GORM models instead of the SQL
# file, so extending AppUser (generic UserManagerOf[T]) regenerates migrations
# automatically. To keep this library dependency-free, the GORM provider is not
# vendored here. To enable it, in a SEPARATE module (so atlas-provider-gorm does
# not enter go-idento's dependency graph) add a loader:
#
#   // loader/main.go
#   package main
#   import (
#     "io"; "os"
#     "ariga.io/atlas-provider-gorm/gormschema"
#     "github.com/terglos/go-idento/identity"
#   )
#   func main() {
#     stmts, _ := gormschema.New("postgres").Load(
#       &identity.User{}, &identity.Role{}, &identity.UserRole{},
#       &identity.UserClaim{}, &identity.RoleClaim{},
#       &identity.UserLogin{}, &identity.UserToken{},
#       // ...plus your own &AppUser{}
#     )
#     io.WriteString(os.Stdout, stmts)
#   }
#
# then point an env at it:
#
# data "external_schema" "gorm" {
#   program = ["go", "run", "./loader"]
# }
# env "gorm" {
#   src = data.external_schema.gorm.url
#   dev = "docker://postgres/16/dev?search_path=public"
#   migration { dir = "file://migrations" }
# }
