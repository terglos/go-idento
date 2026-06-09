# Atlas configuration for go-identity (https://atlasgo.io).
#
# Default workflow uses the canonical schema file as the desired state — no Go
# dependencies required:
#
#   atlas migrate diff <name> --env local     # generate a versioned migration
#   atlas migrate apply --env local --url <db-url>
#
# This reproduces the ASP.NET Core "add-migration" loop: edit the schema (or
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
# automatically. Requires `go get ariga.io/atlas-provider-gorm/gormschema` and
# the build-tagged loader in tools/atlasloader.
#
# data "external_schema" "gorm" {
#   program = ["go", "run", "-tags", "atlas", "./tools/atlasloader"]
# }
# env "gorm" {
#   src = data.external_schema.gorm.url
#   dev = "docker://postgres/16/dev?search_path=public"
#   migration { dir = "file://migrations" }
# }
