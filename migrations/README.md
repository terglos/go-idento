# migrations

Versioned schema history for go-idento. The baseline matches
[`identity/migrations/postgres.sql`](../identity/migrations/postgres.sql).

## Choose your path

**No CLI (library).** Apply the canonical schema from Go:

```go
import "github.com/terglos/go-idento/identity/migrations"
migrations.ApplyPostgres(ctx, db) // database/sql; idempotent
```

**Atlas (recommended for production).** Versioned, reviewable, diff-generated:

```bash
# generate a new migration from a schema change
atlas migrate diff add_something --env local
# after editing files, refresh the integrity hash
atlas migrate hash --dir file://migrations
# apply
atlas migrate apply --env local --url "postgres://user:pass@localhost:5432/db?sslmode=disable"
```

`--env local` diffs against `identity/migrations/postgres.sql`. To drive the diff
from the GORM models instead (so extending `AppUser` via `UserManagerOf[T]`
auto-generates migrations), follow the commented `gorm` env recipe in
`atlas.hcl` — it uses the `atlas-provider-gorm` loader in a separate module so
the provider never enters go-idento's own dependency graph.

**goose / golang-migrate.** These run the SQL too; point them at this directory
(golang-migrate expects `*.up.sql` / `*.down.sql` pairs, so split the baseline
if you adopt it).

> `atlas.sum` is created by `atlas migrate hash` on first use; it is intentionally
> not committed here because it depends on your Atlas version.
