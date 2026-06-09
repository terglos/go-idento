package pgxsqlc

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Migrate applies the sqlc store's schema. It is idempotent (CREATE ... IF NOT
// EXISTS), so it is safe to run on startup. The same DDL is the source of truth
// for sqlc's compile-time query checking.
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, schema)
	return err
}
