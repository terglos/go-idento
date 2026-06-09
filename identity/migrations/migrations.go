// Package migrations exposes the canonical go-identity schema as an embedded
// asset, so applications can bootstrap the database with the standard
// library's database/sql — no ORM, no external migration CLI required.
//
// For a versioned, reviewable migration history in production, feed the same
// SQL to Atlas (see atlas.hcl at the repo root), goose, or golang-migrate.
package migrations

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed postgres.sql
var postgresSchema string

// PostgresSchema returns the canonical PostgreSQL DDL as a string.
func PostgresSchema() string { return postgresSchema }

// ApplyPostgres executes the canonical schema against db. It is idempotent
// (every statement uses IF NOT EXISTS), so it is safe to run on every boot.
func ApplyPostgres(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, postgresSchema)
	return err
}
