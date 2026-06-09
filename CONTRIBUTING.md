# Contributing to go-idento

Thanks for your interest in improving go-idento!

## Development

```bash
go build ./...
go test ./...          # no database required (uses SQLite/in-memory)
go vet ./...
gofmt -l .             # must be empty (excluding generated code)
```

Optional, matching CI:

```bash
staticcheck $(go list ./... | grep -v '/internal/sqlcgen')
govulncheck ./...
golangci-lint run
```

### Postgres integration tests (opt-in)

```bash
GOIDENTITY_PG_DSN="postgres://user:pass@localhost:5432/idento_test?sslmode=disable" \
  go test ./stores/pgxstore/
GOIDENTITY_PG_SQLC_DSN="postgres://user:pass@localhost:5432/idento_sqlc_test?sslmode=disable" \
  go test ./stores/pgxsqlc/
```

### Regenerating sqlc code

After editing `stores/pgxsqlc/schema.sql` or `query.sql`:

```bash
cd stores/pgxsqlc && sqlc generate
```

(`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest` if needed.) Commit the
generated `internal/sqlcgen` output.

## Guidelines

- Keep the core `identity` package free of database/driver imports — persistence
  lives behind the store interfaces.
- New store capabilities go on the `UserStore`/`RoleStore` interfaces and must be
  implemented in **all** bundled stores (gorm, pgx, pgxsqlc, memstore); the
  compile-time `var _ ...Store` assertions will catch omissions.
- Add tests against `memstore` (fast, DB-free); add a real-DB assertion to the
  pgx integration tests when SQL is involved.
- Preserve the back-compat aliases (`UserManager`, `SignInManager`,
  `TokenService`); new generic-only APIs go on the `...Of[T,PT]` types.
- Run `gofmt`, `go vet`, and the test suite before opening a PR.

## License

By contributing, you agree your contributions are licensed under the project's
[Apache 2.0 License](LICENSE).
