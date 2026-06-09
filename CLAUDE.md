# CLAUDE.md

Guidance for AI assistants (and humans) working in this repository.

## What this is

`go-idento` (module `github.com/terglos/go-idento`) is a complete, embedded
identity framework for Go: user/role management, password hashing, claims,
lockout, two-factor, external logins and JWT — built on **pluggable stores** so
persistence can be swapped without touching business logic. The API is built
around familiar building blocks (`UserManager` / `RoleManager` /
`SignInManager` + store interfaces).

Design goal: a batteries-included identity toolkit you embed in your own app and
own your data, including the "extend the user model + generate a migration"
workflow.

## Layout

```
identity/              core (no DB dependency)
  entities.go          User/Role/Claim + identity tables; UserModel + Base()
  user_manager.go      UserManagerOf[T,PT]  (alias UserManager = ...[User,*User])
  role_manager.go      RoleManager (concrete; roles are not generic)
  signin_manager.go    SignInManagerOf[T,PT] + SignInResult
  token_service.go     TokenServiceOf[T,PT]: JWT access/refresh issue+validate
  signer.go            Signer abstraction: HMAC (HS256) and RSAKeyring (RS256 + rotation)
  ecdsa_signer.go      ECDSAKeyring (ES256 + rotation)
  jwks.go              JWK/JWKSet + JWKS() on the RSA/ECDSA keyrings
  token_provider.go    DataTokenProvider: email-confirm / password-reset tokens
  totp.go              RFC 6238 TOTP + otpauth URI
  twofactor.go         authenticator key + one-time recovery codes (on UserManagerOf)
  twofactor_providers.go pluggable TwoFactorTokenProvider + GenerateUserToken/VerifyUserToken/GetValidTwoFactorProviders
  phone.go             SMS two-factor (SMSSender) + phone change flow (token bound to new number)
  email.go             EmailSender + SendEmailConfirmation/SendPasswordReset helpers
  external_login.go    OAuth/OIDC login association + ExternalLoginSignIn
  hasher.go            PBKDF2 password hasher — versioned wire format (0x01 marker)
  options.go           IdentityOptions (password/lockout/user/signin policy)
  store.go             UserStore[T,PT] interface + DefaultUserStore alias; RoleStore
  migrations/          embed.FS canonical schema + ApplyPostgres (no CLI)
auth/                  HTTP layer
  middleware.go        Bearer+cookie auth -> Principal; RequireAuth / RequireRole
  policy.go            Policy/claims authorization + RequirePolicy
  cookie.go            CookieAuth (HttpOnly cookie sessions)
  jwks.go              JWKSHandler (serves a Signer's public keys)
stores/
  memstore/            in-memory store (tests/prototyping) — part of the CORE module
  gormstore/           [own module] GORM (Postgres/MySQL/SQLite); generic.go = NewUserStoreOf[T]
    examples/          httpserver (SQLite), customfields (A/B), genericuser (D)
  pgxstore/            [own module] raw pgx (PostgreSQL) + example/postgres demo
  pgxsqlc/             [own module] sqlc-generated pgx store; regenerate: `sqlc generate`
demo/totp/             TOTP code helper (core only)
migrations/            versioned SQL history (baseline); atlas.hcl at repo root

Multi-module repo: the root module is dependency-light (jwt/uuid/x-crypto);
gorm/pgx live in the per-store submodules. go.work ties them for local dev.
tools/atlasloader/     Atlas GORM provider loader (build tag `atlas`)
docs/                  architecture, getting-started, design records
```

## Core conventions

- **Generics with back-compat aliases.** Managers/stores are generic over a
  user type `T` (and its pointer `PT`). A custom type embeds `identity.User`,
  which promotes `Base() *User` (satisfying `UserModel`) and `TableName()`. The
  built-in path uses aliases (`UserManager = UserManagerOf[User, *User]`), so the
  non-generic API still works. Inside managers, get base fields via `u.Base()`.
- **Stores are interfaces.** Business logic never imports a DB driver. The three
  stores all satisfy `identity.DefaultUserStore` (= `UserStore[User, *User]`);
  custom user types use `gormstore.NewUserStoreOf[T]`.
- **Security stamp = revocation.** Password/2FA/email changes call `newStamp()`;
  it's embedded in JWTs and re-checked on validation, so old tokens die.
- **Password hashes use a versioned format** (marker `0x01`, PRF/iter/salt-len
  header, PBKDF2-HMAC-SHA256). Don't change the wire format without a version bump.
- **Errors** are typed `*IdentityError` with a code; stores return the
  `ErrNotFound` sentinel for missing rows.
- **Normalization** is uppercase-invariant (`NormalizedUserName`/`Email`),
  always look up by the normalized value.

## Build / test

```bash
go build ./...
go vet ./...
go test ./...                 # no database needed (uses sqlite/memstore)
gofmt -l .                    # must be empty
```

Postgres integration test (opt-in):

```bash
GOIDENTITY_PG_DSN="postgres://postgres:123@localhost:5432/identity_test?sslmode=disable" \
  go test ./stores/pgxstore/ -run TestPgxIntegration
```

Run the Postgres demo: see [stores/pgxstore/example/postgres/README.md](stores/pgxstore/example/postgres/README.md).
Local dev DB credentials and DSN are in the assistant memory (`local-postgres`).

> `-race` requires CGO; this dev machine has CGO disabled, so race tests don't run here.

## Extending the user (4 options)

Smallest blast radius first; full analysis in
[docs/design/extending-user-and-migrations.md](docs/design/extending-user-and-migrations.md):

- **A. Extension table** (1:1, app-owned) — no framework change.
- **B. Claims** as attributes — flow into the JWT.
- **C. `Attributes` JSON column** — `u.SetAttribute(k,v)`; jsonb on Postgres.
- **D. Generic `UserManagerOf[T]`** — typed custom columns on the user row
  (`gormstore.NewUserStoreOf[T]` + `MigrateOf[T]`).

## Migrations

- Dev/tests: GORM `AutoMigrate` / pgx embedded `schema.sql` / `migrations.ApplyPostgres`.
- Production: **Atlas** (`atlas.hcl`) generates versioned SQL via
  `atlas migrate diff` — the EF `add-migration` loop. goose/golang-migrate can
  consume the same SQL.

## When adding features

1. Add core logic to `identity/` against the store interface (never a driver).
2. If it needs storage, extend `UserStore`/`RoleStore` and implement in **all
   three** stores (gorm, pgx, mem) — the compile-time `var _ ...Store` assertions
   will tell you if you missed one.
3. Add tests against `memstore` (fast, DB-free); add a real-DB assertion to the
   pgx integration test when SQL is involved.
4. Keep the `UserManager`/etc. aliases working; new generic-only APIs go on the
   `...Of[T,PT]` types.
5. `gofmt`, `go vet`, `go test ./...` before finishing. Update README + docs.

## Regenerating sqlc

The `stores/pgxsqlc` package's `internal/sqlcgen` is generated. After editing
`schema.sql`/`query.sql`, run `sqlc generate` from `stores/pgxsqlc/`
(`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest` if missing). Keep the
generated code committed.

## Roadmap (not yet done)

WebAuthn/passkeys · backchannel logout / token introspection · generic role types.
