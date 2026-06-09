# go-idento

[![Go Reference](https://pkg.go.dev/badge/github.com/terglos/go-idento.svg)](https://pkg.go.dev/github.com/terglos/go-idento)
[![Go Report Card](https://goreportcard.com/badge/github.com/terglos/go-idento)](https://goreportcard.com/report/github.com/terglos/go-idento)
[![CI](https://github.com/terglos/go-idento/actions/workflows/ci.yml/badge.svg)](https://github.com/terglos/go-idento/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A complete, batteries-included **identity framework for Go** — user/role
management, password hashing, claims, lockout, two-factor and JWT, built on
pluggable stores so the persistence layer can be swapped without touching
business logic.

> Status: beta (v0.3.1). User/role/sign-in managers, PBKDF2 hashing, JWT
> (HS256/RS256/ES256) + JWKS, TOTP/SMS two-factor with recovery codes, external
> logins, email-confirmation/password-reset tokens, and policy authorization are
> implemented and tested. Four stores ship: in-memory, GORM, raw `pgx`, and a
> `sqlc`-generated `pgx` store — with configurable schema/table names and
> referential integrity (cascade delete + optimistic concurrency). The API may
> still change before v1.0.

**Docs:** [getting started](docs/getting-started.md) ·
[architecture](docs/architecture.md) ·
[extending the user & migrations](docs/design/extending-user-and-migrations.md) ·
[customizing the schema](docs/customizing-schema.md) ·
[contributor/agent guide](CLAUDE.md)

## Why

Go has JWT libraries and full identity providers (Ory, ZITADEL), but no
embedded, batteries-included identity toolkit you drop straight into your own
app and own your data. go-idento fills that gap with familiar building blocks —
`UserManager` / `RoleManager` / `SignInManager` over pluggable stores.

## What you get

| Area | API |
|---|---|
| Entities | `identity.User` / `identity.Role` / `identity.Claim` |
| Users | `identity.UserManager` (create, password add/change/remove, email & phone change, roles, claims, lockout, 2FA) |
| Roles | `identity.RoleManager` (CRUD + role claims, optimistic concurrency) |
| Queries | users-by-role / users-by-claim, paged `ListUsers` |
| Sign-in | `identity.SignInManager` (password, 2FA, external, remember-this-machine, security-stamp validation) |
| Two-factor | TOTP + SMS + recovery codes, pluggable `TwoFactorTokenProvider` |
| Tokens | `identity.TokenService` (JWT access + refresh, HS256/RS256/ES256) |
| Delivery | `identity.SMSSender` / `identity.EmailSender` (provider-agnostic) |
| Persistence | `identity.UserStore` / `identity.RoleStore` interfaces |
| Password hashing | `identity.PasswordHasher` (PBKDF2, versioned format) |
| Config | `identity.Options` (password / lockout / user / sign-in policy) |
| HTTP | `auth.RequireAuth` / `auth.RequireRole` / `auth.RequirePolicy` |

The default password hasher uses a **versioned PBKDF2 format**
(`0x01` marker, PRF/iterations/salt-length header, PBKDF2-HMAC-SHA256); the
version byte lets parameters evolve while old hashes keep verifying.

## Quick start

```go
db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
gormstore.Migrate(db)

users  := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
signIn := identity.NewSignInManager(users)
tokens := identity.NewTokenService(users,
    identity.DefaultTokenOptions(secret, "issuer", "audience"))

u := &identity.User{UserName: "jane", Email: "m@x.com"}
users.CreateWithPassword(ctx, u, "Abcdef1!")

res, signed := signIn.PasswordSignIn(ctx, "jane", "Abcdef1!", true)
if res.Succeeded {
    pair, _ := tokens.IssuePair(ctx, signed) // access + refresh token
}
```

Run the demo server:

```
cd stores/gormstore && go run ./examples/httpserver
```

## Modules

The repo is split so the **core stays dependency-light**: importing
`github.com/terglos/go-idento` pulls only `golang-jwt`, `google/uuid` and
`golang.org/x/crypto` — no ORM or DB driver. Each heavy store is its own module
you opt into:

| Module | Import | Extra deps |
|---|---|---|
| core | `github.com/terglos/go-idento` (+`/auth`, `/stores/memstore`) | jwt, uuid, x/crypto |
| GORM store | `github.com/terglos/go-idento/stores/gormstore` | gorm, drivers |
| pgx store | `github.com/terglos/go-idento/stores/pgxstore` | pgx |
| sqlc store | `github.com/terglos/go-idento/stores/pgxsqlc` | pgx |

## Layout

```
identity/          core: entities, managers, hasher, options, JWT, signer/JWKS
auth/              HTTP middleware: Bearer + cookie, RequireAuth/RequireRole/RequirePolicy, JWKS
stores/memstore/   in-memory implementation (tests / prototyping) — in the core module
stores/gormstore/  [module] GORM (Postgres / MySQL / SQLite) + examples
stores/pgxstore/   [module] raw pgx (PostgreSQL) + demo
stores/pgxsqlc/    [module] sqlc-generated pgx (PostgreSQL)
demo/totp/         TOTP code helper (core only)
```

## Extending the user

Four ways, smallest blast radius first (full analysis in
[docs/design/extending-user-and-migrations.md](docs/design/extending-user-and-migrations.md)):

```go
// Option D — custom typed columns on the user row.
type AppUser struct {
    identity.User          // embeds -> Base()/TableName() promoted
    TenantID string
}
db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
gormstore.MigrateOf[AppUser](db)
store := gormstore.NewUserStoreOf[AppUser](db)
um := identity.NewUserManagerOf[AppUser](store, identity.DefaultOptions())
um.CreateWithPassword(ctx, &AppUser{User: identity.User{UserName: "jane"}, TenantID: "acme"}, "Abcdef1!")
```

```go
// Option C — schema-less JSON attributes (no custom type).
u.SetAttribute("tenant", "acme")           // persisted in the attributes column
// Option B — claims (flow into the JWT). Option A — your own 1:1 extension table.
```

See [stores/gormstore/examples/genericuser](stores/gormstore/examples/genericuser) (Option D) and
[stores/gormstore/examples/customfields](stores/gormstore/examples/customfields) (Options A & B).

## Migrations

```go
// No CLI: apply the canonical schema from Go.
migrations.ApplyPostgres(ctx, sqlDB)
```

For versioned, reviewable history use **Atlas** (`atlas.hcl` + [migrations/](migrations)):
`atlas migrate diff <name> --env local` generates SQL from schema changes — the
EF `add-migration` loop. goose / golang-migrate can run the same SQL.

## Demos

- [`stores/pgxstore/example/postgres`](stores/pgxstore/example/postgres) — full flow
  against a real PostgreSQL via the raw `pgx` store: `docker compose up -d && go run .`
  then follow its README (register, login, JWT + cookie, refresh, role-gated route, TOTP 2FA).
- [`stores/gormstore/examples/httpserver`](stores/gormstore/examples/httpserver) — minimal
  zero-setup server on SQLite: `cd stores/gormstore && go run ./examples/httpserver`.

## Features

- [x] User/role management (`UserManager`, `RoleManager`, `SignInManager`)
- [x] PBKDF2 password hashing with a versioned wire format
- [x] JWT access + refresh tokens with security-stamp revocation
- [x] HS256, **RS256 and ES256** signing via pluggable `Signer` + `RSAKeyring` / `ECDSAKeyring` (kid rotation)
- [x] **JWKS endpoint** (`auth.JWKSHandler`) publishing RSA/EC public keys
- [x] TOTP two-factor (RFC 6238) + one-time recovery codes
- [x] **Phone (SMS) two-factor** via a pluggable `SMSSender`
- [x] Email confirmation, password-reset & change-email token providers
- [x] External/OAuth login association (`AddLogin` / `FindByLogin` / `ExternalLoginSignIn`)
- [x] Account lockout
- [x] Policy/claims authorization (`auth.Policy`, `RequirePolicy`) beyond roles
- [x] Stores: GORM (Postgres/MySQL/SQLite), raw `pgx`, **sqlc-generated** pgx, in-memory
- [x] **Configurable schema**: custom namespace / table prefix / table names per store
  (`WithSchema`/`WithTablePrefix`/`WithTableNames`) + `ON DELETE CASCADE` integrity ([docs](docs/customizing-schema.md))
- [x] **Extensible user**: custom columns via the generic `UserManagerOf[T]`
  (embed `identity.User`), a JSON `Attributes` bag, an extension table, or claims
- [x] **Migrations**: zero-CLI `migrations.ApplyPostgres`, plus Atlas config for
  versioned, diff-generated migrations (goose/golang-migrate also supported)

### Two-factor quick reference

```go
key, _ := users.GetAuthenticatorKey(ctx, u)       // provision (show as QR via identity.AuthenticatorURI)
users.SetTwoFactorEnabled(ctx, u, true)
res, u := signIn.PasswordSignIn(ctx, name, pw, true)
if res.RequiresTwoFactor {
    res = signIn.TwoFactorAuthenticatorSignIn(ctx, u, totpCode)
}
codes, _ := users.GenerateRecoveryCodes(ctx, u, 10)
```

### RS256 with key rotation

```go
ring := identity.NewRSAKeyring("key-1", privKey)
tokens := identity.NewTokenService(users, identity.TokenOptions{
    Signer: ring, Issuer: "issuer", Audience: "api",
    AccessTokenTTL: 15*time.Minute, RefreshTokenTTL: 7*24*time.Hour,
})
ring.Add("key-2", newKey, true) // new tokens use key-2; key-1 tokens still verify
ring.Remove("key-1")            // retire once no live tokens reference it
```

ES256 is identical — use `identity.NewECDSAKeyring(kid, ecdsaKey)`.

### JWKS endpoint

```go
ring := identity.NewRSAKeyring("key-1", privKey) // or NewECDSAKeyring
mux.Handle("/.well-known/jwks.json", auth.JWKSHandler(ring)) // publishes public keys
```

### Phone (SMS) two-factor

```go
users := identity.NewUserManager(store, opts).WithSMSSender(mySMSSender)
users.SendPhoneToken(ctx, u)                       // delivers a 6-digit code
res := signIn.TwoFactorPhoneSignIn(ctx, u, code)   // after PasswordSignIn returned RequiresTwoFactor
```

## Roadmap

- [ ] WebAuthn / passkeys
- [ ] Backchannel logout / token introspection endpoint

## License

Licensed under the [Apache License 2.0](LICENSE) — permissive, with an explicit
patent grant. See [NOTICE](NOTICE) for attribution. Built by
[Terglos](https://github.com/terglos).
