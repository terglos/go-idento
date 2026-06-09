# go-idento

A Go port of **ASP.NET Core Identity** — user/role management, password hashing,
claims, lockout, two-factor flags and JWT, built on pluggable stores so the
persistence layer can be swapped without touching business logic.

> Status: early. Core managers, GORM store, password hasher, JWT + cookie auth,
> and an end-to-end example are implemented and tested.

**Docs:** [getting started](docs/getting-started.md) ·
[architecture](docs/architecture.md) ·
[extending the user & migrations](docs/design/extending-user-and-migrations.md) ·
[contributor/agent guide](CLAUDE.md)

## Why

Go has JWT libraries and full IdPs (Ory, ZITADEL), but nothing with the
embedded, batteries-included ergonomics of ASP.NET Core Identity
(`UserManager` / `RoleManager` / `SignInManager` + pluggable stores). This fills
that gap.

## Mapping to ASP.NET Core Identity

| ASP.NET Core Identity | go-identity |
|---|---|
| `IdentityUser` / `IdentityRole` | `identity.User` / `identity.Role` |
| `AspNetUsers` … schema | `identity_users` … (same columns) |
| `UserManager<TUser>` | `identity.UserManager` |
| `RoleManager<TRole>` | `identity.RoleManager` |
| `SignInManager<TUser>` | `identity.SignInManager` |
| `IUserStore` / `IRoleStore` | `identity.UserStore` / `identity.RoleStore` |
| `IPasswordHasher` (PBKDF2 v3) | `identity.PasswordHasher` (same wire format) |
| `IdentityOptions` | `identity.Options` |
| `[Authorize]` / `[Authorize(Roles=)]` | `auth.RequireAuth` / `auth.RequireRole` |

The default password hasher uses the **same v3 byte format as .NET**
(`0x01` marker, PRF/iterations/salt-length header, PBKDF2-HMAC-SHA256), so hashes
are interoperable for migrations.

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
go run ./examples/httpserver
```

## Layout

```
identity/          core: entities, managers, hasher, options, JWT
  entities.go      User/Role/Claim and the AspNet*-equivalent tables
  user_manager.go  UserManager (create, password, roles, claims, lockout)
  role_manager.go  RoleManager
  signin_manager.go SignInManager (+ SignInResult)
  hasher.go        PBKDF2 v3 password hasher (.NET-compatible)
  token_service.go JWT access/refresh issuance + validation
  store.go         UserStore / RoleStore interfaces
auth/              HTTP middleware: Bearer + cookie, RequireAuth/RequireRole/RequirePolicy
stores/gormstore/  GORM implementation (Postgres / MySQL / SQLite)
stores/pgxstore/   raw pgx implementation (PostgreSQL, hand-written SQL)
stores/pgxsqlc/    sqlc-generated pgx implementation (PostgreSQL)
stores/memstore/   in-memory implementation (tests / prototyping)
examples/httpserver minimal register/login/me/admin server (SQLite)
demo/postgres/     full PostgreSQL demo (docker-compose + 2FA + refresh)
```

## Extending the user

Four ways, smallest blast radius first (full analysis in
[docs/design/extending-user-and-migrations.md](docs/design/extending-user-and-migrations.md)):

```go
// Option D — custom typed columns on the user row (the .NET subclassing analog).
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

See [examples/genericuser](examples/genericuser) (Option D) and
[examples/customfields](examples/customfields) (Options A & B).

## Migrations

```go
// No CLI: apply the canonical schema from Go.
migrations.ApplyPostgres(ctx, sqlDB)
```

For versioned, reviewable history use **Atlas** (`atlas.hcl` + [migrations/](migrations)):
`atlas migrate diff <name> --env local` generates SQL from schema changes — the
EF `add-migration` loop. goose / golang-migrate can run the same SQL.

## Demos

- [`demo/postgres`](demo/postgres) — full flow against a real PostgreSQL via the
  raw `pgx` store: `docker compose up -d && go run .` then follow its README
  (register, login, JWT + cookie, refresh, role-gated route, TOTP 2FA).
- [`examples/httpserver`](examples/httpserver) — minimal zero-setup server on
  SQLite: `go run ./examples/httpserver`.

## Features

- [x] User/role management (`UserManager`, `RoleManager`, `SignInManager`)
- [x] PBKDF2 password hashing, **.NET v3-compatible** wire format
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
