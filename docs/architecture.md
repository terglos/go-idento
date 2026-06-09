# Architecture

go-identity reproduces the three-layer design of ASP.NET Core Identity in Go.

```
Managers (business logic)   UserManager · RoleManager · SignInManager · TokenService
        │ depend on
Stores (interfaces)         UserStore[T,PT] · RoleStore        (no DB driver here)
        │ implemented by
Persistence                 gormstore · pgxstore · memstore
```

The managers never import a database driver — they talk to the store interfaces.
Swapping persistence (or testing) is just passing a different store.

## Layers & types

| Concern | Type | .NET analog |
|---|---|---|
| User entity | `identity.User` (+ `Role`, `Claim`, join tables) | `IdentityUser` / `AspNet*` |
| User business API | `UserManagerOf[T,PT]` (alias `UserManager`) | `UserManager<TUser>` |
| Role business API | `RoleManager` | `RoleManager<TRole>` |
| Sign-in orchestration | `SignInManagerOf[T,PT]` (alias `SignInManager`) | `SignInManager<TUser>` |
| Tokens (JWT) | `TokenServiceOf[T,PT]` (alias `TokenService`) | `JwtBearer` (external in .NET) |
| Persistence contract | `UserStore[T,PT]`, `RoleStore` | `IUserStore`, `IRoleStore` |
| Password hashing | `PasswordHasher` (PBKDF2 v3) | `IPasswordHasher` |
| JWT signing | `Signer` (`HMAC` HS256, `RSAKeyring` RS256, `ECDSAKeyring` ES256) | token signing key set |
| Public key publishing | `JWKSProvider` + `auth.JWKSHandler` | JWKS endpoint |
| SMS two-factor | `SMSSender` + phone token helpers | `PhoneNumberTokenProvider` |
| Reset/confirm tokens | `DataTokenProvider` | `DataProtectorTokenProvider` |
| Policy authz | `auth.Policy` + `RequirePolicy` | `AuthorizationPolicy` |
| Options | `identity.Options` | `IdentityOptions` |

## The generics model (extending the user)

`User` exposes `Base() *User`, declared by the `UserModel` interface. A custom
type **embeds** `identity.User`, so Go method promotion gives it `Base()` (and
`TableName()`) for free:

```go
type AppUser struct {
    identity.User      // promotes Base() and TableName()
    TenantID string
}
```

Managers are generic over `T` and its pointer `PT` (`PT interface { *T; UserModel }`),
the standard Go pattern for "construct a new `T`" inside a generic store while
requiring the identity fields. Internally managers read/write base fields through
`u.Base()`; the store persists the *whole* `T`, so custom columns live on the
user row — the Go equivalent of subclassing `IdentityUser`.

Backward compatibility is preserved with type aliases:

```go
type UserManager   = UserManagerOf[User, *User]
type SignInManager = SignInManagerOf[User, *User]
type TokenService  = TokenServiceOf[User, *User]
type DefaultUserStore = UserStore[User, *User]
```

The concrete constructors (`NewUserManager`, …) return these aliases, so code
that predates generics compiles unchanged. The three bundled stores satisfy
`DefaultUserStore`; custom types use `gormstore.NewUserStoreOf[T]`.

## Sign-in & token flow

```
PasswordSignIn(name, pw)
  ├─ FindByName(normalized)          (generic failure if absent — no enumeration)
  ├─ IsLockedOut?  → IsLockedOut
  ├─ CanSignIn?    → IsNotAllowed (email/phone confirmation)
  ├─ CheckPassword (rehash if params outdated)
  │     ├─ TwoFactorEnabled → RequiresTwoFactor
  │     └─ else → Succeeded
  └─ on failure: AccessFailed (+lockout after N)

IssuePair(user) → access JWT (sub, name, email, roles, custom claims,
                  SecurityStamp) + opaque refresh token (stored hashed)
ValidateAccessToken → verify signature + issuer/audience, reload user,
                  compare SecurityStamp (revocation), return user + claims
Refresh → verify stored hash, rotate (new pair, old refresh invalidated)
```

## Security properties

- **Revocation via security stamp.** Any credential change rotates
  `SecurityStamp`; it's embedded in every JWT and re-checked on validation, so
  outstanding access tokens are invalidated. Refresh tokens are stored hashed.
- **Password hashing.** PBKDF2-HMAC-SHA256, 100k iterations, 128-bit salt,
  256-bit subkey, encoded in the **.NET Identity v3 format** (marker `0x01` +
  PRF/iteration/salt-length header) — hashes interoperate with .NET. Outdated
  parameters trigger a transparent rehash on next successful login.
- **TOTP** is RFC 6238 (HMAC-SHA1, 30s, ±1 step); recovery codes are one-time
  and stored hashed.
- **Reset/confirm tokens** are HMAC over `userID|purpose|securityStamp` with an
  expiry, so they're purpose-bound, time-limited and single-use (consuming one
  rotates the stamp, invalidating the rest).
- **Constant-time comparisons** for password subkeys, TOTP codes and token MACs.

## HTTP layer (`auth`)

`auth.Middleware(tokens, cookies)` authenticates each request (Bearer token,
falling back to an HttpOnly cookie), building a `Principal` (user + claims +
roles) in the request context. Authorization is composed on top:
`RequireAuth` (401 if anonymous), `RequireRole` and `RequirePolicy` (403 if the
policy fails) — the analogs of `[Authorize]`, `[Authorize(Roles=)]` and
`[Authorize(Policy=)]`.

## Stores

All three implement the same interfaces; pick by need:

- **gormstore** — Postgres/MySQL/SQLite from one codebase (closest to EF Core).
  `generic.go` adds `NewUserStoreOf[T]` / `MigrateOf[T]` for custom user types.
- **pgxstore** — raw `pgx` for PostgreSQL; hand-written SQL with an embedded
  `schema.sql`. `attributes` is `jsonb`. Concrete to `*User`.
- **pgxsqlc** — PostgreSQL with a **sqlc-generated** query layer (compile-time
  checked SQL); same schema, an adapter maps the generated types to the store
  interfaces. Regenerate with `sqlc generate`.
- **memstore** — in-memory, concurrency-safe; for unit tests and prototyping.

See [extending-user-and-migrations.md](design/extending-user-and-migrations.md)
for the persistence/migration trade-offs.
