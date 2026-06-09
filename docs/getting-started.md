# Getting started

## Install

```bash
go get github.com/terglos/go-idento
```

You also need a store. The examples use the GORM store with a pure-Go SQLite
driver (no CGO):

```bash
go get gorm.io/gorm github.com/glebarez/sqlite
```

## Wire it up

```go
package main

import (
    "context"
    "time"

    "github.com/glebarez/sqlite"
    "github.com/terglos/go-idento/identity"
    "github.com/terglos/go-idento/stores/gormstore"
    "gorm.io/gorm"
)

func main() {
    ctx := context.Background()

    db, _ := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
    gormstore.Migrate(db) // dev/test; use migrations/Atlas in production

    users := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions()).
        WithTokenProvider(identity.NewDataTokenProvider([]byte("change-me-token-secret"), time.Hour))
    roles := identity.NewRoleManager(gormstore.NewRoleStore(db))
    signIn := identity.NewSignInManager(users)
    tokens := identity.NewTokenService(users,
        identity.DefaultTokenOptions([]byte("change-me-32-byte-jwt-secret-min!"), "my-app", "api"))

    _ = roles.Create(ctx, &identity.Role{Name: "Admin"})

    u := &identity.User{UserName: "jane", Email: "jane@example.com"}
    _ = users.CreateWithPassword(ctx, u, "Abcdef1!")
    _ = users.AddToRole(ctx, u, "Admin")

    if res, signed := signIn.PasswordSignIn(ctx, "jane", "Abcdef1!", true); res.Succeeded {
        pair, _ := tokens.IssuePair(ctx, signed) // access + refresh token
        _ = pair
    }
}
```

## Protect HTTP routes

```go
import "github.com/terglos/go-idento/auth"

mux := http.NewServeMux()
mux.Handle("GET /me",    auth.RequireAuth(meHandler))
mux.Handle("GET /admin", auth.RequireRole("Admin")(adminHandler))

// policy-based, beyond roles:
policy := auth.NewPolicy("EngOnly").RequireClaim("department", "eng")
mux.Handle("GET /eng", auth.RequirePolicy(policy)(engHandler))

cookies := auth.DefaultCookieAuth()
handler := auth.Middleware(tokens, cookies)(mux) // Bearer + cookie auth

// inside a handler:
p, _ := auth.PrincipalFrom(r.Context()) // p.User, p.Roles, p.Claims
```

## Common flows

```go
// Email confirmation & password reset (needs WithTokenProvider)
tok := users.GenerateEmailConfirmationToken(u); users.ConfirmEmail(ctx, u, tok)
rt  := users.GeneratePasswordResetToken(u);     users.ResetPassword(ctx, u, rt, "Newpass1!")

// Two-factor (TOTP) + recovery codes
key, _ := users.GetAuthenticatorKey(ctx, u)     // show identity.AuthenticatorURI(...) as a QR
users.SetTwoFactorEnabled(ctx, u, true)
codes, _ := users.GenerateRecoveryCodes(ctx, u, 10)
// login then: signIn.TwoFactorAuthenticatorSignIn(ctx, u, totpCode)

// External / OAuth login
users.AddLogin(ctx, u, identity.UserLoginInfo{LoginProvider: "GitHub", ProviderKey: "gh-123"})
res, u := signIn.ExternalLoginSignIn(ctx, "GitHub", "gh-123")

// Refresh / revoke
pair, _ := tokens.Refresh(ctx, u, oldRefreshToken) // rotates
tokens.Revoke(ctx, u)
```

## RS256 with key rotation

```go
ring := identity.NewRSAKeyring("key-1", privKey)
tokens := identity.NewTokenService(users, identity.TokenOptions{
    Signer: ring, Issuer: "my-app", Audience: "api",
    AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 7 * 24 * time.Hour,
})
ring.Add("key-2", newKey, true) // new tokens use key-2; key-1 tokens still verify
ring.Remove("key-1")            // retire once no live tokens reference it
```

## Custom user columns

See [extending the user](design/extending-user-and-migrations.md). Quickest typed
option (Option D):

```go
type AppUser struct {
    identity.User
    TenantID string
}
gormstore.MigrateOf[AppUser](db)
store := gormstore.NewUserStoreOf[AppUser](db)
users := identity.NewUserManagerOf[AppUser](store, identity.DefaultOptions())
users.CreateWithPassword(ctx, &AppUser{User: identity.User{UserName: "x"}, TenantID: "acme"}, "Abcdef1!")
```

## Production migrations

```go
// no CLI: apply the canonical schema
migrations.ApplyPostgres(ctx, sqlDB)
```

Or versioned with Atlas (`atlas.hcl`): `atlas migrate diff <name> --env local`.
See [migrations/README.md](../migrations/README.md).

## Next steps

- Full PostgreSQL demo: [demo/postgres](../demo/postgres).
- Architecture & security details: [architecture.md](architecture.md).
