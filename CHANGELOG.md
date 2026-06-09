# Changelog

Notable changes per release. Versions follow [SemVer](https://semver.org). This
is a multi-module repo; all modules (`.`, `stores/gormstore`, `stores/pgxstore`,
`stores/pgxsqlc`) share the same version tag.

## v0.3.1

Hardening pass (post-v0.3.0 double-check).

### Fixed
- **SMS code brute-force**: `VerifyPhoneToken` and `ChangePhoneNumber` now cap
  wrong guesses per issued code (`PhoneTokenMaxAttempts`, default 5) and
  invalidate the code once exceeded, so the 6-digit space can't be guessed
  within the validity window. The stored token format gained an attempt counter
  (internal/ephemeral — no migration).
- Added the missing compile-time interface assertion that the generic GORM store
  (`GenericUserStore[T,PT]`) satisfies `UserStore`/`UserLister`, so a future
  interface method is caught on the generic path too.

### Docs
- `RemovePassword` now documents that the caller must ensure another sign-in
  method exists (removing the only credential leaves the account
  unauthenticatable).

## v0.3.0

Feature parity pass against the reference identity framework (ASP.NET Core
Identity): management queries, account lifecycle, and pluggable two-factor.

### Added
- **Reverse queries**: `UserManager.GetUsersInRole` and `GetUsersForClaim`
  (backed by new `UserRoleStore`/`UserClaimStore` methods, implemented in all
  four stores).
- **Password lifecycle**: `AddPassword`, `RemovePassword`, `HasPassword` for the
  external-login → local-password flow.
- **Account setters**: `SetUserName`, `SetEmail` (admin path) and a full phone
  change flow — `SetPhoneNumber`, `GenerateChangePhoneNumberToken` /
  `SendChangePhoneNumberToken`, `ChangePhoneNumber`, `GetPhoneNumberConfirmed`
  (the change token is bound to the new number).
- **Sessions**: `SignInManager.ValidateSecurityStamp` / `RefreshSignIn`,
  `UserManager.UpdateSecurityStamp` (sign-out-everywhere) and `GetSecurityStamp`.
- **Remember this machine**: `GenerateTwoFactorRememberToken` /
  `VerifyTwoFactorRememberToken` and `SignInManager.PasswordSignInRemembering` /
  `IsTwoFactorClientRemembered` (stamp-bound, long-lived).
- **Pluggable two-factor**: `TwoFactorTokenProvider` interface +
  `RegisterTwoFactorProvider`, `GenerateUserToken`, `VerifyUserToken`,
  `GetValidTwoFactorProviders` (built-in Authenticator/Phone providers).
- **Claims**: `ReplaceClaim` on both `UserManager` and `RoleManager`.
- **Email delivery**: `EmailSender` interface (+ `EmailSenderFunc`),
  `WithEmailSender`, and `SendEmailConfirmation` / `SendPasswordReset` helpers,
  symmetric to `SMSSender`.

### Fixed
- **`UserOptions.AllowedUserNameCharacters` is now enforced** on user creation
  and `SetUserName` (previously configured but ignored). New `ErrInvalidUserName`;
  `ValidateUserName` is exported.
- **`PasswordOptions.RequiredUniqueChars` is now enforced** in `ValidatePassword`
  (previously a no-op). New `ErrPasswordRequiresUniqueChars`.

### Notes
- **Backward compatible** for callers of the built-in managers. Custom
  `UserStore` implementers must add `GetUsersInRole` / `GetUsersForClaim` (the
  compile-time interface assertions flag any gap).

## v0.2.1

### Added
- `UserManager.Delete` and `RoleManager.Update` — the manager layer now exposes
  user deletion and role rename (the latter under optimistic concurrency).
- `identity.Naming.Validate` (and `ErrInvalidIdentifier`): stores reject schema
  or table names that are not safe SQL identifiers before running migrations,
  hardening the configurable-schema feature against injection.

### Changed / Fixed
- **Cascade delete parity**: deleting a user now removes its roles, claims,
  logins and tokens in **every** store — Postgres via `ON DELETE CASCADE`
  (added to `pgxsqlc` too), GORM and in-memory via a single transaction.
- **Role optimistic concurrency** is now enforced in all four stores
  (`memstore`, `gormstore`, `pgxstore`, `pgxsqlc`): a stale `RoleStore.Update`
  returns `ErrConcurrencyFailure`, mirroring user updates.
- `ChangeEmail` re-checks `RequireUniqueEmail` at apply time, so a previously
  minted token can no longer collide two accounts on one address.
- `RedeemRecoveryCode` uses a constant-time comparison.

## v0.2.0

### Added
- **Configurable physical schema** per store — `WithSchema`, `WithTablePrefix`
  and `WithTableNames` on the GORM and pgx stores (including the generic store).
  All SQL (and joins) is built from a single `identity.Naming`, so renaming a
  table, adding a prefix, or moving everything into a schema stays consistent.
- **Referential integrity**: `pgxstore.Migrate` now generates `ON DELETE CASCADE`
  foreign keys from the satellite tables to users/roles, so deleting a user or
  role cleans up its memberships, claims, logins and tokens.
- `docs/customizing-schema.md` documenting the five levels of customization.

### Notes
- **Backward compatible** — defaults are the canonical `identity_*` tables;
  existing `NewUserStore(db)` / `Migrate(...)` calls are unchanged.
- The sqlc store keeps a fixed canonical schema (compile-time SQL); use a
  connection `search_path` for a custom namespace.

## v0.1.0

Initial public release.

- Managers: `UserManager` / `RoleManager` / `SignInManager`, with the generic
  `UserManagerOf[T]` for custom user columns (back-compat aliases).
- Passwords: PBKDF2-HMAC-SHA256 in a versioned format with transparent rehash.
- JWT: access + refresh; HS256, RS256 and ES256 via pluggable signers with `kid`
  rotation; JWKS endpoint.
- Two-factor: TOTP (RFC 6238) + one-time recovery codes; SMS via a pluggable sender.
- Email-confirmation / password-reset token providers, external (OAuth/OIDC)
  logins, account lockout, claims/policy authorization, optimistic concurrency,
  and paged listing.
- Pluggable stores behind segregated interfaces: GORM (Postgres/MySQL/SQLite),
  raw pgx, sqlc-generated pgx, and in-memory.
- Dependency-light core with per-store submodules. Apache-2.0.
