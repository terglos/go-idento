# Changelog

Notable changes per release. Versions follow [SemVer](https://semver.org). This
is a multi-module repo; all modules (`.`, `stores/gormstore`, `stores/pgxstore`,
`stores/pgxsqlc`) share the same version tag.

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
