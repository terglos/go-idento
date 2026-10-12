# Changelog

Notable changes per release. Versions follow [SemVer](https://semver.org). This
is a multi-module repo; all modules (`.`, `stores/gormstore`, `stores/pgxstore`,
`stores/pgxsqlc`) share the same version tag.

## v0.8.0

`private_key_jwt` client authentication (RFC 7523 §2.2) for Client ID Metadata
Document clients. ChatGPT identifies itself with
`https://chatgpt.com/oauth/client.json`, which declares
`token_endpoint_auth_method: "private_key_jwt"` (RS256, `jwks_uri`); v0.7.0
refused it at `/oauth/authorize` ("only none"), so ChatGPT had to fall back to
DCR. The CIMD draft only forbids shared-secret methods, and §8.2 requires the
server to enforce RFC 7523 authentication in this case.

### Added
- CIMD documents may declare `private_key_jwt` with `jwks_uri` (https; fetched
  with the document's SSRF protections, 64 KB cap, cached per `Cache-Control`,
  re-fetched on an unknown `kid` for key rotation, at most every
  `CIMDFetcher.JWKSMinRefresh`) or inline `jwks`; an optional
  `token_endpoint_auth_signing_alg` pins the algorithm.
- Token and revocation endpoints accept `client_assertion` /
  `client_assertion_type` and **require** them for such clients. Checks:
  RS256/ES256 (`oauth.AssertionSigningAlgs`) with the client's keys (RSA ≥ 2048,
  EC P-256); `iss` = `sub` = `client_id`; `aud` = issuer or token endpoint (or
  the revocation endpoint there); `exp` required and at most
  `Options.ClientAssertionMaxLifetime` ahead (default 1 h); `iat`/`nbf` not in
  the future; `jti` required and accepted once. Failures are `401
  invalid_client` with a specific description.
- **Replay protection shared by all instances**: used `jti`s are recorded in the
  store until the assertion expires (`oauth.ClientAssertion`, new table
  `identity_oauth_assertions`, `TableNames.OAuthAssertions`); `PurgeExpired`
  also removes expired ids.
- Metadata advertises `private_key_jwt` in
  `token_endpoint_auth_methods_supported` /
  `revocation_endpoint_auth_methods_supported` and
  `token_endpoint_auth_signing_alg_values_supported` /
  `revocation_endpoint_auth_signing_alg_values_supported` when `AllowCIMD` is on.
- `oauthtest.RunEndToEnd`: CIMD client with `jwks_uri` + RS256 (the ChatGPT
  shape) through authorize → code → refresh → key rotation → revoke, every
  rejection case (no assertion, wrong `aud`, expired, `iss` ≠ `sub`, overlong
  `exp`, missing `jti`, future `iat`, unknown key, undeclared algorithm,
  `alg: none`, replay, `client_id` mismatch, mixed methods), and inline `jwks` +
  ES256. `RunStoreConformance`: assertion-id storage, including concurrent use.

### Changed
- **`oauth.Store` gained `UseClientAssertion` and
  `DeleteExpiredClientAssertions`** (implemented by all four bundled stores).
  Custom stores must add them; `RunStoreConformance` covers the contract.
- CIMD documents declaring `client_secret_jwt` are now refused with an explicit
  shared-secret message, like `client_secret_basic`/`_post`.

### Schema
- New table `identity_oauth_assertions` (`client_id`, `jti`, `expires_at`;
  PK `(client_id, jti)`, indexed `expires_at`) in every store's `Migrate`, the
  canonical `identity/migrations/postgres.sql`, and
  `migrations/20261012000001_oauth_client_assertions.sql`. Apps that pass a
  hand-built `TableNames` must set `OAuthAssertions` (start from
  `DefaultTableNames()`).

## v0.7.0

Embedded **OAuth 2.1 authorization server** (new package `oauth`) so apps can
expose their API to MCP connectors (Claude, ChatGPT) and other third-party
clients with per-user, audience-bound tokens — the profile required by the MCP
authorization spec. Guide: [docs/oauth-server.md](docs/oauth-server.md).

### Added
- **`oauth.NewServer(users, tokens, store, Options)`** (validates config) with
  `Routes(mux)`:
  - authorization code + **PKCE S256 only**; RFC 9207 `iss` in the response;
    duplicated parameters rejected; app-owned login (`CurrentUser`, `LoginURL`)
    and consent (`RenderConsent`, default page included) with HMAC CSRF and
    remembered per-client consent;
  - token endpoint: code exchange and **refresh rotation with reuse detection**
    (replay revokes the grant; optional `RefreshReuseGrace`); every failure is
    `invalid_grant`; `RequireOfflineAccess` option; confidential and public
    clients;
  - **RFC 8414** metadata (incl. issuer-path form), **RFC 7009** revocation,
    **RFC 7591** DCR (rate-limited per IP), **CIMD** URL client_ids
    (dial-time private-IP blocking, no redirects, size/time limits, bounded
    cache), **RFC 8252** loopback redirects on any port;
  - CORS on metadata/token/register/revoke for browser clients.
- **Access tokens**: `typ: at+jwt` JWTs signed by the existing `TokenService`
  signer (JWKS unchanged), `aud` = **RFC 8707** resource, carrying `client_id`,
  `scope`, `gid` (grant) and `idn_sstamp`. `ValidateResourceToken` also checks
  the grant still exists (immediate revocation), security stamp and lockout.
- **Resource side**: `ProtectedResourceHandler` / `ResourceMetadataURL` /
  `ResourceMetadataPath` (**RFC 9728**), `Challenge` (401 +
  `WWW-Authenticate: Bearer resource_metadata=…, scope=…`), `InsufficientScope`
  (403 step-up), `RequireScopes`.
- **`auth.WithOAuthResource(server, resource)`**: the middleware accepts OAuth
  tokens (Bearer only) with precedence session → OAuth → API key;
  `Principal` gains `ViaOAuth` and `ClientID` (scopes in `Scopes`).
- Connected apps: `ListGrants`, `RevokeGrant`, `RevokeClient`; GC:
  `PurgeExpired` (codes + grants), `PurgeStaleClients` (unused DCR clients).
- `oauth.Store` implemented in all four stores (`memstore.Store.OAuth()`,
  `gormstore`/`pgxstore`/`pgxsqlc` `NewOAuthStore`); codes, consents and grants
  cascade on user delete.
- **`oauth/oauthtest`**: exported store-conformance and end-to-end suites.
- **`demo/mcpoauth`**: runnable MCP server with lazy auth (public + protected
  tool).

### Changed
- `TokenService.ValidateAccessToken` rejects `typ: at+jwt` tokens, so OAuth
  access tokens can never be used as app session tokens.
- `TokenOptions.ResolvedSigner()` exposes the effective signer.
- Store modules: `golang.org/x/text` → v0.43.0 (GO-2026-5970, reachable via
  gorm), `golang.org/x/sync` → v0.24.0.

### Fixed
- Includes the pgxstore fix released as `stores/pgxstore/v0.6.1`: jsonb
  parameters are passed as string, so user creation and API keys work behind
  transaction-pooling proxies (PgBouncer; `QueryExecModeExec` /
  `QueryExecModeSimpleProtocol`). The OAuth store is also tested in both modes.
- The pgxstore exec-mode test closed its pool before its cleanups ran, leaving
  rows behind and failing on the next run.

### Schema
- New tables `identity_oauth_clients`, `identity_oauth_codes`,
  `identity_oauth_consents`, `identity_oauth_grants` (`TableNames.OAuth*`,
  honoring `WithSchema`/`WithTablePrefix`/`WithTableNames`) in every store's
  `Migrate`, the canonical `identity/migrations/postgres.sql`, and a versioned
  migration (`migrations/20261011000001_oauth_server.sql`).

## v0.6.0

Multi-session refresh tokens — fixes the single-slot model that silently forced
one session per account (a second login from another device/tab killed the
previous session's refresh token). One row per session, the industry model
(Duende PersistedGrants / OpenIddict tokens / the standard ASP.NET pattern).

### Added
- **`identity.RefreshToken`** entity (own `identity_refresh_tokens` table:
  `session_id` PK, unique `token_hash`, FK `ON DELETE CASCADE`, indexed
  `user_id`/`expires_at`), honoring `WithSchema`/`WithTablePrefix`/
  `WithTableNames` (`TableNames.RefreshTokens`).
- **`TokenService.WithSessionStore(store)`** enables multi-session: each
  `IssuePair` creates its own session; the opaque token becomes
  `<sessionID>.<secret>` (only the secret's hash is stored); `Refresh` rotates
  within the token's own session (constant-time compare, per-session sliding
  TTL) so other devices/tabs are untouched.
- **`RevokeSession(ctx, u, refreshToken)`** — sign out one device;
  **`Revoke(ctx, u)`** now ends every session; **`ListSessions(ctx, u)`** for a
  "connected devices" panel. Opportunistic GC sweeps expired sessions on issue.
- **`TokenOptions.MaxSessions`** (0 = unlimited): cap concurrent sessions with
  oldest-evicted; `MaxSessions: 1` reproduces the previous single-session
  behavior for those who want it.
- `RefreshTokenStore` implemented in all four stores; sessions cascade when the
  user is deleted/purged.

### Compatibility
- `IssuePair`/`Refresh` signatures unchanged; **without** `WithSessionStore`
  the legacy single-slot behavior is untouched. Legacy tokens (no session id)
  keep redeeming after enabling the store and are migrated to their own session
  on first rotation.

### Schema
- New `identity_refresh_tokens` table in the pgx stores' `Migrate`, the
  canonical `identity/migrations/postgres.sql`, and a versioned migration
  (`migrations/20260617000001_refresh_sessions.sql`).

## v0.5.0

First-class opaque API keys — long-lived machine-to-machine credentials for
callers that can't do interactive login or token rotation (POS terminals,
payment partners, webhooks). Requested for using go-idento as the single
identity base of a payments platform.

### Added
- **`identity.APIKey`** entity (own `identity_api_keys` table, FK `ON DELETE
  CASCADE` to users, unique `key_hash`, indexed `user_id`), honoring the existing
  `WithSchema`/`WithTablePrefix`/`WithTableNames` config (`TableNames.APIKeys`).
- **`identity.APIKeyManager`** (`APIKeyManagerOf[T,PT]`):
  - `CreateAPIKey(ctx, user, opts)` — returns the plaintext secret ONCE; stores
    only its hash + a display `Prefix`. `APIKeyOptions{Name, ExpiresAt, Scopes}`
    (`ExpiresAt` nil = never expires).
  - `VerifyAPIKey(ctx, plaintext)` — resolves the owning user (roles/claims
    apply) with constant-time hash lookup; returns `ErrInvalidAPIKey` for an
    unknown/revoked/expired key or locked-out owner (→ 401) and a wrapped store
    error for infra failure (→ 503), so the two are distinguishable.
  - `RevokeAPIKey`, `ListAPIKeys`, and `ImportAPIKey(...)` to insert a
    **precomputed hash** — point the hasher at an existing scheme and keep
    already-issued keys valid with zero reissue.
  - Configurable `WithAPIKeyHasher` (default **SHA-256**, not PBKDF2 — keys are
    high-entropy) and `WithAPIKeyPrefix`.
- **`APIKeyStore`** capability implemented in all four stores (memstore,
  gormstore, pgxstore, pgxsqlc); keys cascade when the owner is deleted/purged.
- **`auth.WithAPIKeys(keyManager)`** middleware option: a Bearer value that isn't
  a valid JWT is tried as an API key, producing the same `Principal` so
  `RequireRole`/`RequirePolicy` work identically. `Principal.Scopes` +
  `HasScope`, `Principal.ViaAPIKey`.

### Schema
- New `identity_api_keys` table in the pgx stores' `Migrate`, the canonical
  `identity/migrations/postgres.sql`, and a versioned migration
  (`migrations/20260614000001_api_keys.sql`). Independent of the
  password/security-stamp lifecycle — a password change does not invalidate keys.

## v0.4.0

First-class guest (anonymous) identity — from production feedback that
synthesizing throwaway users left orphan rows with no cleanup.

### Added
- **`User.IsAnonymous`** column (indexed) marking a guest account.
- **`UserManager.CreateAnonymous(ctx)`** — creates a credential-less guest with a
  generated unique name; issue a JWT for it like any user.
- **`UserManager.ConvertToRegistered(ctx, u, userName, email, password)`** —
  promotes a guest to a full account **in place, preserving the user ID**, so
  roles/claims/data keyed on it carry over. Returns `ErrNotAnonymous` otherwise.
- **`UserManager.PurgeAnonymousUsers(ctx, olderThan)`** — GC sweep that
  bulk-deletes stale guests and cascades their satellite rows; returns the count.
  Backed by the optional `AnonymousPurger` store capability (`ErrPurgeNotSupported`
  if a store doesn't implement it), available on all four bundled stores.
- `UserManager.IsAnonymous(u)` helper.

### Schema
- New `is_anonymous` column + partial GC index (`… (created_at) WHERE
  is_anonymous`) in the pgx stores' `Migrate`, the canonical
  `identity/migrations/postgres.sql`, and a versioned migration
  (`migrations/20260609000002_guest_identity.sql`). Additive and
  backward-compatible (existing rows default to false); GORM `AutoMigrate` adds
  the column automatically.

## v0.3.5

Toolchain + robustness pass (fifth double-check; signers/middleware re-read,
example smoke-tested end to end).

### Fixed
- **Pinned `toolchain go1.26.4`** in every module (and `go.work`): builds pick
  up the patched standard library — `govulncheck` is now clean across all four
  modules (was flagging GO-2026-5037/5039/4971 in the 1.26.2 stdlib).
- **`RefreshTokenTTL` zero-value footgun**: a manually-constructed
  `TokenOptions` without the field no longer yields instantly-expired refresh
  tokens — an unset TTL falls back to 7 days (mirrors `NewDataTokenProvider`).

### Improved
- The `httpserver` example accepts a `PORT` env var (was hard-coded :8080) and
  was smoke-tested end to end: register → login → `/me` (401 anonymous / 200
  authenticated) → `/admin` (403 without the role).

### Docs
- `SECURITY.md` notes the SMS-code attempt-counter race (same class as the
  recovery-code one); the cascade-FKs migration documents that databases
  created by the pgx stores' `Migrate` already carry the FKs (skip it there).

## v0.3.4

Token-lifetime and schema-source hardening (fourth double-check).

### Fixed (security)
- **`RefreshTokenTTL` is now actually enforced.** Refresh tokens were stored as
  a bare hash with no expiry, so `Refresh` accepted a stolen token forever;
  `RefreshTokenTTL` was dead configuration. The stored value now carries a
  server-side expiry stamped at issuance and re-stamped on each rotation
  (sliding window); `Refresh` rejects expired tokens.
  **Upgrade note:** refresh tokens issued before v0.3.4 are rejected (fail
  closed) — users simply sign in again once.
- **Canonical schema and Atlas baseline gained the cascade FKs** they had been
  missing since v0.2.0: `identity/migrations/postgres.sql` now declares
  `ON DELETE CASCADE` on all satellite tables (matching the pgx stores), and a
  new versioned migration (`migrations/20260609000001_cascade_fks.sql`) upgrades
  existing databases — cleaning orphan rows first, then adding the constraints.

### Docs
- `SECURITY.md` documents two known limitations: TOTP replay inside the 30 s
  step (standard practice) and the theoretical recovery-code double-redeem race
  under perfectly concurrent requests.

## v0.3.3

Store behavioral-parity pass (third double-check): the same manager call now
behaves identically on every store, and the contract is documented on the
store interfaces and pinned by tests.

### Fixed
- **`AddToRole` with a missing role** now returns `ErrRoleNotFound` on every
  store. Before: pgxstore **silently succeeded** (the `INSERT..SELECT` matched
  no role and `ON CONFLICT` hid it), and gorm/sqlc returned the wrong sentinel
  (`ErrNotFound`).
- **`RemoveFromRole` with a missing role** is now a no-op on every store
  (gorm/sqlc previously errored; mem/pgx already no-op'ed).
- **`FindByEmail("")`** now returns `ErrNotFound` on the SQL stores instead of
  potentially matching an arbitrary user created without an email (memstore
  already guarded).
- **`memstore.AddLogin`** no longer silently re-binds an existing
  (provider, key) to another user; it returns the new `ErrLoginAlreadyUsed`
  (SQL stores already rejected via unique constraint).

### Docs
- The cross-store contract is documented on `UserCrudStore`/`UserRoleStore`/
  `UserLoginStore`; README quick start is now self-contained (defines
  `ctx`/`secret`).

## v0.3.2

Hardening pass (second double-check; core crypto/token review).

### Fixed
- **PBKDF2 algorithmic-DoS guard**: `Verify` now bounds the iteration count
  embedded in a stored hash (`1 .. 10_000_000`); a crafted hash can no longer
  force an unbounded-work derivation. Fails closed.
- **Constant-time refresh-token check**: `TokenService.Refresh` compares the
  stored refresh-token hash with `crypto/subtle.ConstantTimeCompare` (consistent
  with password/2FA/recovery-code comparisons).

### Docs
- `SECURITY.md` documents caller responsibilities: CSRF on cookie-authenticated
  state-changing endpoints, and verifying the OAuth/OIDC token before calling
  `ExternalLoginSignIn`. The same contract is noted on the `ExternalLoginSignIn`
  doc comment.

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
