# Security Policy

go-idento is an authentication/identity library, so security reports are taken
seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, use
GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.

We aim to acknowledge reports within a few business days and to ship a fix or
mitigation as quickly as is practical.

## Scope & notes

- Password hashing uses PBKDF2-HMAC-SHA256 with a versioned encoding; the
  version byte allows parameters to be raised over time, and outdated hashes are
  rehashed transparently on the next successful sign-in.
- Refresh tokens and 2FA recovery codes are stored hashed at rest.
- Access tokens embed a security stamp; rotating it (password/2FA/email change)
  revokes outstanding tokens.
- SMS verification codes cap wrong guesses per issued code
  (`PhoneTokenMaxAttempts`) and the embedded PBKDF2 iteration count is bounded on
  verify, so a crafted stored hash cannot force unbounded work.
- Refresh tokens are rotated on every use and carry a server-side expiry
  (`RefreshTokenTTL`, sliding on rotation), so a stolen, dormant token dies at
  the TTL.
- **OAuth authorization server** (`oauth`): PKCE S256 is mandatory; codes are
  single-use (a replay revokes the grant issued from it) and live 60 s; refresh
  tokens rotate on every use and a reused one revokes the whole grant (strict
  by default — `RefreshReuseGrace` is 0); access tokens are audience-bound
  `at+jwt` JWTs that are rejected once their grant is revoked, the user's
  security stamp changes or the user is locked out. Codes, refresh tokens and
  client secrets are stored hashed. Consent forms carry an HMAC CSRF token
  bound to the user and every request parameter; the default consent page
  denies framing.
- **CIMD fetches (SSRF).** URL client_ids are fetched over https only, without
  following redirects or using a proxy, with a 5 s timeout and 5 KB cap; every
  dialed address is checked against special-use ranges (loopback, private,
  link-local, CGNAT, multicast, …) *at connect time*, which also defeats DNS
  rebinding. `CIMDFetcher.AllowPrivateNetworks` disables this and is meant for
  tests only. A `jwks_uri` declared by a document goes through the same client
  (https only, no redirects, no proxy, dial-time IP checks; 64 KB cap).
- **`private_key_jwt` (CIMD clients).** A client whose metadata document
  declares it must authenticate every token/revocation request with an
  RFC 7523 assertion — PKCE alone is refused. Only RS256/ES256 with the
  client's published keys (RSA ≥ 2048, P-256) are accepted, never `none` or
  HMAC; `iss`/`sub`/`aud`/`exp`/`iat` are enforced, `exp` is capped
  (`ClientAssertionMaxLifetime`, default 1 h) and each `jti` is accepted once,
  recorded in the shared store so replays fail on every instance. The accepted
  `aud` values are the issuer and this server's own token (or revocation)
  endpoint URL.

## Known limitations

- **TOTP replay within the step.** A valid TOTP code is accepted more than once
  inside its 30-second step (±1 step skew). Used-code tracking is not
  implemented — consistent with common authenticator deployments; the window is
  ≤90 s.
- **Recovery-code redemption race.** Redeeming a recovery code is a
  read-modify-write on the user-token store without per-token optimistic
  concurrency, so two perfectly concurrent redemptions of the *same* code can
  both succeed. The window is microseconds and the code is still consumed;
  treat recovery codes as single-use-best-effort under extreme concurrency.
- **SMS-code attempt counter race.** The wrong-guess counter on a phone code is
  the same read-modify-write pattern, so perfectly concurrent wrong guesses can
  lose an increment (one extra guess before invalidation). The 5-minute expiry
  and the cap itself still bound the attack.
- Run `govulncheck ./...` to check for known issues in dependencies and the Go
  toolchain; build releases with a current, patched Go toolchain.

## Caller responsibilities

The library is unopinionated about transport; a few controls are yours to wire:

- **CSRF (cookie auth).** `auth.CookieAuth` sets `HttpOnly`, `Secure` and
  `SameSite=Lax` by default, which blocks cross-site requests for most flows. If
  you serve state-changing endpoints (POST/PUT/PATCH/DELETE) authenticated by
  cookie, still add CSRF tokens (e.g. `gorilla/csrf`) — the library does not add
  them for you. Pure `Authorization: Bearer` APIs are not CSRF-exposed.
- **External logins.** `ExternalLoginSignIn` / `AddLogin` trust the
  `loginProvider`/`providerKey` you pass as already-verified. Validate the
  OAuth/OIDC ID-token signature and `iss`/`aud`/`exp` against the provider first,
  and derive `providerKey` from the validated `sub` claim.
- **OAuth server deployment.** Serve the issuer over https; behind several
  instances set a stable `Options.CSRFKey` (the default is per-process); behind
  a proxy set `Options.ClientIP` so DCR rate limiting sees the real client IP;
  run `PurgeExpired` / `PurgeStaleClients` periodically; show the
  `ConsentRequest.ClientHost` (not just the self-asserted `ClientName`) on a
  custom consent page; and advertise only the scopes your API needs (consider
  `RequireOfflineAccess` to make long-lived access opt-in).
