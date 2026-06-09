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
