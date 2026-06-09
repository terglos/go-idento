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
- Run `govulncheck ./...` to check for known issues in dependencies and the Go
  toolchain; build releases with a current, patched Go toolchain.
