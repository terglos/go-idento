# go-idento — PostgreSQL demo

A complete, runnable example of **go-idento** backed by **PostgreSQL** using
the raw `pgx` store. It demonstrates the full flow: registration, password
login (JWT + cookie), token refresh, protected and role-gated endpoints, and
TOTP two-factor with recovery codes.

## Run

```bash
# 1. start Postgres
docker compose up -d

# 2. start the API (uses DATABASE_URL or the default localhost DSN)
go run .
# postgres-demo listening on :8080
```

Override config via env vars: `DATABASE_URL`, `JWT_SECRET`, `TOKEN_SECRET`, `ADDR`.

## Endpoints

| Method & path        | Auth         | Purpose                                   |
|----------------------|--------------|-------------------------------------------|
| `POST /register`     | none         | Create a user                             |
| `POST /login`        | none         | Password login → JWT (+ 2FA if enabled)   |
| `POST /refresh`      | none         | Exchange a refresh token for a new pair   |
| `GET  /me`           | bearer/cookie| Current principal                         |
| `POST /promote`      | bearer/cookie| Add current user to the `Admin` role      |
| `GET  /admin`        | role: Admin  | Role-gated endpoint                       |
| `POST /2fa/setup`    | bearer/cookie| Get authenticator shared key + otpauth URI|
| `POST /2fa/enable`   | bearer/cookie| Verify a code, enable 2FA, get recovery codes |
| `POST /2fa/verify`   | none         | Complete a 2FA login with a code          |

## Walkthrough (curl)

```bash
# Register
curl -s localhost:8080/register \
  -d '{"userName":"jane","email":"jane@example.com","password":"Abcdef1!"}'

# Login -> copy accessToken / refreshToken / userId from the response
curl -s localhost:8080/login \
  -d '{"userName":"jane","password":"Abcdef1!"}'

TOKEN=<accessToken>

# Authenticated call
curl -s localhost:8080/me -H "Authorization: Bearer $TOKEN"

# Admin endpoint -> 403 until promoted
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/admin -H "Authorization: Bearer $TOKEN"
curl -s localhost:8080/promote -X POST -H "Authorization: Bearer $TOKEN"
# log in again to get a token that carries the Admin role, then:
curl -s localhost:8080/admin -H "Authorization: Bearer <new accessToken>"

# Refresh
curl -s localhost:8080/refresh \
  -d '{"userId":"<userId>","refreshToken":"<refreshToken>"}'
```

### Enable two-factor

No phone needed — `go run ./demo/totp <sharedKey>` prints the current 6-digit code.

```bash
# 1. get a shared key + otpauth URI (add it to Google Authenticator / Authy)
curl -s localhost:8080/2fa/setup -X POST -H "Authorization: Bearer $TOKEN"
#  -> {"sharedKey":"NASN2OOZ...","authenticatorUri":"otpauth://totp/..."}

# 2. enable with the current 6-digit code -> returns recovery codes
CODE=$(go run ./demo/totp NASN2OOZ...)
curl -s localhost:8080/2fa/enable -X POST -H "Authorization: Bearer $TOKEN" \
  -d "{\"code\":\"$CODE\"}"

# 3. subsequent logins need the code
curl -s localhost:8080/login \
  -d "{\"userName\":\"jane\",\"password\":\"Abcdef1!\",\"twoFactorCode\":\"$(go run ./demo/totp NASN2OOZ...)\"}"
```

## Inspect the schema

```bash
docker compose exec db psql -U identity -c '\dt'
docker compose exec db psql -U identity -c 'SELECT id, user_name, email, two_factor_enabled FROM identity_users;'
```

## Tear down

```bash
docker compose down -v   # -v also drops the data volume
```

> Want GORM (Postgres/MySQL/SQLite) instead of raw pgx? Swap
> `pgxstore.NewUserStore(pool)` for `gormstore.NewUserStore(db)` — the manager
> code is identical.
