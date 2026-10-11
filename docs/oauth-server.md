# Embedded OAuth 2.1 authorization server (MCP connectors)

Package [`oauth`](../oauth) turns a go-idento app into an OAuth 2.1
authorization server, so third-party clients — **MCP clients such as Claude and
ChatGPT**, CLIs, integrations — can obtain per-user, audience-bound access
tokens for your API. It implements the profile required by the
[MCP authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization):

| Spec | What it does here |
|---|---|
| OAuth 2.1 authorization code | **PKCE mandatory, S256 only** (`plain` rejected) |
| Refresh token grant | rotation on every use + **reuse detection** (replay revokes the grant) |
| RFC 8414 | `/.well-known/oauth-authorization-server[/issuer-path]` |
| RFC 9728 | protected resource metadata + `WWW-Authenticate: Bearer resource_metadata=…` 401 challenge, 403 `insufficient_scope` step-up |
| RFC 8707 | `resource` → access-token `aud`; tokens for one resource are rejected by another |
| RFC 7591 | Dynamic Client Registration (rate-limited per IP; stale clients GC'd) |
| CIMD | `client_id` as an https URL to a Client ID Metadata Document (SSRF-hardened fetch) |
| RFC 8252 | loopback redirects: any port on `127.0.0.1` / `[::1]` / `localhost` |
| RFC 7009 | token revocation (always 200) |
| RFC 9207 | `iss` in the authorization response |
| RFC 9068 | access tokens are `typ: at+jwt` JWTs |

The app keeps ownership of the user experience: **who is signed in**
(`CurrentUser`), **where anonymous users go** (`LoginURL`) and **what the
consent page looks like** (`RenderConsent`). The server does not render a
login page or own a session.

A runnable demo (core module only, in-memory) is in
[`demo/mcpoauth`](../demo/mcpoauth).

## Wiring

```go
srv, err := oauth.NewServer(users, tokens, gormstore.NewOAuthStore(db), oauth.Options{
    Issuer:    "https://api.example.com",
    Resources: []string{"https://api.example.com/mcp"}, // RFC 8707 audiences
    Scopes:    []string{"mcp:read", "mcp:write", oauth.ScopeOfflineAccess},
    AllowDCR:  true, // RFC 7591
    AllowCIMD: true, // URL client_ids
    CurrentUser: func(r *http.Request) (string, bool) { /* your session cookie */ },
    LoginURL: func(r *http.Request, returnTo string) string {
        return "/login?return_to=" + url.QueryEscape(returnTo)
    },
    RenderConsent: myConsentPage, // optional; oauth.DefaultConsentPage otherwise
    CSRFKey:       consentKey,    // stable 32+ bytes when running several instances
})
srv.Routes(mux) // metadata, /oauth/authorize, /oauth/token, /oauth/revoke, /oauth/register

// Protected resource metadata (RFC 9728) for the MCP endpoint.
resource := "https://api.example.com/mcp"
metaURL, _ := oauth.ResourceMetadataURL(resource)   // …/.well-known/oauth-protected-resource/mcp
metaPath, _ := oauth.ResourceMetadataPath(resource)
mux.Handle(metaPath, oauth.ProtectedResourceHandler(oauth.ProtectedResourceMetadata{
    Resource: resource, AuthorizationServers: []string{srv.Issuer()},
    ScopesSupported: []string{"mcp:read", "mcp:write"},
}))

// Accept OAuth access tokens on the MCP endpoint (alongside sessions and API keys).
mcp := auth.Middleware(tokens, cookies,
    auth.WithOAuthResource(srv, resource),
    auth.WithAPIKeys(keys))(mcpHandler)
mux.Handle("/mcp", mcp)
```

Stores: `memstore.New().OAuth()`, `gormstore.NewOAuthStore(db, opts...)`,
`pgxstore.NewOAuthStore(pool, opts...)`, `pgxsqlc.NewOAuthStore(pool)`. Each
store's `Migrate` creates the four tables (`identity_oauth_clients`, `_codes`,
`_consents`, `_grants`), honoring `WithSchema` / `WithTablePrefix` /
`WithTableNames` (`TableNames.OAuth*`).

`NewServer` validates its configuration and returns an error for: a non-https
issuer (http is allowed only on loopback, for development), no resources, a
missing `CurrentUser`/`LoginURL`, or default scopes not in `Scopes`.

## Authentication precedence and the Principal

`auth.Middleware` tries, in order: **session JWT** (Bearer or cookie) →
**OAuth access token** (Bearer only, never a cookie) → **API key**. An OAuth
token yields:

```go
p, _ := auth.PrincipalFrom(r.Context())
p.ViaOAuth  // true
p.ClientID  // the OAuth client
p.Scopes    // granted scopes
p.User      // the consenting user (roles/claims apply as usual)
```

Session tokens and OAuth tokens are **not interchangeable**: OAuth access
tokens carry `typ: at+jwt` and are rejected by `TokenService.ValidateAccessToken`,
and a session JWT is rejected by `ValidateResourceToken` (wrong audience/type).

## Lazy authentication (public + protected tools on one endpoint)

MCP clients only start OAuth when they see an **HTTP 401 with
`WWW-Authenticate`** — a 200 response with an error payload is ignored. Keep
the endpoint open and challenge per tool:

```go
case "whoami":
    p, ok := auth.PrincipalFrom(r.Context())
    if !ok || !p.ViaOAuth {
        oauth.Challenge(w, metaURL, "mcp:read") // 401 + resource_metadata + scope
        return
    }
```

To require a token for the whole endpoint use
`oauth.RequireScopes(metaURL, "mcp:read")(handler)`; an OAuth token missing a
scope gets 403 `insufficient_scope` (`oauth.InsufficientScope`), which MCP
clients answer with a step-up authorization.

Both helpers *append* `WWW-Authenticate` to `Access-Control-Expose-Headers`, so
an app CORS layer exposing `Mcp-Session-Id` keeps working.

## Tokens

- **Access token**: JWT signed with the `TokenService` signer (so an existing
  `auth.JWKSHandler` publishes its keys), header `typ: at+jwt`, claims `iss`,
  `sub`, `aud` (= resource), `exp`/`iat`/`nbf`, `jti`, `client_id`, `scope`,
  `gid` (grant id), `idn_sstamp` (security stamp), `roles`.
  `ValidateResourceToken` checks signature, issuer, audience, type, **that the
  grant still exists** (so revocation is immediate, not at expiry), the
  user's security stamp and lockout.
- **Refresh token**: opaque `gid.secret`; only the secret's SHA-256 is stored.
  Rotated on every use with a sliding `RefreshTokenTTL` (default 30 days).
  Presenting an already-rotated token **revokes the whole grant** (and with it
  every access token minted from it). `RefreshReuseGrace` (default 0 = strict)
  can absorb benign client retries.
- **Every failure at the token endpoint is `invalid_grant`** (unknown/expired/
  replayed code, PKCE mismatch, wrong client/resource, stale security stamp…).
- A password/2FA/email change rotates the security stamp: refresh fails and the
  grant is revoked; outstanding access tokens are rejected.
- Refresh tokens are issued to every client allowed the `refresh_token` grant;
  set `RequireOfflineAccess` to issue them only when `offline_access` is granted.
  DCR registers `authorization_code` + `refresh_token` when the client omits
  `grant_types` (echoed back in the registration response).

## Consent

- Consent is remembered per (user, client); a later request for a subset of the
  approved scopes skips the page. New scopes ask again (approved sets are
  unioned).
- `RenderConsent` receives a `ConsentRequest`: client id/name, **`ClientHost`**
  (for CIMD clients, the host of the `client_id` URL — display it as the app
  identity, since `client_name` is self-asserted), redirect host,
  `LoopbackOnly`, scopes, resource, and the hidden `Fields` (including a CSRF
  token) to POST back to `Action` with `decision=approve` (anything else denies).
- The CSRF token is an HMAC over the user, every authorization parameter and a
  timestamp (15-minute lifetime). The default page sends
  `X-Frame-Options: DENY` and `frame-ancestors 'none'`.

## Client registration

- **DCR** (`AllowDCR`): `POST /oauth/register` (JSON, 16 KB cap, rate-limited
  per IP via `RegisterLimit`/`ClientIP`). Public clients use
  `token_endpoint_auth_method: none`; confidential clients get a secret (stored
  hashed) and authenticate with `client_secret_basic` or `client_secret_post`.
  Redirect URIs must be https, or http on a loopback host.
- **CIMD** (`AllowCIMD`): an https `client_id` URL is fetched with no
  redirects, a 5 KB cap and 5 s timeout; special-use/private IP ranges are
  blocked **at dial time** (defeats DNS rebinding), no proxy; the document's
  `client_id` must equal the URL; only `token_endpoint_auth_method: none`. Cached
  per `Cache-Control` (bounded), errors never cached. `CIMDFetcher.AllowPrivateNetworks`
  exists for tests only.
- **Pre-registered clients**: `srv.RegisterClient(ctx, oauth.ClientMetadata{…})`
  from your own code (same validation as DCR).

## Connected apps and housekeeping

```go
grants, _ := srv.ListGrants(ctx, userID)       // "connected apps" page
srv.RevokeGrant(ctx, userID, grantID)          // one connection
srv.RevokeClient(ctx, userID, clientID)        // all grants + remembered consent

// From a periodic job:
srv.PurgeExpired(ctx)                                       // expired codes + grants
srv.PurgeStaleClients(ctx, time.Now().Add(-30*24*time.Hour)) // unused DCR clients with no grants
```

Deleting a user cascades to their codes, consents and grants in every store.

## Endpoint CORS

Metadata, token, register and revoke endpoints answer CORS (`*`, no
credentials) so browser-based clients (MCP Inspector) can complete the flow. The
authorize endpoint is a top-level browser navigation and has no CORS.

## Testing your store

`oauth/oauthtest` exports `RunStoreConformance` and `RunEndToEnd` (full flow
through the HTTP handlers: PKCE, rotation/reuse, replay, loopback, confidential
clients, audience separation, stamp revocation, challenge/step-up, scope
narrowing, connected apps, purge). Run them against a custom `oauth.Store`.

## Not included

OpenID Connect (ID tokens, `/.well-known/openid-configuration`, userinfo),
the client-credentials and device grants, token introspection, and
`private_key_jwt` client authentication.
