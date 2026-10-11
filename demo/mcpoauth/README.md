# MCP + OAuth 2.1 demo

A minimal MCP server (Streamable HTTP, JSON responses) protected by go-idento's
embedded OAuth 2.1 authorization server, with **lazy authentication**:

- `get_time` — public, works without signing in;
- `whoami` — protected: called without a token it answers **HTTP 401 +
  `WWW-Authenticate: Bearer resource_metadata=…`**, which makes MCP clients
  start the OAuth flow (discovery → DCR/CIMD → login → consent → PKCE code →
  token).

Core module only, in-memory store (resets on restart).

```bash
go run ./demo/mcpoauth            # http://localhost:8091/mcp — user demo / Demo123!
```

`DEMO_REQUIRE_AUTH=1` protects the whole endpoint (`oauth.RequireScopes`)
instead of per tool; `PORT` changes the listen port; `DEMO_BASE_URL` sets the
public base URL (default `http://localhost:$PORT`).

## Try it

**MCP Inspector:** `npx @modelcontextprotocol/inspector`, transport
"Streamable HTTP", URL `http://localhost:8091/mcp`. List tools, call `get_time`,
then call `whoami` (or use "Open Auth Settings → Quick OAuth Flow") — sign in as
`demo` / `Demo123!` and approve.

**Claude Code:** `claude mcp add --transport http idento-demo http://localhost:8091/mcp`,
then `/mcp` to authenticate.

**curl:** the 401 challenge and discovery documents:

```bash
curl -i -X POST localhost:8091/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}'
curl localhost:8091/.well-known/oauth-protected-resource/mcp
curl localhost:8091/.well-known/oauth-authorization-server
```

Claude.ai / ChatGPT connectors need a public **https** URL: put a tunnel in
front (e.g. `cloudflared tunnel --url http://localhost:8091`) and start the demo
with `DEMO_BASE_URL=https://<tunnel-host>` so the issuer, resource and metadata
use it; then add `https://<tunnel-host>/mcp` as a custom connector. The issuer
must be https outside loopback.

See [docs/oauth-server.md](../../docs/oauth-server.md) for the full guide.
