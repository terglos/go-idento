// Command mcpoauth is a runnable demo of go-idento's embedded OAuth 2.1
// authorization server protecting an MCP server, with lazy authentication: the
// public tool works anonymously, and calling the protected tool without a token
// answers 401 + WWW-Authenticate so MCP clients (Claude, ChatGPT, MCP
// Inspector) start the OAuth flow.
//
//	go run ./demo/mcpoauth                 # http://localhost:8091, user demo / Demo123!
//	DEMO_REQUIRE_AUTH=1 go run ./demo/mcpoauth   # whole /mcp endpoint requires a token
//	DEMO_BASE_URL=https://xyz.example go run ./demo/mcpoauth  # behind an https tunnel
//
// In-memory store; everything resets on restart. Development only.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
	"github.com/terglos/go-idento/stores/memstore"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8091"
	}
	base := strings.TrimSuffix(os.Getenv("DEMO_BASE_URL"), "/") // public https URL when behind a tunnel
	if base == "" {
		base = "http://localhost:" + port
	}
	resource := base + "/mcp"

	st := memstore.New()
	users := identity.NewUserManager(st.Users(), identity.DefaultOptions())
	signIn := identity.NewSignInManager(users)
	tokens := identity.NewTokenService(users, identity.DefaultTokenOptions([]byte("demo-only-signing-key-change-me!!"), base, "app"))
	cookies := auth.DefaultCookieAuth()
	cookies.Secure = false // demo over http://localhost

	demo := &identity.User{UserName: "demo", Email: "demo@example.com"}
	if err := users.CreateWithPassword(context.Background(), demo, "Demo123!"); err != nil {
		log.Fatal(err)
	}

	// Who is signed in to the app (the session cookie set by /login).
	currentUser := func(r *http.Request) (string, bool) {
		c, err := r.Cookie(cookies.Name)
		if err != nil {
			return "", false
		}
		u, _, err := tokens.ValidateAccessToken(r.Context(), c.Value)
		if err != nil {
			return "", false
		}
		return u.ID, true
	}

	srv, err := oauth.NewServer(users, tokens, st.OAuth(), oauth.Options{
		Issuer:      base,
		Resources:   []string{resource},
		Scopes:      []string{"mcp:read", oauth.ScopeOfflineAccess},
		AllowDCR:    true,
		AllowCIMD:   true,
		CurrentUser: currentUser,
		LoginURL: func(_ *http.Request, returnTo string) string {
			return "/login?return_to=" + url.QueryEscape(returnTo)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	srv.Routes(mux)

	// Protected resource metadata (RFC 9728), path-suffixed and root.
	metaURL, _ := oauth.ResourceMetadataURL(resource)
	metaPath, _ := oauth.ResourceMetadataPath(resource)
	prm := oauth.ProtectedResourceHandler(oauth.ProtectedResourceMetadata{
		Resource: resource, AuthorizationServers: []string{base}, ScopesSupported: []string{"mcp:read"},
		ResourceName: "go-idento MCP demo"})
	mux.Handle(metaPath, prm)
	mux.Handle("/.well-known/oauth-protected-resource", prm)

	// App login (owned by the app, not the library).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		returnTo := r.FormValue("return_to")
		if !strings.HasPrefix(returnTo, base+"/") {
			returnTo = base + "/"
		}
		if r.Method == http.MethodPost {
			res, u := signIn.PasswordSignIn(r.Context(), r.FormValue("username"), r.FormValue("password"), true)
			if res.Succeeded {
				pair, err := tokens.IssuePair(r.Context(), u)
				if err == nil {
					cookies.Write(w, pair.AccessToken)
					http.Redirect(w, r, returnTo, http.StatusSeeOther)
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
		}
		_ = loginTmpl.Execute(w, map[string]string{"ReturnTo": returnTo})
	})

	// The MCP endpoint (Streamable HTTP, JSON responses).
	var mcp http.Handler = mcpHandler(metaURL)
	if os.Getenv("DEMO_REQUIRE_AUTH") == "1" {
		mcp = oauth.RequireScopes(metaURL, "mcp:read")(mcp)
	}
	mux.Handle("/mcp", withCORS(auth.Middleware(tokens, nil, auth.WithOAuthResource(srv, resource))(mcp)))

	log.Printf("MCP demo on %s/mcp  (issuer %s, user demo / Demo123!)", base, base)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html><meta charset="utf-8">
<title>Sign in</title><body style="font-family:system-ui;max-width:24rem;margin:4rem auto">
<h1>Sign in</h1><form method="post"><input type="hidden" name="return_to" value="{{.ReturnTo}}">
<p><label>User <input name="username" value="demo"></label></p>
<p><label>Password <input name="password" type="password"></label></p>
<button type="submit">Sign in</button></form></body>`))

// withCORS lets browser-based MCP clients (MCP Inspector) reach /mcp and read
// the WWW-Authenticate challenge.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func mcpHandler(metaURL string) http.Handler {
	tools := []map[string]any{
		{"name": "get_time", "description": "Current server time (public, no sign-in).",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "whoami", "description": "Who you are (requires sign-in: answers 401 and triggers OAuth).",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "this demo serves JSON responses only (no SSE stream)", http.StatusMethodNotAllowed)
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON-RPC", http.StatusBadRequest)
			return
		}
		if len(req.ID) == 0 { // notification
			w.WriteHeader(http.StatusAccepted)
			return
		}
		reply := func(result any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		}
		text := func(s string) map[string]any {
			return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
		}
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-11-25"
			}
			reply(map[string]any{"protocolVersion": p.ProtocolVersion,
				"capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo":   map[string]any{"name": "go-idento-mcp-demo", "version": "0.7.0"}})
		case "ping":
			reply(map[string]any{})
		case "tools/list":
			reply(map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(req.Params, &p)
			switch p.Name {
			case "get_time":
				reply(text(time.Now().Format(time.RFC3339)))
			case "whoami":
				pr, ok := auth.PrincipalFrom(r.Context())
				if !ok || !pr.ViaOAuth {
					// Lazy auth: a real HTTP 401 (not a 200 with isError) starts sign-in.
					oauth.Challenge(w, metaURL, "mcp:read")
					return
				}
				reply(text(fmt.Sprintf("You are %s (client %s, scopes %s)", pr.User.UserName, pr.ClientID, strings.Join(pr.Scopes, " "))))
			default:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]any{"code": -32602, "message": "unknown tool: " + p.Name}})
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32601, "message": "method not found: " + req.Method}})
		}
	})
}
