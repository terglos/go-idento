package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/terglos/go-idento/auth"
)

// ProtectedResourceMetadata is the RFC 9728 document a resource server (e.g.
// your MCP endpoint) publishes so clients can discover its authorization server.
type ProtectedResourceMetadata struct {
	// Resource must equal the URL users configure in the client, path included.
	Resource string `json:"resource"`
	// AuthorizationServers lists issuer identifiers; Claude uses only the first.
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// ProtectedResourceHandler serves the metadata document. Mount it at both
// ResourceMetadataPath(resource) (tried first) and
// "/.well-known/oauth-protected-resource".
func ProtectedResourceHandler(m ProtectedResourceMetadata) http.Handler {
	if len(m.BearerMethodsSupported) == 0 {
		m.BearerMethodsSupported = []string{"header"}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, m)
	})
}

// ResourceMetadataPath returns the path-suffixed well-known path for a resource:
// https://api.example.com/v1/mcp → /.well-known/oauth-protected-resource/v1/mcp.
func ResourceMetadataPath(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("oauth: invalid resource %q", resource)
	}
	return "/.well-known/oauth-protected-resource" + strings.TrimSuffix(u.EscapedPath(), "/"), nil
}

// ResourceMetadataURL returns the absolute metadata URL for a resource — the
// value to put in the resource_metadata challenge parameter.
func ResourceMetadataURL(resource string) (string, error) {
	p, err := ResourceMetadataPath(resource)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(resource)
	return u.Scheme + "://" + u.Host + p, nil
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Challenge writes 401 with `WWW-Authenticate: Bearer resource_metadata=…,
// scope=…` — the response that makes MCP clients (Claude, ChatGPT) start the
// OAuth flow. Clients ignore WWW-Authenticate on 200 responses, so a protected
// tool must answer with this status, not with a 200 error payload.
func Challenge(w http.ResponseWriter, metadataURL, scope string) {
	v := "Bearer resource_metadata=" + quote(metadataURL)
	if scope != "" {
		v += ", scope=" + quote(scope)
	}
	w.Header().Set("WWW-Authenticate", v)
	exposeHeader(w.Header(), "WWW-Authenticate")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized",
		"error_description": "authentication required"})
}

// InsufficientScope writes 403 with `error="insufficient_scope"` and the scopes
// needed, prompting a step-up authorization.
func InsufficientScope(w http.ResponseWriter, metadataURL, scope, description string) {
	v := `Bearer error="insufficient_scope", scope=` + quote(scope) + ", resource_metadata=" + quote(metadataURL)
	if description != "" {
		v += ", error_description=" + quote(description)
	}
	w.Header().Set("WWW-Authenticate", v)
	exposeHeader(w.Header(), "WWW-Authenticate")
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope",
		"error_description": description})
}

// RequireScopes protects a handler behind auth.Middleware (configured with
// auth.WithOAuthResource): anonymous requests get the 401 challenge, and OAuth
// requests whose token lacks a required scope get 403 insufficient_scope.
// Principals authenticated another way (app session, API key) are not
// scope-checked — gate those with your own policy if needed.
func RequireScopes(metadataURL string, scopes ...string) func(http.Handler) http.Handler {
	scope := joinScopes(scopes)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				Challenge(w, metadataURL, scope)
				return
			}
			if p.ViaOAuth && !containsAll(p.Scopes, scopes) {
				InsufficientScope(w, metadataURL, joinScopes(unionScopes(p.Scopes, scopes)), "additional scope required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// exposeHeader adds name to Access-Control-Expose-Headers without clobbering a
// list the application's CORS middleware already set (e.g. Mcp-Session-Id).
func exposeHeader(h http.Header, name string) {
	cur := h.Get("Access-Control-Expose-Headers")
	for _, v := range strings.Split(cur, ",") {
		if strings.EqualFold(strings.TrimSpace(v), name) {
			return
		}
	}
	if cur == "" {
		h.Set("Access-Control-Expose-Headers", name)
		return
	}
	h.Set("Access-Control-Expose-Headers", cur+", "+name)
}
