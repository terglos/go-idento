package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Error is an OAuth error response (RFC 6749 §5.2 / §4.1.2.1).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	Status      int    `json:"-"`
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func oerr(status int, code, desc string) *Error {
	return &Error{Code: code, Description: desc, Status: status}
}

// Standard error constructors.
func errInvalidRequest(d string) *Error { return oerr(http.StatusBadRequest, "invalid_request", d) }
func errInvalidClient(d string) *Error  { return oerr(http.StatusUnauthorized, "invalid_client", d) }
func errInvalidGrant(d string) *Error   { return oerr(http.StatusBadRequest, "invalid_grant", d) }
func errInvalidScope(d string) *Error   { return oerr(http.StatusBadRequest, "invalid_scope", d) }
func errInvalidTarget(d string) *Error  { return oerr(http.StatusBadRequest, "invalid_target", d) }
func errUnsupportedGrant(d string) *Error {
	return oerr(http.StatusBadRequest, "unsupported_grant_type", d)
}
func errServer(d string) *Error { return oerr(http.StatusInternalServerError, "server_error", d) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *Error) {
	status := e.Status
	if status == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, e)
}

// noStore marks a response as uncacheable (token / registration responses).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// cors allows browser-based OAuth clients (e.g. MCP Inspector) to call the
// metadata, token, registration and revocation endpoints. It answers preflight
// requests itself and reports whether the request was one.
func cors(w http.ResponseWriter, r *http.Request) (preflight bool) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		h.Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// randomSecret returns n random bytes, base64url-encoded.
func randomSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: cannot read random bytes: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashSecret is the at-rest form of codes, refresh secrets and client secrets:
// all are high-entropy random values, so a single SHA-256 is sufficient.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// --- PKCE (RFC 7636), S256 only ---

func isUnreserved(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
		r == '-' || r == '.' || r == '_' || r == '~'
}

// validChallenge accepts an S256 challenge: base64url(SHA-256) is 43 chars.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, r := range c {
		if !isUnreserved(r) || r == '.' || r == '~' {
			return false
		}
	}
	return true
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !isUnreserved(r) {
			return false
		}
	}
	return true
}

// verifyS256 checks BASE64URL(SHA256(verifier)) == challenge in constant time.
func verifyS256(verifier, challenge string) bool {
	if !validVerifier(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return constEq(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

// --- scopes ---

func parseScopes(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, sc := range strings.Fields(s) {
		if !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return out
}

func joinScopes(s []string) string { return strings.Join(s, " ") }

func containsAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func unionScopes(a, b []string) []string { return parseScopes(joinScopes(a) + " " + joinScopes(b)) }

func hasScope(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- URLs ---

// canonicalResource normalizes a resource identifier for comparison: lowercase
// scheme and host (the MCP spec asks servers to accept uppercase variants) and
// no trailing slash on the root path. ok is false for non-absolute URIs or URIs
// with a fragment (RFC 8707 §2).
func canonicalResource(s string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String(), true
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateRedirectURI enforces the registration rules: an absolute URI without
// fragment or credentials, using https — or http on a loopback host (native
// apps, RFC 8252).
func validateRedirectURI(s string) error {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errInvalidRedirect("redirect_uri must be an absolute URI: " + s)
	}
	if u.Fragment != "" || strings.Contains(s, "#") {
		return errInvalidRedirect("redirect_uri must not contain a fragment: " + s)
	}
	if u.User != nil {
		return errInvalidRedirect("redirect_uri must not contain credentials")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errInvalidRedirect("http redirect_uri is only allowed on a loopback host: " + s)
	default:
		return errInvalidRedirect("redirect_uri must use https (or http on loopback): " + s)
	}
}

func errInvalidRedirect(d string) *Error {
	return oerr(http.StatusBadRequest, "invalid_redirect_uri", d)
}

// matchRedirectURI reports whether requested matches one of the registered
// redirect URIs: exact string match, except that for loopback http URIs the
// port is ignored (RFC 8252 §7.3) — native clients such as Claude Code bind an
// ephemeral port per session. Host, path and query must still match exactly.
func matchRedirectURI(registered []string, requested string) bool {
	if requested == "" {
		return false
	}
	for _, reg := range registered {
		if reg == requested {
			return true
		}
	}
	ru, err := url.Parse(requested)
	if err != nil || !strings.EqualFold(ru.Scheme, "http") || !isLoopbackHost(ru.Hostname()) || ru.Fragment != "" {
		return false
	}
	for _, reg := range registered {
		gu, err := url.Parse(reg)
		if err != nil || !strings.EqualFold(gu.Scheme, "http") || !isLoopbackHost(gu.Hostname()) {
			continue
		}
		if strings.EqualFold(gu.Hostname(), ru.Hostname()) && gu.EscapedPath() == ru.EscapedPath() && gu.RawQuery == ru.RawQuery {
			return true
		}
	}
	return false
}

// allLoopback reports whether every redirect URI targets a loopback host — the
// consent page must warn, since CIMD can't prevent localhost impersonation.
func allLoopback(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil || !isLoopbackHost(u.Hostname()) {
			return false
		}
	}
	return true
}

func hostOf(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Host
}
