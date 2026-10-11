package oauth

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

// ClientMetadata is a client registration request (RFC 7591 §2). Unknown fields
// are ignored.
type ClientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
}

// ClientRegistration is the registration response (RFC 7591 §3.2.1). The
// ClientSecret is returned once and only stored hashed.
type ClientRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name,omitempty"`
}

// RegisterHandler serves Dynamic Client Registration (RFC 7591). Clients such as
// Claude register on every fresh connection, so it is rate-limited per IP and
// abandoned clients should be purged with PurgeStaleClients.
func (s *Server) RegisterHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		noStore(w)
		if r.Method != http.MethodPost {
			writeError(w, oerr(http.StatusMethodNotAllowed, "invalid_request", "use POST"))
			return
		}
		if s.limiter != nil && !s.limiter.allow(s.opts.ClientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeError(w, oerr(http.StatusTooManyRequests, "invalid_request", "too many registrations; retry later"))
			return
		}
		if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
			writeError(w, oerr(http.StatusBadRequest, "invalid_client_metadata", "content type must be application/json"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var m ClientMetadata
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeError(w, oerr(http.StatusBadRequest, "invalid_client_metadata", "malformed JSON"))
			return
		}
		reg, e := s.register(r.Context(), m)
		if e != nil {
			writeError(w, e)
			return
		}
		writeJSON(w, http.StatusCreated, reg)
	})
}

func (s *Server) register(ctx context.Context, m ClientMetadata) (*ClientRegistration, *Error) {
	bad := func(d string) *Error { return oerr(http.StatusBadRequest, "invalid_client_metadata", d) }
	if len(m.RedirectURIs) == 0 {
		return nil, errInvalidRedirect("at least one redirect_uri is required")
	}
	if len(m.RedirectURIs) > 20 {
		return nil, errInvalidRedirect("too many redirect_uris")
	}
	for _, ru := range m.RedirectURIs {
		if err := validateRedirectURI(ru); err != nil {
			return nil, err.(*Error)
		}
	}
	method := m.TokenEndpointAuthMethod
	if method == "" {
		method = AuthMethodClientSecretBasic // RFC 7591 default
	}
	switch method {
	case AuthMethodNone, AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
	default:
		return nil, bad("unsupported token_endpoint_auth_method: " + method)
	}
	grants := m.GrantTypes
	if len(grants) == 0 {
		// RFC 7591's default is authorization_code alone, but an MCP client that
		// omits grant_types would then never get a refresh token and re-prompt
		// every AccessTokenTTL. Register both and echo them back (RFC 7591 §3.2.1
		// lets the server replace requested values).
		grants = []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}
	}
	for _, g := range grants {
		if g != GrantTypeAuthorizationCode && g != GrantTypeRefreshToken {
			return nil, bad("unsupported grant_type: " + g)
		}
	}
	if !hasScope(grants, GrantTypeAuthorizationCode) {
		return nil, bad("grant_types must include authorization_code")
	}
	resp := m.ResponseTypes
	if len(resp) == 0 {
		resp = []string{"code"}
	}
	for _, rt := range resp {
		if rt != "code" {
			return nil, bad("unsupported response_type: " + rt)
		}
	}
	name := strings.TrimSpace(m.ClientName)
	if len(name) > 256 {
		name = name[:256]
	}
	now := s.opts.Now()
	c := &Client{
		ClientID:                newID(),
		Name:                    name,
		RedirectURIs:            m.RedirectURIs,
		TokenEndpointAuthMethod: method,
		GrantTypes:              grants,
		CreatedAt:               now,
	}
	out := &ClientRegistration{
		ClientID: c.ClientID, ClientIDIssuedAt: now.Unix(), RedirectURIs: m.RedirectURIs,
		TokenEndpointAuthMethod: method, GrantTypes: grants, ResponseTypes: resp, ClientName: name,
	}
	if method != AuthMethodNone {
		secret := randomSecret(32)
		c.SecretHash = hashSecret(secret)
		out.ClientSecret = secret
		never := int64(0)
		out.ClientSecretExpiresAt = &never
	}
	if err := s.store.CreateClient(ctx, c); err != nil {
		return nil, errServer("could not register client")
	}
	return out, nil
}
