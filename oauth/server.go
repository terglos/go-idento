package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/terglos/go-idento/identity"
)

// ConsentRequest is what the app's consent page shows and posts back. The page
// MUST display ClientHost (for metadata-document clients) or ClientName, and
// RedirectHost; when LoopbackOnly is true it SHOULD warn that the redirect goes
// to a local application. The form must POST Fields (hidden inputs) plus
// decision=approve (or decision=deny) to Action.
type ConsentRequest struct {
	ClientID     string
	ClientName   string // self-asserted name (DCR client_name / CIMD client_name)
	ClientHost   string // CIMD: host of the client_id URL — display this as the app identity
	RedirectURI  string
	RedirectHost string
	LoopbackOnly bool
	Scopes       []string
	Resource     string
	UserID       string
	Action       string
	Fields       url.Values
}

// Options configures the authorization server.
type Options struct {
	// Issuer is the authorization server identifier (https URL, no query or
	// fragment); endpoint URLs are Issuer + the *Path options.
	Issuer string
	// Resources are the allowed RFC 8707 resource indicators — they become the
	// access-token audience. With exactly one, an omitted resource defaults to it.
	Resources []string
	// Scopes lists the supported scopes (advertised in metadata); requests for
	// unknown scopes are rejected with invalid_scope.
	Scopes []string
	// DefaultScopes apply when a request omits scope (default: Scopes).
	DefaultScopes []string

	CodeTTL         time.Duration // default 60s
	AccessTokenTTL  time.Duration // default: TokenService AccessTokenTTL, else 15m
	RefreshTokenTTL time.Duration // default 30 days (sliding on rotation)
	// RefreshReuseGrace tolerates a replay of the just-rotated refresh token for
	// this long (answering invalid_grant without revoking), to absorb benign
	// client retries. 0 = strict: any reuse revokes the grant.
	RefreshReuseGrace time.Duration
	// RequireOfflineAccess issues refresh tokens only when offline_access was
	// granted. Default false: a refresh token is issued to every client allowed
	// the refresh_token grant (DCR registers it unless grant_types says otherwise).
	RequireOfflineAccess bool

	AllowDCR  bool // enable POST RegisterPath (RFC 7591)
	AllowCIMD bool // accept https URL client_ids (Client ID Metadata Documents)

	AuthorizePath, TokenPath, RegisterPath, RevokePath string // defaults /oauth/...

	// CurrentUser returns the signed-in user id for the request (e.g. from the
	// app's session cookie). Required.
	CurrentUser func(r *http.Request) (userID string, ok bool)
	// LoginURL is where anonymous users are sent; returnTo is the authorize URL
	// to come back to after sign-in. Required.
	LoginURL func(r *http.Request, returnTo string) string
	// RenderConsent renders the app-styled consent page (default: a minimal
	// built-in page, DefaultConsentPage).
	RenderConsent func(w http.ResponseWriter, r *http.Request, c ConsentRequest)
	// RenderError renders errors that can't be redirected to the client (unknown
	// client, bad redirect_uri). Default: a plain-text page.
	RenderError func(w http.ResponseWriter, r *http.Request, e *Error)

	// CSRFKey signs consent forms. Default: a random per-process key (set a
	// stable key when running several instances behind a load balancer).
	CSRFKey []byte
	// CIMD fetches metadata documents (default: NewCIMDFetcher()).
	CIMD *CIMDFetcher
	// RegisterLimit caps DCR requests per client IP per minute (default 20;
	// negative disables). ClientIP extracts the IP (default: RemoteAddr host).
	RegisterLimit int
	ClientIP      func(r *http.Request) string
	// ClientAssertionMaxLifetime is the furthest in the future a private_key_jwt
	// client assertion's exp may be (default 1h); it bounds how long used
	// assertion ids are kept for replay detection.
	ClientAssertionMaxLifetime time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Server is the embedded OAuth 2.1 authorization server.
type Server struct {
	users   *identity.UserManager
	tokens  *identity.TokenService
	store   Store
	opts    Options
	issuer  string // trimmed
	ipath   string // issuer path ("" or "/tenant")
	signer  identity.Signer
	limiter *ipLimiter

	scopeSet     map[string]bool
	resourceList []string // canonical
}

// resolvedClient is a client as seen by the server, whatever its origin.
type resolvedClient struct {
	ID           string
	Name         string
	DisplayHost  string
	RedirectURIs []string
	AuthMethod   string
	SecretHash   string
	GrantTypes   []string
	CIMD         bool
	// private_key_jwt: the client's keys come from JWKSURI (fetched and cached)
	// or are inline (Keys); SigningAlg pins the assertion algorithm when declared.
	JWKSURI    string
	Keys       []clientKey
	SigningAlg string
}

func (c *resolvedClient) public() bool {
	return c.SecretHash == "" && c.AuthMethod != AuthMethodPrivateKeyJWT
}

// NewServer validates the options and builds the server. Access tokens are
// signed with tokens' signer (HS256 key or RS256/ES256 keyring), so the app's
// existing JWKS keeps working for asymmetric keys.
func NewServer(users *identity.UserManager, tokens *identity.TokenService, store Store, opts Options) (*Server, error) {
	if users == nil || tokens == nil || store == nil {
		return nil, errors.New("oauth: users, tokens and store are required")
	}
	if opts.CurrentUser == nil || opts.LoginURL == nil {
		return nil, errors.New("oauth: Options.CurrentUser and Options.LoginURL are required")
	}
	iu, err := url.Parse(strings.TrimSuffix(opts.Issuer, "/"))
	if err != nil || iu.Host == "" || iu.RawQuery != "" || iu.Fragment != "" {
		return nil, fmt.Errorf("oauth: invalid Issuer %q", opts.Issuer)
	}
	if iu.Scheme != "https" && !(iu.Scheme == "http" && isLoopbackHost(iu.Hostname())) {
		return nil, fmt.Errorf("oauth: Issuer must use https (http is allowed only on loopback for development)")
	}
	if len(opts.Resources) == 0 {
		return nil, errors.New("oauth: at least one Resource is required")
	}
	s := &Server{users: users, tokens: tokens, store: store, opts: opts,
		issuer: iu.String(), ipath: iu.EscapedPath(), signer: tokens.Options.ResolvedSigner(),
		scopeSet: map[string]bool{}}
	for _, r := range opts.Resources {
		c, ok := canonicalResource(r)
		if !ok {
			return nil, fmt.Errorf("oauth: invalid resource %q", r)
		}
		s.resourceList = append(s.resourceList, c)
	}
	for _, sc := range opts.Scopes {
		s.scopeSet[sc] = true
	}
	for _, sc := range opts.DefaultScopes {
		if !s.scopeSet[sc] {
			return nil, fmt.Errorf("oauth: default scope %q is not in Scopes", sc)
		}
	}
	o := &s.opts
	if o.CodeTTL <= 0 {
		o.CodeTTL = 60 * time.Second
	}
	if o.AccessTokenTTL <= 0 {
		o.AccessTokenTTL = tokens.Options.AccessTokenTTL
		if o.AccessTokenTTL <= 0 {
			o.AccessTokenTTL = 15 * time.Minute
		}
	}
	if o.RefreshTokenTTL <= 0 {
		o.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if o.ClientAssertionMaxLifetime <= 0 {
		o.ClientAssertionMaxLifetime = time.Hour
	}
	for _, p := range []*string{&o.AuthorizePath, &o.TokenPath, &o.RegisterPath, &o.RevokePath} {
		if *p != "" && !strings.HasPrefix(*p, "/") {
			return nil, fmt.Errorf("oauth: endpoint path %q must start with /", *p)
		}
	}
	setDefault(&o.AuthorizePath, "/oauth/authorize")
	setDefault(&o.TokenPath, "/oauth/token")
	setDefault(&o.RegisterPath, "/oauth/register")
	setDefault(&o.RevokePath, "/oauth/revoke")
	if o.RenderConsent == nil {
		o.RenderConsent = DefaultConsentPage
	}
	if o.RenderError == nil {
		o.RenderError = defaultErrorPage
	}
	if len(o.CSRFKey) == 0 {
		o.CSRFKey = make([]byte, 32)
		if _, err := rand.Read(o.CSRFKey); err != nil {
			return nil, err
		}
	}
	if o.CIMD == nil {
		o.CIMD = NewCIMDFetcher()
	}
	if o.RegisterLimit == 0 {
		o.RegisterLimit = 20
	}
	if o.ClientIP == nil {
		o.ClientIP = func(r *http.Request) string {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return host
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RegisterLimit > 0 {
		s.limiter = &ipLimiter{limit: o.RegisterLimit, window: time.Minute, now: o.Now, hits: map[string]*window{}}
	}
	return s, nil
}

func setDefault(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

// Issuer returns the issuer identifier.
func (s *Server) Issuer() string { return s.issuer }

// endpoint returns the absolute URL of an endpoint path.
func (s *Server) endpoint(path string) string { return s.issuer + path }

// mountPath returns the server-relative path to mount an endpoint at.
func (s *Server) mountPath(path string) string { return s.ipath + path }

// MetadataPath is where RFC 8414 metadata must be served: the well-known suffix
// inserted before the issuer path.
func (s *Server) MetadataPath() string { return "/.well-known/oauth-authorization-server" + s.ipath }

// Routes mounts every authorization-server endpoint on mux: metadata, authorize,
// token, revoke and (when AllowDCR) register.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.Handle(s.MetadataPath(), s.MetadataHandler())
	mux.Handle(s.mountPath(s.opts.AuthorizePath), s.AuthorizeHandler())
	mux.Handle(s.mountPath(s.opts.TokenPath), s.TokenHandler())
	mux.Handle(s.mountPath(s.opts.RevokePath), s.RevokeHandler())
	if s.opts.AllowDCR {
		mux.Handle(s.mountPath(s.opts.RegisterPath), s.RegisterHandler())
	}
}

// Metadata returns the RFC 8414 authorization server metadata document.
func (s *Server) Metadata() map[string]any {
	m := map[string]any{
		"issuer":                                         s.issuer,
		"authorization_endpoint":                         s.endpoint(s.opts.AuthorizePath),
		"token_endpoint":                                 s.endpoint(s.opts.TokenPath),
		"revocation_endpoint":                            s.endpoint(s.opts.RevokePath),
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          s.opts.AllowCIMD,
		"authorization_response_iss_parameter_supported": true,
	}
	if len(s.opts.Scopes) > 0 {
		m["scopes_supported"] = s.opts.Scopes
	}
	authMethods := []string{AuthMethodNone, AuthMethodClientSecretBasic, AuthMethodClientSecretPost}
	if s.opts.AllowCIMD { // private_key_jwt is available to metadata-document clients
		authMethods = append(authMethods, AuthMethodPrivateKeyJWT)
		m["token_endpoint_auth_signing_alg_values_supported"] = AssertionSigningAlgs
		m["revocation_endpoint_auth_signing_alg_values_supported"] = AssertionSigningAlgs
	}
	m["token_endpoint_auth_methods_supported"] = authMethods
	m["revocation_endpoint_auth_methods_supported"] = authMethods
	if s.opts.AllowDCR {
		m["registration_endpoint"] = s.endpoint(s.opts.RegisterPath)
	}
	return m
}

// MetadataHandler serves the authorization server metadata (RFC 8414).
func (s *Server) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, s.Metadata())
	})
}

// resolveClient finds a client by id: a CIMD URL (when allowed) or a stored
// (DCR / pre-registered) client.
func (s *Server) resolveClient(ctx context.Context, clientID string) (*resolvedClient, error) {
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	if IsCIMDClientID(clientID) {
		if !s.opts.AllowCIMD {
			return nil, errors.New("client metadata documents are not accepted by this server")
		}
		return s.opts.CIMD.Resolve(ctx, clientID)
	}
	c, err := s.store.GetClient(ctx, clientID)
	if errors.Is(err, identity.ErrNotFound) {
		return nil, errors.New("unknown client_id")
	}
	if err != nil {
		return nil, err
	}
	return &resolvedClient{ID: c.ClientID, Name: c.Name, RedirectURIs: c.RedirectURIs,
		AuthMethod: c.TokenEndpointAuthMethod, SecretHash: c.SecretHash, GrantTypes: c.GrantTypes}, nil
}

// resolveResource validates an RFC 8707 resource (defaulting to the single
// configured one) and returns its canonical form.
func (s *Server) resolveResource(raw string) (string, *Error) {
	if raw == "" {
		if len(s.resourceList) == 1 {
			return s.resourceList[0], nil
		}
		return "", errInvalidTarget("resource is required")
	}
	c, ok := canonicalResource(raw)
	if !ok {
		return "", errInvalidTarget("resource must be an absolute URI without fragment")
	}
	for _, r := range s.resourceList {
		if r == c {
			return c, nil
		}
	}
	return "", errInvalidTarget("resource is not served by this authorization server")
}

// resolveScopes validates requested scopes (defaulting when empty).
func (s *Server) resolveScopes(raw string) ([]string, *Error) {
	req := parseScopes(raw)
	if len(req) == 0 {
		if s.opts.DefaultScopes != nil {
			return append([]string(nil), s.opts.DefaultScopes...), nil
		}
		return append([]string(nil), s.opts.Scopes...), nil
	}
	for _, sc := range req {
		if !s.scopeSet[sc] {
			return nil, errInvalidScope("unknown scope: " + sc)
		}
	}
	return req, nil
}

// --- app-facing management (connected apps, GC) ---

// RegisterClient pre-registers a client programmatically (e.g. credentials a
// platform holds for your server). Same validation as DCR.
func (s *Server) RegisterClient(ctx context.Context, m ClientMetadata) (*ClientRegistration, error) {
	reg, e := s.register(ctx, m)
	if e != nil {
		return nil, e
	}
	return reg, nil
}

// ListGrants returns the user's OAuth grants ("connected apps").
func (s *Server) ListGrants(ctx context.Context, userID string) ([]Grant, error) {
	return s.store.ListUserGrants(ctx, userID)
}

// RevokeGrant revokes one grant of the user: its refresh token and every access
// token minted from it stop working immediately.
func (s *Server) RevokeGrant(ctx context.Context, userID, grantID string) error {
	g, err := s.store.GetGrant(ctx, grantID)
	if errors.Is(err, identity.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if g.UserID != userID {
		return identity.ErrNotFound
	}
	return s.store.DeleteGrant(ctx, grantID)
}

// RevokeClient disconnects a client from the user: all its grants and the
// remembered consent.
func (s *Server) RevokeClient(ctx context.Context, userID, clientID string) error {
	if _, err := s.store.DeleteUserClientGrants(ctx, userID, clientID); err != nil {
		return err
	}
	return s.store.DeleteConsent(ctx, userID, clientID)
}

// PurgeExpired deletes expired authorization codes and grants, and the
// recorded ids of expired client assertions (run it from a periodic job).
func (s *Server) PurgeExpired(ctx context.Context) (codes, grants int64, err error) {
	now := s.opts.Now()
	if codes, err = s.store.DeleteExpiredCodes(ctx, now); err != nil {
		return
	}
	if grants, err = s.store.DeleteExpiredGrants(ctx, now); err != nil {
		return
	}
	_, err = s.store.DeleteExpiredClientAssertions(ctx, now)
	return
}

// PurgeStaleClients deletes registered clients created before olderThan that
// have not been used since and hold no grants — DCR registers a client per
// fresh connection, so run this periodically.
func (s *Server) PurgeStaleClients(ctx context.Context, olderThan time.Time) (int64, error) {
	return s.store.DeleteStaleClients(ctx, olderThan)
}

// --- DCR rate limiter ---

type window struct {
	start time.Time
	n     int
}

type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[string]*window
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > 10000 {
		for k, w := range l.hits {
			if now.Sub(w.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	w := l.hits[ip]
	if w == nil || now.Sub(w.start) > l.window {
		l.hits[ip] = &window{start: now, n: 1}
		return true
	}
	if w.n >= l.limit {
		return false
	}
	w.n++
	return true
}

func newID() string { return uuid.NewString() }
