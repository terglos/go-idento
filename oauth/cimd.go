package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CIMDFetcher resolves Client ID Metadata Documents (an HTTPS URL used as
// client_id) with the protections the draft requires: https only, no automatic
// redirects, special-use/private IPs refused at dial time (so DNS rebinding
// can't bypass the check), a short timeout, a small size cap, and a cache that
// honors Cache-Control and never stores failures. The zero value is not usable;
// call NewCIMDFetcher.
type CIMDFetcher struct {
	// Timeout bounds the whole fetch (default 5s).
	Timeout time.Duration
	// MaxBytes caps the document size (default 5 KB).
	MaxBytes int64
	// DefaultTTL applies when the response has no max-age (default 5m); cache
	// lifetimes are clamped to [MinTTL, MaxTTL] (default 1m / 24h).
	DefaultTTL, MinTTL, MaxTTL time.Duration
	// AllowPrivateNetworks disables the special-use IP block. Development and
	// tests only — never enable it in production.
	AllowPrivateNetworks bool
	// TLSClientConfig customizes TLS (e.g. test root CAs). Nil = system roots.
	TLSClientConfig *tls.Config

	once   sync.Once
	client *http.Client
	mu     sync.Mutex
	cache  map[string]cimdEntry
}

type cimdEntry struct {
	client  *resolvedClient
	expires time.Time
}

// NewCIMDFetcher returns a fetcher with the recommended defaults.
func NewCIMDFetcher() *CIMDFetcher {
	return &CIMDFetcher{
		Timeout:    5 * time.Second,
		MaxBytes:   5 * 1024,
		DefaultTTL: 5 * time.Minute,
		MinTTL:     time.Minute,
		MaxTTL:     24 * time.Hour,
	}
}

// IsCIMDClientID reports whether a client_id is a Client ID Metadata Document
// URL (as opposed to a registered client id).
func IsCIMDClientID(clientID string) bool {
	return strings.HasPrefix(strings.ToLower(clientID), "https://")
}

// validateCIMDURL enforces the client identifier URL rules: https, a host, a
// non-root path, no userinfo, no fragment, no dot segments.
func validateCIMDURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id URL")
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("client_id URL must use https")
	case u.Host == "" || u.Hostname() == "":
		return nil, fmt.Errorf("client_id URL must have a host")
	case u.User != nil:
		return nil, fmt.Errorf("client_id URL must not contain credentials")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return nil, fmt.Errorf("client_id URL must not contain a fragment")
	case u.Path == "" || u.Path == "/":
		return nil, fmt.Errorf("client_id URL must contain a path")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." || strings.EqualFold(seg, "%2e") || strings.EqualFold(seg, "%2e%2e") {
			return nil, fmt.Errorf("client_id URL must not contain dot segments")
		}
	}
	return u, nil
}

// blockedPrefixes are special-use ranges (RFC 6890 and friends) that a metadata
// fetch must never reach.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isBlockedIP(addr netip.Addr) bool {
	addr = addr.Unmap() // judge IPv4-mapped IPv6 by its IPv4 address
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// dialControl rejects connections to special-use addresses. It runs on the
// address actually being dialed (after DNS resolution), which also defeats DNS
// rebinding.
func dialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("oauth: refusing non-IP dial target %q", host)
	}
	if isBlockedIP(addr) {
		return fmt.Errorf("oauth: refusing to fetch client metadata from special-use address %s", addr)
	}
	return nil
}

func (f *CIMDFetcher) httpClient() *http.Client {
	f.once.Do(func() {
		dialer := &net.Dialer{Timeout: f.Timeout}
		if !f.AllowPrivateNetworks {
			dialer.Control = dialControl
		}
		f.client = &http.Client{
			Timeout: f.Timeout,
			Transport: &http.Transport{
				Proxy:                 nil, // a proxy would bypass the IP check
				DialContext:           dialer.DialContext,
				TLSClientConfig:       f.TLSClientConfig,
				TLSHandshakeTimeout:   f.Timeout,
				ResponseHeaderTimeout: f.Timeout,
				MaxIdleConns:          10,
				IdleConnTimeout:       30 * time.Second,
			},
			// The draft: the AS MUST NOT automatically follow redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return f.client
}

// cimdDocument is the subset of client metadata the server uses.
type cimdDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientSecret            *string  `json:"client_secret"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at"`
}

// Resolve fetches (or returns the cached) metadata document for a CIMD
// client_id and validates it.
func (f *CIMDFetcher) Resolve(ctx context.Context, clientID string) (*resolvedClient, error) {
	u, err := validateCIMDURL(clientID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	f.mu.Lock()
	if e, ok := f.cache[clientID]; ok && now.Before(e.expires) {
		f.mu.Unlock()
		return e.client, nil
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata fetch returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading client metadata: %w", err)
	}
	if int64(len(body)) > f.MaxBytes {
		return nil, fmt.Errorf("client metadata document exceeds %d bytes", f.MaxBytes)
	}
	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("client metadata is not valid JSON")
	}
	rc, err := validateCIMDDocument(clientID, &doc)
	if err != nil {
		return nil, err
	}
	if ttl, ok := f.cacheTTL(resp.Header.Get("Cache-Control")); ok {
		f.mu.Lock()
		if f.cache == nil {
			f.cache = map[string]cimdEntry{}
		}
		if len(f.cache) > 1000 { // bound memory: drop expired, then everything
			for k, e := range f.cache {
				if now.After(e.expires) {
					delete(f.cache, k)
				}
			}
			if len(f.cache) > 1000 {
				f.cache = map[string]cimdEntry{}
			}
		}
		f.cache[clientID] = cimdEntry{client: rc, expires: now.Add(ttl)}
		f.mu.Unlock()
	}
	return rc, nil
}

func validateCIMDDocument(clientID string, d *cimdDocument) (*resolvedClient, error) {
	if d.ClientID != clientID {
		return nil, errors.New("client metadata client_id does not match the document URL")
	}
	if d.ClientSecret != nil || d.ClientSecretExpiresAt != nil {
		return nil, errors.New("client metadata must not contain a client secret")
	}
	switch d.TokenEndpointAuthMethod {
	case "", AuthMethodNone:
	default:
		return nil, fmt.Errorf("unsupported token_endpoint_auth_method %q for a metadata-document client (only \"none\")", d.TokenEndpointAuthMethod)
	}
	if len(d.RedirectURIs) == 0 {
		return nil, errors.New("client metadata must list redirect_uris")
	}
	for _, r := range d.RedirectURIs {
		if err := validateRedirectURI(r); err != nil {
			return nil, err
		}
	}
	if len(d.GrantTypes) > 0 && !hasScope(d.GrantTypes, GrantTypeAuthorizationCode) {
		return nil, errors.New("client metadata grant_types must include authorization_code")
	}
	if len(d.ResponseTypes) > 0 && !hasScope(d.ResponseTypes, "code") {
		return nil, errors.New("client metadata response_types must include code")
	}
	name := strings.TrimSpace(d.ClientName)
	if len(name) > 256 {
		name = name[:256]
	}
	return &resolvedClient{
		ID:           clientID,
		Name:         name,
		DisplayHost:  hostOf(clientID),
		RedirectURIs: d.RedirectURIs,
		AuthMethod:   AuthMethodNone,
		CIMD:         true,
	}, nil
}

// cacheTTL derives the cache lifetime from Cache-Control: no-store/no-cache
// disables caching; max-age is clamped; absent → DefaultTTL.
func (f *CIMDFetcher) cacheTTL(cc string) (time.Duration, bool) {
	cc = strings.ToLower(cc)
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") {
		return 0, false
	}
	ttl := f.DefaultTTL
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	if ttl < f.MinTTL {
		ttl = f.MinTTL
	}
	if ttl > f.MaxTTL {
		ttl = f.MaxTTL
	}
	return ttl, ttl > 0
}
