package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client assertion (RFC 7523 §2.2, private_key_jwt) support.

// AssertionSigningAlgs are the client-assertion algorithms the server accepts.
var AssertionSigningAlgs = []string{"RS256", "ES256"}

const (
	// assertionLeeway tolerates clock skew between client and server.
	assertionLeeway = 30 * time.Second
	maxJTILen       = 256
)

// clientKey is one public verification key of a client.
type clientKey struct {
	kid, alg string
	key      crypto.PublicKey
}

// rawJWK is the subset of RFC 7517 members used to build a public key. The
// private members are decoded only to refuse documents that leak them.
type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	P   string `json:"p"`
}

// parseJWKS turns a JWK Set into the usable signing keys: RSA (≥ 2048 bits) and
// EC P-256. Keys for other uses or unsupported types are skipped; a set
// carrying private key material is refused outright.
func parseJWKS(data []byte) ([]clientKey, error) {
	var set struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("jwks is not a valid JWK Set")
	}
	var out []clientKey
	for _, k := range set.Keys {
		if k.D != "" || k.P != "" {
			return nil, errors.New("jwks must contain only public keys")
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var pub crypto.PublicKey
		switch k.Kty {
		case "RSA":
			pub = rsaFromJWK(k)
		case "EC":
			pub = ecFromJWK(k)
		}
		if pub != nil {
			out = append(out, clientKey{kid: k.Kid, alg: k.Alg, key: pub})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks has no usable RS256/ES256 signing key")
	}
	return out, nil
}

func b64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	return b
}

func rsaFromJWK(k rawJWK) crypto.PublicKey {
	n, e := b64(k.N), b64(k.E)
	if len(n) == 0 || len(e) == 0 || len(e) > 4 {
		return nil
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < 2048 || pub.E < 3 || pub.E%2 == 0 {
		return nil
	}
	return pub
}

func ecFromJWK(k rawJWK) crypto.PublicKey {
	if k.Crv != "P-256" {
		return nil
	}
	x, y := b64(k.X), b64(k.Y)
	if len(x) == 0 || len(x) > 32 || len(y) == 0 || len(y) > 32 {
		return nil
	}
	// Uncompressed SEC 1 point: 0x04 || X || Y, each left-padded to 32 bytes.
	point := make([]byte, 65)
	point[0] = 4
	copy(point[33-len(x):33], x)
	copy(point[65-len(y):], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point) // checks the point is on the curve
	if err != nil {
		return nil
	}
	return pub
}

// fits reports whether k can verify a token signed with alg.
func (k clientKey) fits(alg string) bool {
	if k.alg != "" && k.alg != alg {
		return false
	}
	switch k.key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256"
	case *ecdsa.PublicKey:
		return alg == "ES256"
	}
	return false
}

// validateJWKSURI applies the fetch rules for a jwks_uri found in a metadata
// document: https, a host, no credentials or fragment. Special-use addresses
// are refused at dial time like the document itself (draft §8.6).
func validateJWKSURI(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("invalid jwks_uri")
	case u.Scheme != "https":
		return errors.New("jwks_uri must use https")
	case u.Hostname() == "":
		return errors.New("jwks_uri must have a host")
	case u.User != nil:
		return errors.New("jwks_uri must not contain credentials")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return errors.New("jwks_uri must not contain a fragment")
	}
	return nil
}

type jwksEntry struct {
	keys             []clientKey
	fetched, expires time.Time
}

// jwks returns the keys published at uri, from cache when fresh. refresh asks
// for a re-fetch (an unknown kid: the client may have rotated keys); it is
// honored at most once per JWKSMinRefresh per URI.
func (f *CIMDFetcher) jwks(ctx context.Context, uri string, refresh bool) ([]clientKey, error) {
	now := time.Now()
	minRefresh := f.JWKSMinRefresh
	if minRefresh <= 0 {
		minRefresh = 30 * time.Second
	}
	f.mu.Lock()
	e, ok := f.jwksCache[uri]
	f.mu.Unlock()
	if ok && now.Before(e.expires) && (!refresh || now.Sub(e.fetched) < minRefresh) {
		return e.keys, nil
	}
	if err := validateJWKSURI(uri); err != nil {
		return nil, err
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/jwk-set+json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching jwks_uri: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks_uri fetch returned HTTP %d", resp.StatusCode)
	}
	max := f.MaxJWKSBytes
	if max <= 0 {
		max = 64 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading jwks_uri: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("jwks_uri document exceeds %d bytes", max)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	if ttl, ok := f.cacheTTL(resp.Header.Get("Cache-Control")); ok {
		f.mu.Lock()
		if f.jwksCache == nil || len(f.jwksCache) > 1000 {
			f.jwksCache = map[string]jwksEntry{}
		}
		f.jwksCache[uri] = jwksEntry{keys: keys, fetched: now, expires: now.Add(ttl)}
		f.mu.Unlock()
	}
	return keys, nil
}

// authenticateAssertion verifies an RFC 7523 client assertion presented at
// endpoint (the token or revocation endpoint URL) and returns the client.
// Checks: client_assertion_type; iss = sub = client_id (and = the client_id
// parameter when sent); a client registered for private_key_jwt; signature by
// one of the client's keys with an accepted algorithm (the document's
// token_endpoint_auth_signing_alg when declared); aud = issuer, token endpoint
// or this endpoint; exp present, not past and within ClientAssertionMaxLifetime;
// iat/nbf not in the future; jti present and never seen before (replay).
func (s *Server) authenticateAssertion(ctx context.Context, endpoint string, f url.Values) (*resolvedClient, *Error) {
	if f.Get("client_assertion_type") != ClientAssertionTypeJWTBearer {
		return nil, errInvalidClient("unsupported client_assertion_type")
	}
	assertion := f.Get("client_assertion")
	if assertion == "" {
		return nil, errInvalidRequest("client_assertion is required")
	}
	unverified, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, errInvalidClient("malformed client assertion")
	}
	uc, _ := unverified.Claims.(jwt.MapClaims)
	clientID, _ := uc["sub"].(string)
	if iss, _ := uc["iss"].(string); clientID == "" || iss != clientID {
		return nil, errInvalidClient("client assertion iss and sub must both be the client_id")
	}
	if id := f.Get("client_id"); id != "" && id != clientID {
		return nil, errInvalidClient("client_id does not match the client assertion")
	}
	client, err := s.resolveClient(ctx, clientID)
	if err != nil {
		return nil, errInvalidClient(err.Error())
	}
	if client.AuthMethod != AuthMethodPrivateKeyJWT {
		return nil, errInvalidClient("client is not registered for private_key_jwt")
	}
	algs := AssertionSigningAlgs
	if client.SigningAlg != "" {
		algs = []string{client.SigningAlg}
	}
	keyfunc := func(t *jwt.Token) (any, error) {
		alg := t.Method.Alg()
		kid, _ := t.Header["kid"].(string)
		pick := func(keys []clientKey) jwt.VerificationKeySet {
			var set jwt.VerificationKeySet
			for _, k := range keys {
				if k.fits(alg) && (kid == "" || k.kid == kid) {
					set.Keys = append(set.Keys, k.key)
				}
			}
			return set
		}
		keys := client.Keys
		if client.JWKSURI != "" {
			fetched, ferr := s.opts.CIMD.jwks(ctx, client.JWKSURI, false)
			if ferr != nil {
				return nil, ferr
			}
			keys = fetched
		}
		set := pick(keys)
		if len(set.Keys) == 0 && kid != "" && client.JWKSURI != "" {
			fetched, ferr := s.opts.CIMD.jwks(ctx, client.JWKSURI, true)
			if ferr != nil {
				return nil, ferr
			}
			set = pick(fetched)
		}
		if len(set.Keys) == 0 {
			return nil, errors.New("no client key matches the assertion")
		}
		return set, nil
	}
	audiences := []string{s.issuer, s.endpoint(s.opts.TokenPath)}
	if endpoint != audiences[1] {
		audiences = append(audiences, endpoint)
	}
	parsed, err := jwt.Parse(assertion, keyfunc,
		jwt.WithValidMethods(algs), jwt.WithIssuer(clientID), jwt.WithSubject(clientID),
		jwt.WithAudience(audiences...), jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithLeeway(assertionLeeway), jwt.WithTimeFunc(s.opts.Now))
	if err != nil || !parsed.Valid {
		return nil, errInvalidClient(assertionError(err))
	}
	claims := parsed.Claims.(jwt.MapClaims)
	exp, _ := claims.GetExpirationTime()
	if exp.Sub(s.opts.Now()) > s.opts.ClientAssertionMaxLifetime {
		return nil, errInvalidClient("client assertion lifetime is too long")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || len(jti) > maxJTILen {
		return nil, errInvalidClient("client assertion must carry a jti")
	}
	fresh, err := s.store.UseClientAssertion(ctx, clientID, jti, exp.Add(assertionLeeway))
	if err != nil {
		return nil, errServer("could not record the client assertion")
	}
	if !fresh {
		return nil, errInvalidClient("client assertion was already used")
	}
	return client, nil
}

// assertionError explains why a client assertion failed validation, so client
// developers can fix their integration.
func assertionError(err error) string {
	switch {
	case err == nil:
		return "invalid client assertion"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		// The keyfunc's own error (no matching key, jwks_uri unreachable, …).
		msg := strings.TrimPrefix(err.Error(), jwt.ErrTokenUnverifiable.Error()+": ")
		return "client assertion not verifiable: " + strings.TrimPrefix(msg, "error while executing keyfunc: ")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "client assertion signature or algorithm not accepted (" + strings.Join(AssertionSigningAlgs, ", ") + " with the client's published keys)"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "client assertion aud must be the issuer or the token endpoint URL"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "client assertion has expired"
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return "client assertion must carry exp"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued), errors.Is(err, jwt.ErrTokenNotValidYet):
		return "client assertion is not valid yet (iat/nbf in the future)"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer), errors.Is(err, jwt.ErrTokenInvalidSubject):
		return "client assertion iss and sub must both be the client_id"
	}
	return "invalid client assertion"
}
