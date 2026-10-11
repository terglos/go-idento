package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/terglos/go-idento/identity"
)

// authzParams are the OAuth parameters carried through login and consent.
var authzParams = []string{"response_type", "client_id", "redirect_uri", "state", "scope",
	"code_challenge", "code_challenge_method", "resource"}

type authzRequest struct {
	v           url.Values // the original OAuth params only
	client      *resolvedClient
	redirectURI string
	state       string
	scopes      []string
	resource    string
	challenge   string
}

// AuthorizeHandler serves the authorization endpoint: GET starts the flow
// (login → consent), POST receives the consent decision.
func (s *Server) AuthorizeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The consent page must never be framed (clickjacking).
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		var params url.Values
		switch r.Method {
		case http.MethodGet:
			params = r.URL.Query()
		case http.MethodPost:
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				s.opts.RenderError(w, r, errInvalidRequest("malformed form"))
				return
			}
			params = r.PostForm
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		req, fatal, redirErr := s.parseAuthz(r.Context(), params)
		if fatal != nil {
			s.opts.RenderError(w, r, fatal) // never redirect to an unvalidated URI
			return
		}
		if redirErr != nil {
			s.redirectError(w, r, req, redirErr)
			return
		}

		userID, ok := s.currentUser(r)
		if !ok {
			returnTo := s.endpoint(s.opts.AuthorizePath) + "?" + req.v.Encode()
			http.Redirect(w, r, s.opts.LoginURL(r, returnTo), http.StatusFound)
			return
		}
		u, err := s.users.FindByID(r.Context(), userID)
		if err != nil || u == nil {
			returnTo := s.endpoint(s.opts.AuthorizePath) + "?" + req.v.Encode()
			http.Redirect(w, r, s.opts.LoginURL(r, returnTo), http.StatusFound)
			return
		}
		if s.users.IsLockedOut(u) {
			s.redirectError(w, r, req, oerr(http.StatusForbidden, "access_denied", "account is locked"))
			return
		}

		if r.Method == http.MethodPost {
			if !s.checkCSRF(params.Get("csrf_token"), userID, req) {
				s.opts.RenderError(w, r, errInvalidRequest("consent form expired or tampered; please retry"))
				return
			}
			if params.Get("decision") != "approve" {
				s.redirectError(w, r, req, oerr(http.StatusForbidden, "access_denied", "the user denied the request"))
				return
			}
			if err := s.saveConsent(r.Context(), userID, req); err != nil {
				s.redirectError(w, r, req, errServer("could not record consent"))
				return
			}
			s.issueCode(w, r, userID, req)
			return
		}

		// GET: skip the page when a remembered consent already covers the scopes.
		if c, err := s.store.GetConsent(r.Context(), userID, req.client.ID); err == nil &&
			containsAll(parseScopes(c.Scopes), req.scopes) {
			s.issueCode(w, r, userID, req)
			return
		} else if err != nil && !errors.Is(err, identity.ErrNotFound) {
			s.redirectError(w, r, req, errServer("consent lookup failed"))
			return
		}

		fields := url.Values{}
		for k, vs := range req.v {
			fields[k] = append([]string(nil), vs...)
		}
		fields.Set("csrf_token", s.csrfToken(userID, req))
		s.opts.RenderConsent(w, r, ConsentRequest{
			ClientID:     req.client.ID,
			ClientName:   req.client.Name,
			ClientHost:   req.client.DisplayHost,
			RedirectURI:  req.redirectURI,
			RedirectHost: hostOf(req.redirectURI),
			LoopbackOnly: allLoopback(req.client.RedirectURIs),
			Scopes:       req.scopes,
			Resource:     req.resource,
			UserID:       userID,
			Action:       s.endpoint(s.opts.AuthorizePath),
			Fields:       fields,
		})
	})
}

func (s *Server) currentUser(r *http.Request) (string, bool) {
	id, ok := s.opts.CurrentUser(r)
	return id, ok && id != ""
}

// parseAuthz validates an authorization request in two phases. Problems found
// before the client and redirect_uri are established are "fatal" (rendered as
// an error page); later problems are redirected to the client with error=.
func (s *Server) parseAuthz(ctx context.Context, all url.Values) (req *authzRequest, fatal, redirErr *Error) {
	v := url.Values{}
	for _, k := range authzParams {
		if vals, ok := all[k]; ok {
			if len(vals) > 1 {
				return nil, errInvalidRequest("parameter " + k + " is duplicated"), nil
			}
			v.Set(k, vals[0])
		}
	}
	req = &authzRequest{v: v, state: v.Get("state")}

	client, err := s.resolveClient(ctx, v.Get("client_id"))
	if err != nil {
		return nil, oerr(http.StatusBadRequest, "invalid_client", err.Error()), nil
	}
	req.client = client
	req.redirectURI = v.Get("redirect_uri")
	if req.redirectURI == "" {
		return nil, errInvalidRequest("redirect_uri is required"), nil
	}
	if !matchRedirectURI(client.RedirectURIs, req.redirectURI) {
		return nil, errInvalidRequest("redirect_uri is not registered for this client"), nil
	}

	// From here on the redirect URI is trusted: errors go back to the client.
	if v.Get("response_type") != "code" {
		return req, nil, oerr(http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
	}
	if len(client.GrantTypes) > 0 && !hasScope(client.GrantTypes, GrantTypeAuthorizationCode) {
		return req, nil, oerr(http.StatusBadRequest, "unauthorized_client", "client is not allowed to use the authorization code grant")
	}
	req.challenge = v.Get("code_challenge")
	switch {
	case req.challenge == "":
		return req, nil, errInvalidRequest("code_challenge is required (PKCE)")
	case v.Get("code_challenge_method") != "S256":
		return req, nil, errInvalidRequest("code_challenge_method must be S256")
	case !validChallenge(req.challenge):
		return req, nil, errInvalidRequest("malformed code_challenge")
	}
	scopes, e := s.resolveScopes(v.Get("scope"))
	if e != nil {
		return req, nil, e
	}
	req.scopes = scopes
	res, e := s.resolveResource(v.Get("resource"))
	if e != nil {
		return req, nil, e
	}
	req.resource = res
	return req, nil, nil
}

// redirectError sends an error to the client's validated redirect URI.
func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, req *authzRequest, e *Error) {
	q := url.Values{"error": {e.Code}}
	if e.Description != "" {
		q.Set("error_description", e.Description)
	}
	s.redirectTo(w, r, req, q)
}

func (s *Server) redirectTo(w http.ResponseWriter, r *http.Request, req *authzRequest, add url.Values) {
	u, err := url.Parse(req.redirectURI)
	if err != nil {
		s.opts.RenderError(w, r, errServer("bad redirect_uri"))
		return
	}
	q := u.Query()
	for k, vs := range add {
		q[k] = vs
	}
	if req.state != "" {
		q.Set("state", req.state)
	}
	q.Set("iss", s.issuer) // RFC 9207 mix-up protection
	u.RawQuery = q.Encode()
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, u.String(), status)
}

func (s *Server) saveConsent(ctx context.Context, userID string, req *authzRequest) error {
	now := s.opts.Now()
	scopes := req.scopes
	created := now
	if prev, err := s.store.GetConsent(ctx, userID, req.client.ID); err == nil {
		scopes = unionScopes(parseScopes(prev.Scopes), req.scopes)
		created = prev.CreatedAt
	}
	return s.store.SaveConsent(ctx, &Consent{UserID: userID, ClientID: req.client.ID,
		Scopes: joinScopes(scopes), CreatedAt: created, UpdatedAt: now})
}

// issueCode mints a single-use authorization code bound to the request and
// redirects back to the client.
func (s *Server) issueCode(w http.ResponseWriter, r *http.Request, userID string, req *authzRequest) {
	code := randomSecret(32)
	err := s.store.CreateCode(r.Context(), &Code{
		CodeHash:      hashSecret(code),
		ClientID:      req.client.ID,
		UserID:        userID,
		RedirectURI:   req.redirectURI,
		Scopes:        joinScopes(req.scopes),
		Resource:      req.resource,
		CodeChallenge: req.challenge,
		ExpiresAt:     s.opts.Now().Add(s.opts.CodeTTL),
	})
	if err != nil {
		s.redirectError(w, r, req, errServer("could not issue authorization code"))
		return
	}
	s.redirectTo(w, r, req, url.Values{"code": {code}})
}

// --- consent CSRF: an HMAC over the user and every authorization parameter ---

const csrfMaxAge = 15 * time.Minute

func (s *Server) csrfMAC(ts int64, userID string, req *authzRequest) []byte {
	mac := hmac.New(sha256.New, s.opts.CSRFKey)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	mac.Write(b[:])
	for _, part := range []string{userID, req.client.ID, req.redirectURI, joinScopes(req.scopes),
		req.resource, req.state, req.challenge} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}

func (s *Server) csrfToken(userID string, req *authzRequest) string {
	ts := s.opts.Now().Unix()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts))
	return base64.RawURLEncoding.EncodeToString(append(b[:], s.csrfMAC(ts, userID, req)...))
}

func (s *Server) checkCSRF(token, userID string, req *authzRequest) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(raw[:8]))
	age := s.opts.Now().Sub(time.Unix(ts, 0))
	if age < -time.Minute || age > csrfMaxAge {
		return false
	}
	return hmac.Equal(raw[8:], s.csrfMAC(ts, userID, req))
}

// --- default pages ---

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize {{.App}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
.box{border:1px solid #ddd;border-radius:8px;padding:1.5rem}.warn{background:#fff4e5;border:1px solid #f0b46b;padding:.75rem;border-radius:6px}
code{background:#f3f3f3;padding:.1rem .3rem;border-radius:4px}button{font-size:1rem;padding:.6rem 1.2rem;margin-right:.5rem;border-radius:6px;border:1px solid #888;cursor:pointer}
.approve{background:#1a1a1a;color:#fff;border-color:#1a1a1a}</style></head>
<body><div class="box">
<h1>Authorize <strong>{{.App}}</strong>?</h1>
{{if .Name}}<p>The application identifies itself as “{{.Name}}”.</p>{{end}}
<p>It will be redirected to <code>{{.RedirectHost}}</code>.</p>
{{if .LoopbackOnly}}<p class="warn">This application receives the authorization on your own computer (localhost). Only continue if you started this connection yourself.</p>{{end}}
{{if .Scopes}}<p>It is requesting:</p><ul>{{range .Scopes}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
<p>Access to: <code>{{.Resource}}</code></p>
<form method="post" action="{{.Action}}">
{{range $k, $vs := .Fields}}{{range $vs}}<input type="hidden" name="{{$k}}" value="{{.}}">{{end}}{{end}}
<button class="approve" type="submit" name="decision" value="approve">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></div></body></html>`))

// DefaultConsentPage is a minimal, safe consent page. Apps normally provide
// their own styled page through Options.RenderConsent; it must show the same
// information (client host / name, redirect host, loopback warning, scopes).
func DefaultConsentPage(w http.ResponseWriter, _ *http.Request, c ConsentRequest) {
	app := c.ClientHost
	if app == "" {
		app = c.ClientName
	}
	if app == "" {
		app = c.ClientID
	}
	name := c.ClientName
	if name == app {
		name = ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(w, map[string]any{
		"App": app, "Name": name, "RedirectHost": c.RedirectHost, "LoopbackOnly": c.LoopbackOnly,
		"Scopes": c.Scopes, "Resource": c.Resource, "Action": c.Action, "Fields": c.Fields,
	})
}

func defaultErrorPage(w http.ResponseWriter, _ *http.Request, e *Error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	status := e.Status
	if status == 0 || status == http.StatusUnauthorized {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	msg := "Authorization request error: " + e.Code
	if e.Description != "" {
		msg += " — " + e.Description
	}
	_, _ = w.Write([]byte(strings.TrimSpace(msg) + "\n"))
}
