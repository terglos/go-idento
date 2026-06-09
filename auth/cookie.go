package auth

import (
	"net/http"
	"time"
)

// CookieAuth stores the access token in an HttpOnly cookie for browser
// sessions, alongside the bearer-token flow used by APIs.
type CookieAuth struct {
	Name     string
	Path     string
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
}

// DefaultCookieAuth returns secure, HttpOnly, Lax defaults.
func DefaultCookieAuth() *CookieAuth {
	return &CookieAuth{
		Name:     ".GoIdentity.Auth",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   24 * time.Hour,
	}
}

func (c *CookieAuth) read(r *http.Request) string {
	if c == nil {
		return ""
	}
	ck, err := r.Cookie(c.Name)
	if err != nil {
		return ""
	}
	return ck.Value
}

// Write sets the auth cookie (call after a successful sign-in).
func (c *CookieAuth) Write(w http.ResponseWriter, accessToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    accessToken,
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		Expires:  time.Now().Add(c.MaxAge),
	})
}

// Clear removes the auth cookie (sign-out).
func (c *CookieAuth) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     c.Path,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		MaxAge:   -1,
	})
}
