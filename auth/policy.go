package auth

import (
	"net/http"
	"strings"
)

// Requirement is a single condition a principal must satisfy. A Policy is an
// AND of requirements.
type Requirement func(*Principal) bool

// Policy is a named set of requirements (all must pass).
type Policy struct {
	Name         string
	Requirements []Requirement
}

// NewPolicy starts building a policy. Chain Require* methods, e.g.:
//
//	auth.NewPolicy("AdultEditor").
//	    RequireRole("Editor").
//	    RequireClaim("age", "18", "19", "20"). // any of
//	    RequireAssertion(func(p *auth.Principal) bool { return p.User.EmailConfirmed })
func NewPolicy(name string) *Policy { return &Policy{Name: name} }

// RequireRole adds a role requirement (any of the given roles satisfies it).
func (p *Policy) RequireRole(roles ...string) *Policy {
	p.Requirements = append(p.Requirements, func(pr *Principal) bool {
		for _, r := range roles {
			if pr.HasRole(r) {
				return true
			}
		}
		return false
	})
	return p
}

// RequireClaim requires a claim of claimType; if allowedValues are given, the
// claim's value must be one of them.
func (p *Policy) RequireClaim(claimType string, allowedValues ...string) *Policy {
	p.Requirements = append(p.Requirements, func(pr *Principal) bool {
		v, ok := pr.ClaimValue(claimType)
		if !ok {
			return false
		}
		if len(allowedValues) == 0 {
			return true
		}
		for _, a := range allowedValues {
			if v == a {
				return true
			}
		}
		return false
	})
	return p
}

// RequireAssertion adds an arbitrary predicate.
func (p *Policy) RequireAssertion(fn func(*Principal) bool) *Policy {
	p.Requirements = append(p.Requirements, fn)
	return p
}

// Evaluate reports whether the principal satisfies every requirement.
func (p *Policy) Evaluate(pr *Principal) bool {
	for _, req := range p.Requirements {
		if !req(pr) {
			return false
		}
	}
	return true
}

// ClaimValue returns the first claim value of the given type from the token.
func (pr *Principal) ClaimValue(claimType string) (string, bool) {
	v, ok := pr.Claims[claimType]
	if !ok {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case []interface{}:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// HasClaim reports whether the principal carries claimType (optionally with a
// specific value).
func (pr *Principal) HasClaim(claimType string, value ...string) bool {
	v, ok := pr.ClaimValue(claimType)
	if !ok {
		return false
	}
	if len(value) == 0 {
		return true
	}
	return strings.EqualFold(v, value[0])
}

// RequirePolicy is HTTP middleware enforcing a named policy on a route.
// 401 if anonymous, 403 if the policy fails.
func RequirePolicy(policy *Policy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !policy.Evaluate(p) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
