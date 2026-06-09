package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/terglos/go-idento/identity"
)

func TestPolicyEvaluate(t *testing.T) {
	p := &Principal{
		User:  &identity.User{EmailConfirmed: true},
		Roles: []string{"Editor"},
		Claims: jwt.MapClaims{
			"department": "eng",
		},
	}

	pass := NewPolicy("p").
		RequireRole("Editor").
		RequireClaim("department", "eng", "ops").
		RequireAssertion(func(pr *Principal) bool { return pr.User.EmailConfirmed })
	if !pass.Evaluate(p) {
		t.Fatal("expected policy to pass")
	}

	failRole := NewPolicy("p").RequireRole("Admin")
	if failRole.Evaluate(p) {
		t.Fatal("expected role requirement to fail")
	}

	failClaimValue := NewPolicy("p").RequireClaim("department", "sales")
	if failClaimValue.Evaluate(p) {
		t.Fatal("expected claim-value requirement to fail")
	}
}
