package identity

import (
	"errors"
	"testing"
)

func TestNamingValidate(t *testing.T) {
	// Canonical defaults are valid.
	if err := DefaultNaming().Validate(); err != nil {
		t.Fatalf("default naming should be valid: %v", err)
	}
	// A custom schema + prefix made of safe identifiers is valid.
	ok := Naming{Schema: "auth", Tables: DefaultTableNames().WithPrefix("app_")}
	if err := ok.Validate(); err != nil {
		t.Fatalf("auth.app_* naming should be valid: %v", err)
	}

	bad := []Naming{
		{Schema: "auth; DROP TABLE users", Tables: DefaultTableNames()},
		{Tables: DefaultTableNames().WithPrefix("a-b ")},
		{Tables: TableNames{Users: "users\"; --"}},
		{Tables: TableNames{}}, // empty names are not valid identifiers
		{Schema: "1schema", Tables: DefaultTableNames()},
	}
	for i, n := range bad {
		if err := n.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
			t.Fatalf("case %d: expected ErrInvalidIdentifier, got %v", i, err)
		}
	}
}
