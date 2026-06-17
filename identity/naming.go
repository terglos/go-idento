package identity

import "fmt"

// identRe matches a safe, unquoted SQL identifier: a letter or underscore
// followed by letters, digits or underscores. Stores interpolate table/schema
// names into SQL (identifiers can't be bound as parameters), so every
// configured name must pass this check to rule out injection.
func isValidIdentifier(s string) bool {
	if s == "" || len(s) > 63 { // 63 = Postgres NAMEDATALEN-1
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// TableNames holds the physical table name for each identity table. It is the
// single source of truth a store uses to build its SQL, so every reference
// (including joins) stays consistent. Start from [DefaultTableNames] and tweak,
// or use a store option such as WithTablePrefix / WithTableNames.
type TableNames struct {
	Users      string
	Roles      string
	UserRoles  string
	UserClaims string
	RoleClaims string
	UserLogins string
	UserTokens string
	APIKeys    string
}

// DefaultTableNames returns the canonical identity_* names.
func DefaultTableNames() TableNames {
	return TableNames{
		Users:      "identity_users",
		Roles:      "identity_roles",
		UserRoles:  "identity_user_roles",
		UserClaims: "identity_user_claims",
		RoleClaims: "identity_role_claims",
		UserLogins: "identity_user_logins",
		UserTokens: "identity_user_tokens",
		APIKeys:    "identity_api_keys",
	}
}

// WithPrefix returns a copy with prefix prepended to every table name, e.g.
// WithPrefix("app_") -> app_identity_users. Combine with a custom base set for
// full control.
func (n TableNames) WithPrefix(prefix string) TableNames {
	return TableNames{
		Users:      prefix + n.Users,
		Roles:      prefix + n.Roles,
		UserRoles:  prefix + n.UserRoles,
		UserClaims: prefix + n.UserClaims,
		RoleClaims: prefix + n.RoleClaims,
		UserLogins: prefix + n.UserLogins,
		UserTokens: prefix + n.UserTokens,
		APIKeys:    prefix + n.APIKeys,
	}
}

// Naming is the complete physical-layout config: an optional schema/namespace
// plus the per-table names. Stores resolve identifiers through [Naming.Qualify]
// so the schema is applied uniformly.
type Naming struct {
	Schema string // optional, e.g. "auth"; empty = connection default / search_path
	Tables TableNames
}

// DefaultNaming returns the canonical layout (no explicit schema).
func DefaultNaming() Naming { return Naming{Tables: DefaultTableNames()} }

// Validate checks that the schema (when set) and every table name are safe SQL
// identifiers. Stores should call it before running migrations or building SQL,
// since identifiers are interpolated rather than parameter-bound. It returns an
// error wrapping [ErrInvalidIdentifier] naming the offending value.
func (n Naming) Validate() error {
	if n.Schema != "" && !isValidIdentifier(n.Schema) {
		return fmt.Errorf("%w: schema %q", ErrInvalidIdentifier, n.Schema)
	}
	for label, name := range map[string]string{
		"Users": n.Tables.Users, "Roles": n.Tables.Roles, "UserRoles": n.Tables.UserRoles,
		"UserClaims": n.Tables.UserClaims, "RoleClaims": n.Tables.RoleClaims,
		"UserLogins": n.Tables.UserLogins, "UserTokens": n.Tables.UserTokens,
		"APIKeys": n.Tables.APIKeys,
	} {
		if !isValidIdentifier(name) {
			return fmt.Errorf("%w: table %s=%q", ErrInvalidIdentifier, label, name)
		}
	}
	return nil
}

// Qualify returns the table identifier as the store should reference it,
// prefixing the schema when one is configured ("schema"."table" style is left
// to the store; this returns schema.table which both pgx and GORM accept).
func (n Naming) Qualify(table string) string {
	if n.Schema != "" {
		return n.Schema + "." + table
	}
	return table
}
