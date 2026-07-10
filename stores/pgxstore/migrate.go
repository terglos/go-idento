package pgxstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
)

// Migrate creates the schema and tables for the resolved naming. It is
// idempotent (CREATE ... IF NOT EXISTS) and adds ON DELETE CASCADE foreign keys
// from the satellite tables to users/roles, so deleting a user or role cleans up
// its memberships, claims, logins and tokens (referential integrity).
//
//	pgxstore.Migrate(ctx, pool)                                  // canonical
//	pgxstore.Migrate(ctx, pool, pgxstore.WithSchema("auth"),
//	                            pgxstore.WithTablePrefix("app_")) // auth.app_identity_users, ...
func Migrate(ctx context.Context, db *pgxpool.Pool, opts ...Option) error {
	n := resolve(opts...)
	if err := n.Validate(); err != nil {
		return err
	}
	_, err := db.Exec(ctx, buildDDL(n))
	return err
}

func buildDDL(n identity.Naming) string {
	U := n.Qualify(n.Tables.Users)
	R := n.Qualify(n.Tables.Roles)
	UR := n.Qualify(n.Tables.UserRoles)
	UC := n.Qualify(n.Tables.UserClaims)
	RC := n.Qualify(n.Tables.RoleClaims)
	UL := n.Qualify(n.Tables.UserLogins)
	UT := n.Qualify(n.Tables.UserTokens)
	// Index names are unqualified (created in the table's schema) and derived
	// from the physical table name to stay unique.
	ix := func(prefix, base, suffix string) string { return prefix + "_" + base + "_" + suffix }

	var b strings.Builder
	if n.Schema != "" {
		fmt.Fprintf(&b, "CREATE SCHEMA IF NOT EXISTS %s;\n", n.Schema)
	}
	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	id                     varchar(36) PRIMARY KEY,
	user_name              varchar(256) NOT NULL DEFAULT '',
	normalized_user_name   varchar(256) NOT NULL DEFAULT '',
	email                  varchar(256) NOT NULL DEFAULT '',
	normalized_email       varchar(256) NOT NULL DEFAULT '',
	email_confirmed        boolean      NOT NULL DEFAULT false,
	password_hash          varchar(256) NOT NULL DEFAULT '',
	security_stamp         varchar(64)  NOT NULL DEFAULT '',
	concurrency_stamp      varchar(64)  NOT NULL DEFAULT '',
	phone_number           varchar(32)  NOT NULL DEFAULT '',
	phone_number_confirmed boolean      NOT NULL DEFAULT false,
	two_factor_enabled     boolean      NOT NULL DEFAULT false,
	lockout_end            timestamptz,
	lockout_enabled        boolean      NOT NULL DEFAULT false,
	access_failed_count    integer      NOT NULL DEFAULT 0,
	attributes             jsonb        NOT NULL DEFAULT '{}'::jsonb,
	is_anonymous           boolean      NOT NULL DEFAULT false,
	created_at             timestamptz  NOT NULL DEFAULT now(),
	updated_at             timestamptz  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (normalized_user_name);
CREATE INDEX IF NOT EXISTS %s ON %s (normalized_email);
CREATE INDEX IF NOT EXISTS %s ON %s (created_at) WHERE is_anonymous;
`, U, ix("ux", n.Tables.Users, "uname"), U, ix("ix", n.Tables.Users, "email"), U, ix("ix", n.Tables.Users, "guest"), U)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	id                varchar(36) PRIMARY KEY,
	name              varchar(256) NOT NULL DEFAULT '',
	normalized_name   varchar(256) NOT NULL DEFAULT '',
	concurrency_stamp varchar(64)  NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (normalized_name);
`, R, ix("ux", n.Tables.Roles, "name"), R)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	user_id varchar(36) NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	role_id varchar(36) NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	PRIMARY KEY (user_id, role_id)
);
`, UR, U, R)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	id          bigserial PRIMARY KEY,
	user_id     varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	claim_type  varchar(256) NOT NULL DEFAULT '',
	claim_value varchar(256) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS %s ON %s (user_id);
`, UC, U, ix("ix", n.Tables.UserClaims, "user"), UC)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	id          bigserial PRIMARY KEY,
	role_id     varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	claim_type  varchar(256) NOT NULL DEFAULT '',
	claim_value varchar(256) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS %s ON %s (role_id);
`, RC, R, ix("ix", n.Tables.RoleClaims, "role"), RC)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	login_provider        varchar(128) NOT NULL,
	provider_key          varchar(128) NOT NULL,
	provider_display_name varchar(128) NOT NULL DEFAULT '',
	user_id               varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	PRIMARY KEY (login_provider, provider_key)
);
CREATE INDEX IF NOT EXISTS %s ON %s (user_id);
`, UL, U, ix("ix", n.Tables.UserLogins, "user"), UL)

	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	user_id        varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	login_provider varchar(128) NOT NULL,
	name           varchar(128) NOT NULL,
	value          text         NOT NULL DEFAULT '',
	PRIMARY KEY (user_id, login_provider, name)
);
`, UT, U)

	AK := n.Qualify(n.Tables.APIKeys)
	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	id           varchar(36)  PRIMARY KEY,
	user_id      varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	name         varchar(256) NOT NULL DEFAULT '',
	prefix       varchar(32)  NOT NULL DEFAULT '',
	key_hash     varchar(128) NOT NULL,
	scopes       jsonb        NOT NULL DEFAULT '[]'::jsonb,
	expires_at   timestamptz,
	last_used_at timestamptz,
	revoked_at   timestamptz,
	created_at   timestamptz  NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (key_hash);
CREATE INDEX IF NOT EXISTS %s ON %s (user_id);
`, AK, U, ix("ux", n.Tables.APIKeys, "hash"), AK, ix("ix", n.Tables.APIKeys, "user"), AK)

	RT := n.Qualify(n.Tables.RefreshTokens)
	fmt.Fprintf(&b, `CREATE TABLE IF NOT EXISTS %s (
	session_id   varchar(36)  PRIMARY KEY,
	user_id      varchar(36)  NOT NULL REFERENCES %s(id) ON DELETE CASCADE,
	token_hash   varchar(128) NOT NULL,
	name         varchar(256) NOT NULL DEFAULT '',
	expires_at   timestamptz  NOT NULL,
	created_at   timestamptz  NOT NULL DEFAULT now(),
	last_used_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s (token_hash);
CREATE INDEX IF NOT EXISTS %s ON %s (user_id);
CREATE INDEX IF NOT EXISTS %s ON %s (expires_at);
`, RT, U, ix("ux", n.Tables.RefreshTokens, "hash"), RT, ix("ix", n.Tables.RefreshTokens, "user"), RT, ix("ix", n.Tables.RefreshTokens, "exp"), RT)

	return b.String()
}
