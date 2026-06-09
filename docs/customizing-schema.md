# Customizing the schema

go-idento keeps a canonical schema (the `identity_*` tables) but lets you bend
it to your database. From least to most invasive:

## 1. Canonical (zero config)

```go
gormstore.Migrate(db)                 // identity_users, identity_roles, ...
store := gormstore.NewUserStore(db)
// or pgxstore.Migrate(ctx, pool) / pgxstore.NewUserStore(pool)
```

## 2. Custom schema / namespace, prefix, or table names

Both the GORM and pgx stores accept options. The **same options** must be passed
to `Migrate`, `NewUserStore` and `NewRoleStore` so every query stays consistent.

```go
opts := []pgxstore.Option{
    pgxstore.WithSchema("auth"),        // -> auth.<table>           (Postgres/MySQL)
    pgxstore.WithTablePrefix("app_"),   // -> app_identity_users, ...
}
pgxstore.Migrate(ctx, pool, opts...)            // creates the schema + tables + FKs
users := pgxstore.NewUserStore(pool, opts...)
roles := pgxstore.NewRoleStore(pool, opts...)
```

```go
// GORM is identical (WithSchema is Postgres/MySQL; SQLite has no schemas):
opts := []gormstore.Option{gormstore.WithTablePrefix("app_")}
gormstore.Migrate(db, opts...)
users := gormstore.NewUserStore(db, opts...)
```

Rename tables individually with `WithTableNames`:

```go
names := identity.DefaultTableNames()
names.Users = "accounts"
names.Roles = "account_roles"
pgxstore.NewUserStore(pool, pgxstore.WithTableNames(names))
```

The pgx `Migrate` also adds **`ON DELETE CASCADE`** foreign keys from the
satellite tables to users/roles, so deleting a user/role cleans up its
memberships, claims, logins and tokens (referential integrity).

> The **sqlc** store (`stores/pgxsqlc`) uses compile-time-fixed SQL, so it cannot
> rename identifiers; use a connection `search_path` to place its canonical
> tables in a non-default schema.

## 3. Extra columns

- **Typed columns on the user row (GORM):** embed `identity.User` and use the
  generic store — see [extending the user](design/extending-user-and-migrations.md)
  and [examples/genericuser](../stores/gormstore/examples/genericuser).
- **Schema-less, any store:** the `attributes` JSON column
  (`u.SetAttribute(...)`), claims, or a 1:1 extension table you own.

## 4. Field lengths

The framework never enforces lengths in Go — strings are unbounded. The
`varchar(...)` sizes only exist in the bundled DDL (`AutoMigrate` tags and the
generated pgx DDL). To use different sizes, **bring your own migrations** (or
edit the generated SQL); runtime behavior is unaffected.

## 5. A completely different schema — implement the store

The managers depend only on the `identity.UserStore` / `identity.RoleStore`
interfaces, not on any schema. For full control (legacy tables, exotic column
names/types, sharding), implement those interfaces against your own tables — the
in-memory and pgx stores are working references. This is the idiomatic Go
extension point and keeps the business logic untouched.
