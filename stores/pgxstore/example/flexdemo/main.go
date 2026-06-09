// Command flexdemo materializes the identity schema with a CUSTOM namespace and
// table prefix, to show that table names, schema and integrity are configurable.
//
//	DATABASE_URL=postgres://... go run .
//
// It creates tables like <schema>.<prefix>identity_users with ON DELETE CASCADE
// foreign keys, then registers + reads a user back through the renamed tables.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/pgxstore"
)

func main() {
	ctx := context.Background()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:123@localhost:5432/identity_test?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// Custom physical layout: schema "idflex", prefix "app_".
	opts := []pgxstore.Option{pgxstore.WithSchema("idflex"), pgxstore.WithTablePrefix("app_")}
	if err := pgxstore.Migrate(ctx, pool, opts...); err != nil {
		log.Fatal(err)
	}

	users := identity.NewUserManager(pgxstore.NewUserStore(pool, opts...), identity.DefaultOptions())
	roles := identity.NewRoleManager(pgxstore.NewRoleStore(pool, opts...))
	_ = roles.Create(ctx, &identity.Role{Name: "Admin"})

	u := &identity.User{UserName: "flexdemo", Email: "flex@example.com"}
	u.SetAttribute("tenant", "acme")
	if err := users.CreateWithPassword(ctx, u, "Abcdef1!"); err != nil {
		log.Fatal(err)
	}
	_ = users.AddToRole(ctx, u, "Admin")

	got, _ := users.FindByName(ctx, "flexdemo")
	rolesOf, _ := users.GetRoles(ctx, got)
	tenant, _ := got.GetAttribute("tenant")
	fmt.Printf("created %s in idflex.app_identity_users; roles=%v tenant=%s\n", got.UserName, rolesOf, tenant)
}
