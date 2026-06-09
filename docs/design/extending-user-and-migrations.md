# Design analysis: extending the User entity & migration strategy

> Status: analysis / decision record. Date: 2026-06-08.
>
> **Update (implemented):** all four extension options now ship — Option C
> (`Attributes` column), Options A/B (see [examples/customfields](../../examples/customfields)),
> and **Option D generics** as `UserManagerOf[T]` + `gormstore.NewUserStoreOf[T]`
> with back-compat aliases (see [examples/genericuser](../../examples/genericuser)).
> Migrations: the `identity/migrations` embed package + `atlas.hcl` are in place.

Two related questions:

1. **How does a consumer add custom columns** (e.g. `TenantID`, `FirstName`,
   `AvatarURL`) to the user — the thing ASP.NET Core Identity solves by
   subclassing `IdentityUser` + `UserManager<TUser>`?
2. **What migration mechanism** ships the core schema *and* the user's
   additions to production safely?

They are coupled: how we model extension determines what the migration tool has
to track.

---

## Part 1 — Extending the user

### How .NET does it (the bar)

```csharp
public class ApplicationUser : IdentityUser {        // subclass
    public string FirstName { get; set; }
}
services.AddIdentity<ApplicationUser, IdentityRole>();// UserManager<ApplicationUser>
// dotnet ef migrations add AddFirstName               // EF picks up the new column
```

Three ingredients: **subclassing**, **generic managers `UserManager<TUser>`**,
and **EF migrations** that diff the model. Go has no inheritance, so we map
"subclass" to **struct embedding** and "generic manager" to **Go generics**.

### Our constraint today

The core is *concrete*: `identity.User` is a struct and `UserManager`,
`UserStore`, the GORM/pgx stores are all typed to `*identity.User`. Embedding
alone doesn't flow through, because:

```go
type AppUser struct {
    identity.User          // embeds
    TenantID string
}
um.CreateWithPassword(ctx, &appUser, pw) // ❌ wants *identity.User, drops TenantID
```

So we have four real options, from least to most invasive.

### Option A — Extension table (1:1 profile), no core change

User keeps a separate table joined on the user id; the core `identity_users`
stays untouched.

```go
type Profile struct {
    UserID   string `gorm:"primaryKey"`
    TenantID string
    FullName string
}
// create user via the manager, then write the profile yourself
um.CreateWithPassword(ctx, u, pw)
db.Create(&Profile{UserID: u.ID, TenantID: "acme"})
```

- ✅ Zero changes to the framework; works **today** on every store.
- ✅ Core upgrades never collide with user columns.
- ➖ Extra join / second write; custom fields not on the user row.
- **Best for:** rich, queryable, indexed domain data owned by the app.

### Option B — Claims as attributes (the lightweight .NET way)

Store scalar extras as user claims (already implemented).

```go
um.AddClaims(ctx, u, identity.Claim{Type: "tenant", Value: "acme"})
```

- ✅ Zero schema work; flows into the JWT automatically.
- ➖ Not relationally queryable/indexable; one row per attribute.
- **Best for:** sparse, optional, token-bound flags (plan, tenant, feature bits).

### Option C — JSON attributes column

Add one `attributes jsonb` column to `identity_users` and a
`Attributes map[string]any` field.

- ✅ Arbitrary fields with no per-field migration; queryable via Postgres jsonb
  (`attributes->>'tenant'`), GIN-indexable.
- ➖ Weakly typed; cross-DB story weaker (MySQL/SQLite JSON differs).
- **Best for:** flexible, evolving, mostly-read metadata.

### Option D — Generics over `TUser` (the faithful .NET port)

Make the managers and stores generic, with a small accessor interface that
`identity.User` satisfies, so an embedding type satisfies it for free:

```go
// the contract the core needs from any user type
type IdentityUser interface {
    GetID() string;            SetID(string)
    GetPasswordHash() string;  SetPasswordHash(string)
    GetSecurityStamp() string; SetSecurityStamp(string)
    GetNormalizedUserName() string; SetNormalizedUserName(string)
    // … ~12 accessors total, all implemented once on *identity.User
}

type UserManagerOf[T IdentityUser] struct { Store UserStore[T]; … }

// embedding promotes the methods, so AppUser satisfies IdentityUser automatically
type AppUser struct {
    identity.User
    TenantID string
}
um := identity.NewUserManager[*AppUser](store, opts)
um.CreateWithPassword(ctx, &AppUser{User: ..., TenantID: "acme"}, pw) // ✅ field preserved
```

Back-compat is preservable with a type alias:

```go
type User = identity.User
type UserManager = UserManagerOf[*User] // existing concrete API keeps working
```

- ✅ Most faithful to `UserManager<TUser>`; custom fields live **on the user row**
  and are first-class.
- ✅ With GORM, `AutoMigrate(&AppUser{})` and Atlas pick up the new columns
  automatically — the real EF experience.
- ➖ Large refactor: every signature becomes `[T]`; the accessor interface is
  boilerplate (generated once).
- ➖ The **raw pgx store can't stay fully generic** — its hand-written column
  list/`Scan` is per-type. Generic extension realistically targets the **GORM
  store** (reflection-based), with pgx remaining the concrete fast path.

### Recommendation (Part 1)

Phase it:

1. **Now (ship docs + examples):** endorse **Option A (extension table)** and
   **Option B (claims)** — they need no code change and cover ~80% of cases.
   Add the optional **Option C jsonb** field behind a build choice for the
   flexible case.
2. **Next (strategic):** implement **Option D generics** as
   `identity.UserManagerOf[T]`, keep `UserManager` as a type alias for the
   concrete instantiation so nothing breaks, and scope generic extension to the
   **GORM store** (document pgx as concrete-only). This is what makes us a true
   peer of .NET Identity.

The accessor interface is the only real cost and is mechanical; everything else
is renaming with `[T]`.

---

## Part 2 — Migrations

### Where we are

- `gormstore.Migrate` → GORM **AutoMigrate** (additive: creates tables/columns,
  never drops). Great for dev/tests, **unsafe assumption for prod** (no
  down/versioning, won't reconcile type/constraint changes).
- `pgxstore` → a single embedded `schema.sql` run with `IF NOT EXISTS`. Fine for
  bootstrap, but it isn't versioned either.

Neither gives the EF `add-migration` / ordered, reviewable, reversible history a
production team needs.

### The Go field (2026)

| Tool | Style | Notes |
|---|---|---|
| **golang-migrate** | Versioned SQL up/down | Most ubiquitous; CLI-first; many DBs; no model awareness. |
| **goose** | Versioned SQL *or* Go funcs | Lightweight, embeddable as a library; popular. |
| **dbmate / tern** | Versioned SQL | Language-agnostic / pgx-native (tern) respectively. |
| **Atlas (ariga)** | **Declarative + versioned, schema-as-code** | Diffs *desired vs current* and **generates** migrations; has a **GORM provider** that reads our models. Lint + CI. |

### Why Atlas is the strategic fit

Atlas's **GORM provider** loads our GORM structs and runs
`atlas migrate diff` to **auto-generate versioned SQL** from model changes — the
exact EF Core experience. It supports Postgres/MySQL/SQLite (matching our GORM
store), declarative *and* versioned workflows, plus migration linting in CI.
Crucially, it composes with **Option D**: when a consumer extends `AppUser`,
Atlas regenerates the migration for their new columns automatically.

golang-migrate/goose are excellent *executors* but are model-blind — you
hand-write the SQL. They remain valid for teams who prefer that, and Atlas can
emit migrations in golang-migrate format, so the choices aren't exclusive.

### Recommendation (Part 2)

1. **Keep AutoMigrate / embedded `schema.sql` as the dev & test default**
   (zero-setup `go run`, what the demo uses).
2. **Adopt Atlas as the production-recommended path:** add an `atlas.hcl` + the
   GORM provider so `atlas migrate diff` generates versioned SQL under
   `migrations/`. Ship those files in the repo as the canonical schema history.
3. **Document goose/golang-migrate as supported alternatives** that can run the
   Atlas-generated (or hand-written) SQL — we don't lock anyone in.
4. Expose a tiny `identity/migrations` package embedding the canonical SQL via
   `embed.FS`, so library users can apply it without the Atlas CLI if they want.

### Net effect

`extend AppUser struct` → `atlas migrate diff` → reviewed versioned SQL →
`atlas migrate apply` (or goose/golang-migrate). That is the ASP.NET Core
Identity "extend model + add migration" loop, reproduced in Go.
