// Command postgres-demo runs go-idento against a real PostgreSQL database
// using the raw pgx store. It exposes a small HTTP API covering the full flow:
// register, login (JWT + cookie), refresh, a protected endpoint, a role-gated
// endpoint, and TOTP two-factor setup/verification.
//
// Run:
//
//	docker compose up -d            # start Postgres
//	go run .                        # start the API on :8080
//
// Then exercise it with the curl snippets in README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/pgxstore"
)

type app struct {
	users   *identity.UserManager
	roles   *identity.RoleManager
	signIn  *identity.SignInManager
	tokens  *identity.TokenService
	cookies *auth.CookieAuth
}

func main() {
	ctx := context.Background()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://identity:identity@localhost:5432/identity?sslmode=disable"
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pingWithRetry(ctx, pool); err != nil {
		log.Fatalf("database not reachable: %v", err)
	}
	if err := pgxstore.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	users := identity.NewUserManager(pgxstore.NewUserStore(pool), identity.DefaultOptions()).
		WithTokenProvider(identity.NewDataTokenProvider([]byte(env("TOKEN_SECRET", "demo-token-secret-change-me")), time.Hour))
	roles := identity.NewRoleManager(pgxstore.NewRoleStore(pool))
	tokens := identity.NewTokenService(users,
		identity.DefaultTokenOptions([]byte(env("JWT_SECRET", "demo-jwt-secret-change-me-please!")), "go-idento-demo", "api"))
	cookies := auth.DefaultCookieAuth()
	cookies.Secure = false // demo runs over http

	a := &app{users: users, roles: roles, signIn: identity.NewSignInManager(users), tokens: tokens, cookies: cookies}

	// Seed an Admin role so the role-gated endpoint is usable.
	if !a.roles.RoleExists(ctx, "Admin") {
		if err := a.roles.Create(ctx, &identity.Role{Name: "Admin"}); err != nil {
			log.Fatalf("seed role: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", a.register)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /refresh", a.refresh)
	mux.Handle("GET /me", auth.RequireAuth(http.HandlerFunc(a.me)))
	mux.Handle("GET /admin", auth.RequireRole("Admin")(http.HandlerFunc(a.admin)))
	mux.Handle("POST /promote", auth.RequireAuth(http.HandlerFunc(a.promote)))

	// Two-factor setup endpoints (require an authenticated user).
	mux.Handle("POST /2fa/setup", auth.RequireAuth(http.HandlerFunc(a.twoFactorSetup)))
	mux.Handle("POST /2fa/enable", auth.RequireAuth(http.HandlerFunc(a.twoFactorEnable)))
	mux.HandleFunc("POST /2fa/verify", a.twoFactorVerify)

	handler := auth.Middleware(tokens, cookies)(mux)
	addr := env("ADDR", ":8080")
	log.Printf("postgres-demo listening on %s (db: %s)", addr, dsn)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// --- handlers ---

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserName, Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u := &identity.User{UserName: body.UserName, Email: body.Email}
	if err := a.users.CreateWithPassword(r.Context(), u, body.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "userName": u.UserName})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserName, Password, TwoFactorCode string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, u := a.signIn.PasswordSignIn(r.Context(), body.UserName, body.Password, true)
	switch {
	case res.IsLockedOut:
		http.Error(w, "account locked out", http.StatusForbidden)
		return
	case res.RequiresTwoFactor:
		if body.TwoFactorCode == "" {
			writeJSON(w, http.StatusOK, map[string]any{"requiresTwoFactor": true})
			return
		}
		if r2 := a.signIn.TwoFactorAuthenticatorSignIn(r.Context(), u, body.TwoFactorCode); !r2.Succeeded {
			http.Error(w, "invalid two-factor code", http.StatusUnauthorized)
			return
		}
	case !res.Succeeded:
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	a.issue(w, r, u)
}

func (a *app) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserID, RefreshToken string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := a.users.FindByID(r.Context(), body.UserID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pair, err := a.tokens.Refresh(r.Context(), u, body.RefreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	a.cookies.Write(w, pair.AccessToken)
	writeJSON(w, http.StatusOK, pair)
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"id": p.User.ID, "userName": p.User.UserName, "email": p.User.Email,
		"roles": p.Roles, "twoFactorEnabled": p.User.TwoFactorEnabled,
	})
}

func (a *app) admin(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"message": "welcome, admin"})
}

// promote adds the current user to the Admin role (demo convenience).
func (a *app) promote(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	u, err := a.users.FindByID(r.Context(), p.User.ID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := a.users.AddToRole(r.Context(), u, "Admin"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "promoted to Admin — log in again to refresh your token"})
}

func (a *app) twoFactorSetup(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.PrincipalFrom(r.Context())
	u, _ := a.users.FindByID(r.Context(), p.User.ID)
	key, err := a.users.GetAuthenticatorKey(r.Context(), u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"sharedKey":        key,
		"authenticatorUri": identity.AuthenticatorURI("go-idento-demo", u.Email, key),
		"hint":             "add the URI to an authenticator app, then POST /2fa/enable with a code",
	})
}

func (a *app) twoFactorEnable(w http.ResponseWriter, r *http.Request) {
	var body struct{ Code string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	p, _ := auth.PrincipalFrom(r.Context())
	u, _ := a.users.FindByID(r.Context(), p.User.ID)

	ok, err := a.users.VerifyTwoFactorTOTP(r.Context(), u, body.Code)
	if err != nil || !ok {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if err := a.users.SetTwoFactorEnabled(r.Context(), u, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	codes, err := a.users.GenerateRecoveryCodes(r.Context(), u, 10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"twoFactorEnabled": true, "recoveryCodes": codes})
}

// twoFactorVerify is a convenience endpoint that mirrors the 2FA branch of login.
func (a *app) twoFactorVerify(w http.ResponseWriter, r *http.Request) {
	var body struct{ UserName, Code string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	u, err := a.users.FindByName(r.Context(), body.UserName)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if res := a.signIn.TwoFactorAuthenticatorSignIn(r.Context(), u, body.Code); !res.Succeeded {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	a.issue(w, r, u)
}

// issue writes a token pair (and sets the auth cookie).
func (a *app) issue(w http.ResponseWriter, r *http.Request, u *identity.User) {
	pair, err := a.tokens.IssuePair(r.Context(), u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.cookies.Write(w, pair.AccessToken)
	writeJSON(w, http.StatusOK, map[string]any{"userId": u.ID, "tokens": pair})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func pingWithRetry(ctx context.Context, pool *pgxpool.Pool) error {
	var err error
	for i := 0; i < 15; i++ {
		if err = pool.Ping(ctx); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("timed out waiting for postgres: " + err.Error())
}
