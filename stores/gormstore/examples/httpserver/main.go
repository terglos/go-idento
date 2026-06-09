// Command httpserver is a minimal end-to-end demo: register, login (JWT +
// cookie) and a role-protected endpoint, all wired from the identity core.
//
//	go run ./examples/httpserver        # listens on :8080 (override with PORT)
//	curl -s localhost:8080/register -d '{"userName":"jane","email":"m@x.com","password":"Abcdef1!"}'
//	curl -s localhost:8080/login    -d '{"userName":"jane","password":"Abcdef1!"}'
//	curl -s localhost:8080/me -H "Authorization: Bearer <accessToken>"
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/terglos/go-idento/auth"
	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/stores/gormstore"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("identity.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if err := gormstore.Migrate(db); err != nil {
		log.Fatal(err)
	}

	users := identity.NewUserManager(gormstore.NewUserStore(db), identity.DefaultOptions())
	signIn := identity.NewSignInManager(users)
	tokens := identity.NewTokenService(users,
		identity.DefaultTokenOptions([]byte("change-me-32-byte-minimum-secret!"), "go-idento", "api"))
	cookies := auth.DefaultCookieAuth()
	cookies.Secure = false // demo over http

	mux := http.NewServeMux()

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ UserName, Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		u := &identity.User{UserName: body.UserName, Email: body.Email}
		if err := users.CreateWithPassword(r.Context(), u, body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"id": u.ID})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ UserName, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		res, u := signIn.PasswordSignIn(r.Context(), body.UserName, body.Password, true)
		switch {
		case res.IsLockedOut:
			http.Error(w, "locked out", http.StatusForbidden)
		case !res.Succeeded:
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
		default:
			pair, err := tokens.IssuePair(r.Context(), u)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			cookies.Write(w, pair.AccessToken)
			writeJSON(w, pair)
		}
	})

	// Protected: requires a valid principal.
	mux.Handle("/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := auth.PrincipalFrom(r.Context())
		writeJSON(w, map[string]any{"id": p.User.ID, "userName": p.User.UserName, "roles": p.Roles})
	})))

	// Protected by role.
	mux.Handle("/admin", auth.RequireRole("Admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"ok": "welcome admin"})
	})))

	handler := auth.Middleware(tokens, cookies)(mux)
	log.Println("listening on :8080")
	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
