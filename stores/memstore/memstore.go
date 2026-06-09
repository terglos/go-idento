// Package memstore is an in-memory implementation of the identity stores. It is
// useful for unit tests and prototyping (no database required), and doubles as
// the reference for what a UserStore/RoleStore must do. It is concurrency-safe.
package memstore

import (
	"context"
	"sync"

	"github.com/terglos/go-idento/identity"
)

// Store backs both a UserStore and a RoleStore from the same data, so users and
// roles can reference each other (e.g. AddToRole resolves a role by name).
type Store struct {
	mu sync.RWMutex

	users      map[string]*identity.User  // by ID
	roles      map[string]*identity.Role  // by ID
	userRoles  map[string]map[string]bool // userID -> set of roleID
	userClaims map[string][]identity.Claim
	roleClaims map[string][]identity.Claim
	tokens     map[string]string                 // userID|provider|name -> value
	logins     map[string]identity.UserLoginInfo // provider|key -> info
	loginUser  map[string]string                 // provider|key -> userID
}

func New() *Store {
	return &Store{
		users:      map[string]*identity.User{},
		roles:      map[string]*identity.Role{},
		userRoles:  map[string]map[string]bool{},
		userClaims: map[string][]identity.Claim{},
		roleClaims: map[string][]identity.Claim{},
		tokens:     map[string]string{},
		logins:     map[string]identity.UserLoginInfo{},
		loginUser:  map[string]string{},
	}
}

// Users returns a UserStore view.
func (s *Store) Users() identity.DefaultUserStore { return (*userStore)(s) }

// Roles returns a RoleStore view.
func (s *Store) Roles() identity.RoleStore { return (*roleStore)(s) }

type userStore Store
type roleStore Store

var (
	_ identity.DefaultUserStore = (*userStore)(nil)
	_ identity.RoleStore        = (*roleStore)(nil)
)

func tokenKey(userID, provider, name string) string { return userID + "|" + provider + "|" + name }
func loginKey(provider, key string) string          { return provider + "|" + key }

// clone returns a copy so callers can't mutate stored state by reference,
// matching the round-trip semantics of a real DB.
func clone(u *identity.User) *identity.User     { c := *u; return &c }
func cloneRole(r *identity.Role) *identity.Role { c := *r; return &c }

// --- UserStore ---

func (s *userStore) Create(_ context.Context, u *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = clone(u)
	return nil
}

func (s *userStore) Update(_ context.Context, u *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.users[u.ID]
	if !ok {
		return identity.ErrNotFound
	}
	if cur.ConcurrencyStamp != u.ConcurrencyStamp {
		return identity.ErrConcurrencyFailure // a concurrent write won
	}
	u.ConcurrencyStamp = identity.NewConcurrencyStamp() // rotate on success
	s.users[u.ID] = clone(u)
	return nil
}

func (s *userStore) Delete(_ context.Context, u *identity.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, u.ID)
	return nil
}

func (s *userStore) FindByID(_ context.Context, id string) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, identity.ErrNotFound
	}
	return clone(u), nil
}

func (s *userStore) findBy(pred func(*identity.User) bool) (*identity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if pred(u) {
			return clone(u), nil
		}
	}
	return nil, identity.ErrNotFound
}

func (s *userStore) FindByName(_ context.Context, n string) (*identity.User, error) {
	return s.findBy(func(u *identity.User) bool { return u.NormalizedUserName == n })
}

func (s *userStore) FindByEmail(_ context.Context, e string) (*identity.User, error) {
	return s.findBy(func(u *identity.User) bool { return u.NormalizedEmail == e && e != "" })
}

func (s *userStore) roleIDByName(normalizedRoleName string) (string, bool) {
	for _, r := range s.roles {
		if r.NormalizedName == normalizedRoleName {
			return r.ID, true
		}
	}
	return "", false
}

func (s *userStore) AddToRole(_ context.Context, u *identity.User, normalizedRoleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rid, ok := s.roleIDByName(normalizedRoleName)
	if !ok {
		return identity.ErrRoleNotFound
	}
	if s.userRoles[u.ID] == nil {
		s.userRoles[u.ID] = map[string]bool{}
	}
	s.userRoles[u.ID][rid] = true
	return nil
}

func (s *userStore) RemoveFromRole(_ context.Context, u *identity.User, normalizedRoleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rid, ok := s.roleIDByName(normalizedRoleName)
	if !ok {
		return nil
	}
	delete(s.userRoles[u.ID], rid)
	return nil
}

func (s *userStore) GetRoles(_ context.Context, u *identity.User) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for rid := range s.userRoles[u.ID] {
		if r, ok := s.roles[rid]; ok {
			out = append(out, r.Name)
		}
	}
	return out, nil
}

func (s *userStore) IsInRole(_ context.Context, u *identity.User, normalizedRoleName string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rid, ok := s.roleIDByName(normalizedRoleName)
	if !ok {
		return false, nil
	}
	return s.userRoles[u.ID][rid], nil
}

func (s *userStore) GetClaims(_ context.Context, u *identity.User) ([]identity.Claim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]identity.Claim(nil), s.userClaims[u.ID]...), nil
}

func (s *userStore) AddClaims(_ context.Context, u *identity.User, claims []identity.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userClaims[u.ID] = append(s.userClaims[u.ID], claims...)
	return nil
}

func (s *userStore) RemoveClaims(_ context.Context, u *identity.User, claims []identity.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.userClaims[u.ID][:0:0]
	for _, c := range s.userClaims[u.ID] {
		remove := false
		for _, rm := range claims {
			if c == rm {
				remove = true
				break
			}
		}
		if !remove {
			kept = append(kept, c)
		}
	}
	s.userClaims[u.ID] = kept
	return nil
}

func (s *userStore) GetToken(_ context.Context, u *identity.User, provider, name string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens[tokenKey(u.ID, provider, name)], nil
}

func (s *userStore) SetToken(_ context.Context, u *identity.User, provider, name, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenKey(u.ID, provider, name)] = value
	return nil
}

func (s *userStore) RemoveToken(_ context.Context, u *identity.User, provider, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenKey(u.ID, provider, name))
	return nil
}

func (s *userStore) AddLogin(_ context.Context, u *identity.User, login identity.UserLoginInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := loginKey(login.LoginProvider, login.ProviderKey)
	s.logins[k] = login
	s.loginUser[k] = u.ID
	return nil
}

func (s *userStore) RemoveLogin(_ context.Context, u *identity.User, provider, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := loginKey(provider, key)
	delete(s.logins, k)
	delete(s.loginUser, k)
	return nil
}

func (s *userStore) GetLogins(_ context.Context, u *identity.User) ([]identity.UserLoginInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []identity.UserLoginInfo
	for k, uid := range s.loginUser {
		if uid == u.ID {
			out = append(out, s.logins[k])
		}
	}
	return out, nil
}

func (s *userStore) FindByLogin(ctx context.Context, provider, key string) (*identity.User, error) {
	s.mu.RLock()
	uid, ok := s.loginUser[loginKey(provider, key)]
	s.mu.RUnlock()
	if !ok {
		return nil, identity.ErrNotFound
	}
	return s.FindByID(ctx, uid)
}

// --- RoleStore ---

func (s *roleStore) Create(_ context.Context, r *identity.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID] = cloneRole(r)
	return nil
}

func (s *roleStore) Update(_ context.Context, r *identity.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID] = cloneRole(r)
	return nil
}

func (s *roleStore) Delete(_ context.Context, r *identity.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, r.ID)
	return nil
}

func (s *roleStore) FindByID(_ context.Context, id string) (*identity.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[id]
	if !ok {
		return nil, identity.ErrNotFound
	}
	return cloneRole(r), nil
}

func (s *roleStore) FindByName(_ context.Context, normalizedName string) (*identity.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.roles {
		if r.NormalizedName == normalizedName {
			return cloneRole(r), nil
		}
	}
	return nil, identity.ErrNotFound
}

func (s *roleStore) GetClaims(_ context.Context, r *identity.Role) ([]identity.Claim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]identity.Claim(nil), s.roleClaims[r.ID]...), nil
}

func (s *roleStore) AddClaim(_ context.Context, r *identity.Role, c identity.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleClaims[r.ID] = append(s.roleClaims[r.ID], c)
	return nil
}

func (s *roleStore) RemoveClaim(_ context.Context, r *identity.Role, c identity.Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.roleClaims[r.ID][:0:0]
	for _, existing := range s.roleClaims[r.ID] {
		if existing != c {
			kept = append(kept, existing)
		}
	}
	s.roleClaims[r.ID] = kept
	return nil
}
