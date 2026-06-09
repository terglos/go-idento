package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// RoleManager is the business-layer API for roles.
type RoleManager struct {
	Store      RoleStore
	Normalizer Normalizer
}

func NewRoleManager(store RoleStore) *RoleManager {
	return &RoleManager{Store: store, Normalizer: upperNormalizer{}}
}

func (m *RoleManager) Create(ctx context.Context, r *Role) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	r.NormalizedName = m.Normalizer.Normalize(r.Name)
	r.ConcurrencyStamp = uuid.NewString()
	if existing, err := m.Store.FindByName(ctx, r.NormalizedName); err == nil && existing != nil {
		return ErrDuplicateRoleName
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return m.Store.Create(ctx, r)
}

// Update renames a role (re-normalizing) and persists it under optimistic
// concurrency. It rejects a name already used by a different role; the store
// rotates ConcurrencyStamp on success and returns [ErrConcurrencyFailure] if the
// role was modified concurrently.
func (m *RoleManager) Update(ctx context.Context, r *Role) error {
	r.NormalizedName = m.Normalizer.Normalize(r.Name)
	if existing, err := m.Store.FindByName(ctx, r.NormalizedName); err == nil && existing != nil && existing.ID != r.ID {
		return ErrDuplicateRoleName
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return m.Store.Update(ctx, r)
}

func (m *RoleManager) Delete(ctx context.Context, r *Role) error { return m.Store.Delete(ctx, r) }

func (m *RoleManager) FindByName(ctx context.Context, name string) (*Role, error) {
	return m.Store.FindByName(ctx, m.Normalizer.Normalize(name))
}

func (m *RoleManager) FindByID(ctx context.Context, id string) (*Role, error) {
	return m.Store.FindByID(ctx, id)
}

func (m *RoleManager) RoleExists(ctx context.Context, name string) bool {
	r, err := m.Store.FindByName(ctx, m.Normalizer.Normalize(name))
	return err == nil && r != nil
}

func (m *RoleManager) GetClaims(ctx context.Context, r *Role) ([]Claim, error) {
	return m.Store.GetClaims(ctx, r)
}

func (m *RoleManager) AddClaim(ctx context.Context, r *Role, c Claim) error {
	return m.Store.AddClaim(ctx, r, c)
}

func (m *RoleManager) RemoveClaim(ctx context.Context, r *Role, c Claim) error {
	return m.Store.RemoveClaim(ctx, r, c)
}

// ReplaceClaim swaps an existing role claim for a new one (remove old, add new).
func (m *RoleManager) ReplaceClaim(ctx context.Context, r *Role, old, replacement Claim) error {
	if err := m.Store.RemoveClaim(ctx, r, old); err != nil {
		return err
	}
	return m.Store.AddClaim(ctx, r, replacement)
}
