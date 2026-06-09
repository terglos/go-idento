package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// RoleManager is the business-layer API for roles, mirroring RoleManager<TRole>.
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
