package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/terglos/go-idento/identity"
)

func cloneAPIKey(k *identity.APIKey) *identity.APIKey {
	c := *k
	if k.Scopes != nil {
		c.Scopes = append(identity.Scopes(nil), k.Scopes...)
	}
	return &c
}

func (s *apiKeyStore) CreateAPIKey(_ context.Context, k *identity.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.apiKeys {
		if existing.KeyHash == k.KeyHash {
			return identity.ErrLoginAlreadyUsed // hash collision == already-used credential
		}
	}
	s.apiKeys[k.ID] = cloneAPIKey(k)
	return nil
}

func (s *apiKeyStore) GetActiveAPIKeyByHash(_ context.Context, keyHash string) (*identity.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	for _, k := range s.apiKeys {
		if k.KeyHash != keyHash {
			continue
		}
		if k.RevokedAt != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(now)) {
			return nil, identity.ErrNotFound // present but inactive — caller treats as invalid
		}
		return cloneAPIKey(k), nil
	}
	return nil, identity.ErrNotFound
}

func (s *apiKeyStore) ListAPIKeysByUser(_ context.Context, userID string) ([]identity.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []identity.APIKey
	for _, k := range s.apiKeys {
		if k.UserID == userID {
			out = append(out, *cloneAPIKey(k))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *apiKeyStore) RevokeAPIKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.apiKeys[id]; ok && k.RevokedAt == nil {
		now := time.Now()
		k.RevokedAt = &now
	}
	return nil
}

func (s *apiKeyStore) TouchAPIKeyLastUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.apiKeys[id]; ok {
		now := time.Now()
		k.LastUsedAt = &now
	}
	return nil
}
