package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/terglos/go-idento/identity"
	"github.com/terglos/go-idento/oauth"
)

// OAuth returns an oauth.Store view (embedded OAuth 2.1 authorization server).
func (s *Store) OAuth() oauth.Store { return (*oauthStore)(s) }

type oauthStore Store

var _ oauth.Store = (*oauthStore)(nil)

func consentKey(userID, clientID string) string { return userID + "|" + clientID }

func cloneClient(c *oauth.Client) *oauth.Client {
	x := *c
	x.RedirectURIs = append(oauth.StringList(nil), c.RedirectURIs...)
	x.GrantTypes = append(oauth.StringList(nil), c.GrantTypes...)
	return &x
}

func (s *oauthStore) CreateClient(_ context.Context, c *oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthClients[c.ClientID] = cloneClient(c)
	return nil
}

func (s *oauthStore) GetClient(_ context.Context, clientID string) (*oauth.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.oauthClients[clientID]
	if !ok {
		return nil, identity.ErrNotFound
	}
	return cloneClient(c), nil
}

func (s *oauthStore) TouchClient(_ context.Context, clientID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.oauthClients[clientID]; ok {
		t := at
		c.LastUsedAt = &t
	}
	return nil
}

func (s *oauthStore) DeleteStaleClients(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inUse := map[string]bool{}
	for _, g := range s.oauthGrants {
		inUse[g.ClientID] = true
	}
	var n int64
	for id, c := range s.oauthClients {
		if c.CreatedAt.Before(before) && (c.LastUsedAt == nil || c.LastUsedAt.Before(before)) && !inUse[id] {
			delete(s.oauthClients, id)
			n++
		}
	}
	return n, nil
}

func (s *oauthStore) CreateCode(_ context.Context, c *oauth.Code) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := *c
	s.oauthCodes[c.CodeHash] = &x
	return nil
}

func (s *oauthStore) GetCode(_ context.Context, codeHash string) (*oauth.Code, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.oauthCodes[codeHash]
	if !ok {
		return nil, identity.ErrNotFound
	}
	x := *c
	return &x, nil
}

func (s *oauthStore) MarkCodeUsed(_ context.Context, codeHash, grantID string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.oauthCodes[codeHash]
	if !ok || c.UsedAt != nil {
		return false, nil
	}
	t := at
	c.UsedAt, c.GrantID = &t, grantID
	return true, nil
}

func (s *oauthStore) DeleteExpiredCodes(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for h, c := range s.oauthCodes {
		if c.ExpiresAt.Before(before) {
			delete(s.oauthCodes, h)
			n++
		}
	}
	return n, nil
}

func (s *oauthStore) GetConsent(_ context.Context, userID, clientID string) (*oauth.Consent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.oauthConsents[consentKey(userID, clientID)]
	if !ok {
		return nil, identity.ErrNotFound
	}
	x := *c
	return &x, nil
}

func (s *oauthStore) SaveConsent(_ context.Context, c *oauth.Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := *c
	if prev, ok := s.oauthConsents[consentKey(c.UserID, c.ClientID)]; ok {
		x.CreatedAt = prev.CreatedAt
	}
	s.oauthConsents[consentKey(c.UserID, c.ClientID)] = &x
	return nil
}

func (s *oauthStore) DeleteConsent(_ context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oauthConsents, consentKey(userID, clientID))
	return nil
}

func (s *oauthStore) CreateGrant(_ context.Context, g *oauth.Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := *g
	s.oauthGrants[g.ID] = &x
	return nil
}

func (s *oauthStore) GetGrant(_ context.Context, id string) (*oauth.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.oauthGrants[id]
	if !ok {
		return nil, identity.ErrNotFound
	}
	x := *g
	return &x, nil
}

func (s *oauthStore) RotateGrant(_ context.Context, id, oldHash, newHash string, expiresAt, usedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.oauthGrants[id]
	if !ok || g.TokenHash != oldHash {
		return false, nil
	}
	t := usedAt
	g.PrevTokenHash, g.TokenHash, g.ExpiresAt, g.LastUsedAt = oldHash, newHash, expiresAt, &t
	return true, nil
}

func (s *oauthStore) DeleteGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oauthGrants, id)
	return nil
}

func (s *oauthStore) DeleteUserClientGrants(_ context.Context, userID, clientID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, g := range s.oauthGrants {
		if g.UserID == userID && g.ClientID == clientID {
			delete(s.oauthGrants, id)
			n++
		}
	}
	return n, nil
}

func (s *oauthStore) ListUserGrants(_ context.Context, userID string) ([]oauth.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []oauth.Grant
	for _, g := range s.oauthGrants {
		if g.UserID == userID {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *oauthStore) DeleteExpiredGrants(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for id, g := range s.oauthGrants {
		if g.ExpiresAt.Before(before) {
			delete(s.oauthGrants, id)
			n++
		}
	}
	return n, nil
}
