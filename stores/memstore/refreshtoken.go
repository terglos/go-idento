package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/terglos/go-idento/identity"
)

func cloneRefreshToken(rt *identity.RefreshToken) *identity.RefreshToken {
	c := *rt
	return &c
}

func (s *refreshTokenStore) CreateRefreshToken(_ context.Context, rt *identity.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[rt.SessionID] = cloneRefreshToken(rt)
	return nil
}

func (s *refreshTokenStore) GetRefreshTokenBySession(_ context.Context, sessionID string) (*identity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rt, ok := s.refreshTokens[sessionID]
	if !ok {
		return nil, identity.ErrNotFound
	}
	return cloneRefreshToken(rt), nil
}

func (s *refreshTokenStore) UpdateRefreshToken(_ context.Context, rt *identity.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.refreshTokens[rt.SessionID]; !ok {
		return identity.ErrNotFound
	}
	s.refreshTokens[rt.SessionID] = cloneRefreshToken(rt)
	return nil
}

func (s *refreshTokenStore) DeleteRefreshToken(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, sessionID)
	return nil
}

func (s *refreshTokenStore) DeleteUserRefreshTokens(_ context.Context, userID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for sid, rt := range s.refreshTokens {
		if rt.UserID == userID {
			delete(s.refreshTokens, sid)
			n++
		}
	}
	return n, nil
}

func (s *refreshTokenStore) DeleteExpiredRefreshTokens(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for sid, rt := range s.refreshTokens {
		if rt.ExpiresAt.Before(before) {
			delete(s.refreshTokens, sid)
			n++
		}
	}
	return n, nil
}

func (s *refreshTokenStore) ListUserRefreshTokens(_ context.Context, userID string) ([]identity.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []identity.RefreshToken
	for _, rt := range s.refreshTokens {
		if rt.UserID == userID {
			out = append(out, *cloneRefreshToken(rt))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out, nil
}
