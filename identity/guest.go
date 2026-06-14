package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

// CreateAnonymous creates and persists a first-class guest user: no email and no
// password, a generated unique user name, and IsAnonymous set. Issue a token for
// it as usual ([TokenServiceOf.IssuePair]); promote it later with
// [ConvertToRegistered], and sweep abandoned guests with [PurgeAnonymousUsers].
func (m *UserManagerOf[T, PT]) CreateAnonymous(ctx context.Context) (PT, error) {
	var t T
	u := PT(&t)
	b := u.Base()
	b.ID = uuid.NewString()
	b.UserName = "guest_" + randomHex(16)
	b.NormalizedUserName = m.Normalizer.Normalize(b.UserName)
	b.IsAnonymous = true
	b.SecurityStamp = newStamp()
	b.ConcurrencyStamp = uuid.NewString()
	b.LockoutEnabled = m.Options.Lockout.AllowedForNewUsers
	// Stamp creation time so the age-based purge works on every store (the SQL
	// stores also default created_at to now(); this keeps them consistent).
	if b.CreatedAt.IsZero() {
		b.CreatedAt = nowFn()
	}
	if err := m.Store.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// IsAnonymous reports whether the user is a guest (anonymous) account.
func (m *UserManagerOf[T, PT]) IsAnonymous(u PT) bool { return u.Base().IsAnonymous }

// ConvertToRegistered promotes a guest user to a full account in place: it sets
// the user name, email and password (applying the usual validation and
// uniqueness rules), clears IsAnonymous, and rotates the security stamp — all
// while preserving the user ID, so any data keyed on it (cart, claims, roles)
// carries over. Returns [ErrNotAnonymous] if the user is not a guest.
func (m *UserManagerOf[T, PT]) ConvertToRegistered(ctx context.Context, u PT, userName, email, password string) error {
	b := u.Base()
	if !b.IsAnonymous {
		return ErrNotAnonymous
	}
	if err := m.ValidateUserName(userName); err != nil {
		return err
	}
	if err := m.ValidatePassword(password); err != nil {
		return err
	}
	normUser := m.Normalizer.Normalize(userName)
	if existing, err := m.Store.FindByName(ctx, normUser); err == nil && existing != nil && existing.Base().ID != b.ID {
		return ErrDuplicateUserName
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	normEmail := m.Normalizer.Normalize(email)
	if m.Options.User.RequireUniqueEmail && normEmail != "" {
		if existing, err := m.Store.FindByEmail(ctx, normEmail); err == nil && existing != nil && existing.Base().ID != b.ID {
			return ErrDuplicateEmail
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	b.UserName = userName
	b.NormalizedUserName = normUser
	b.Email = email
	b.NormalizedEmail = normEmail
	b.PasswordHash = m.Hasher.Hash(b, password)
	b.IsAnonymous = false
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}

// PurgeAnonymousUsers deletes guest users created before olderThan, cascading
// their roles, claims, logins and tokens, and returns how many were removed. It
// requires the store to implement [AnonymousPurger]; otherwise it returns
// [ErrPurgeNotSupported]. Run it periodically (a cron/worker) to reclaim
// abandoned guest rows.
func (m *UserManagerOf[T, PT]) PurgeAnonymousUsers(ctx context.Context, olderThan time.Time) (int64, error) {
	purger, ok := m.Store.(AnonymousPurger[T, PT])
	if !ok {
		return 0, ErrPurgeNotSupported
	}
	return purger.PurgeAnonymousUsers(ctx, olderThan)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random bytes: " + err.Error())
	}
	return hex.EncodeToString(b)
}
