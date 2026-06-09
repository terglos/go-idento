package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// SMSSender delivers a one-time code to a phone number. Implement it with your
// SMS gateway (Twilio, SNS, etc.); the framework stays provider-agnostic.
type SMSSender interface {
	Send(ctx context.Context, phoneNumber, message string) error
}

// SMSSenderFunc adapts a function to SMSSender.
type SMSSenderFunc func(ctx context.Context, phoneNumber, message string) error

func (f SMSSenderFunc) Send(ctx context.Context, phone, msg string) error { return f(ctx, phone, msg) }

const (
	phoneTokenName       = "PhoneToken"
	changePhoneTokenName = "ChangePhoneToken"
)

// PhoneTokenTTL is how long an issued SMS code stays valid.
var PhoneTokenTTL = 5 * time.Minute

// WithSMSSender attaches an SMS sender, enabling SendPhoneToken. Returns the
// manager for chaining.
func (m *UserManagerOf[T, PT]) WithSMSSender(s SMSSender) *UserManagerOf[T, PT] {
	m.SMS = s
	return m
}

// PhoneTokenMaxAttempts caps wrong guesses against a single issued SMS code
// before it is invalidated, bounding brute-force of the 6-digit code space
// within the (short) validity window.
var PhoneTokenMaxAttempts = 5

// phoneCodeValue formats the stored token: "<hash>:<expiryUnix>:<attempts>".
func phoneCodeValue(hash string, exp int64, attempts int) string {
	return hash + ":" + strconv.FormatInt(exp, 10) + ":" + strconv.Itoa(attempts)
}

// consumePhoneCode validates candidateHash against the token stored under name,
// enforcing expiry and a wrong-guess cap. A correct match consumes the token and
// returns true; a miss increments the attempt counter and invalidates the token
// once [PhoneTokenMaxAttempts] is reached (so a code can't be brute-forced).
func (m *UserManagerOf[T, PT]) consumePhoneCode(ctx context.Context, u PT, name, candidateHash string) (bool, error) {
	stored, err := m.Store.GetToken(ctx, u, internalProvider, name)
	if err != nil || stored == "" {
		return false, err
	}
	parts := strings.Split(stored, ":")
	if len(parts) < 2 {
		return false, nil
	}
	hashPart := parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || nowFn().After(time.Unix(exp, 0)) {
		_ = m.Store.RemoveToken(ctx, u, internalProvider, name) // expired/malformed
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(hashPart), []byte(candidateHash)) == 1 {
		_ = m.Store.RemoveToken(ctx, u, internalProvider, name) // consume on success
		return true, nil
	}
	attempts := 0
	if len(parts) >= 3 {
		attempts, _ = strconv.Atoi(parts[2])
	}
	if attempts+1 >= PhoneTokenMaxAttempts {
		_ = m.Store.RemoveToken(ctx, u, internalProvider, name) // too many misses
	} else {
		_ = m.Store.SetToken(ctx, u, internalProvider, name, phoneCodeValue(hashPart, exp, attempts+1))
	}
	return false, nil
}

// GeneratePhoneToken creates a 6-digit code, stores it hashed with an expiry,
// and returns the plaintext code.
func (m *UserManagerOf[T, PT]) GeneratePhoneToken(ctx context.Context, u PT) (string, error) {
	code := randomDigits(6)
	exp := nowFn().Add(PhoneTokenTTL).Unix()
	if err := m.Store.SetToken(ctx, u, internalProvider, phoneTokenName, phoneCodeValue(hashRefresh(code), exp, 0)); err != nil {
		return "", err
	}
	return code, nil
}

// SendPhoneToken generates a code and delivers it via the configured SMSSender.
func (m *UserManagerOf[T, PT]) SendPhoneToken(ctx context.Context, u PT) error {
	if m.SMS == nil {
		return newErr("NoSMSSender", "no SMS sender configured")
	}
	code, err := m.GeneratePhoneToken(ctx, u)
	if err != nil {
		return err
	}
	phone := u.Base().PhoneNumber
	if phone == "" {
		return newErr("NoPhoneNumber", "user has no phone number")
	}
	return m.SMS.Send(ctx, phone, fmt.Sprintf("Your verification code is %s", code))
}

// VerifyPhoneToken validates a code against the stored token (one-time use,
// expiry-checked, attempt-capped). On success the token is consumed.
func (m *UserManagerOf[T, PT]) VerifyPhoneToken(ctx context.Context, u PT, code string) (bool, error) {
	return m.consumePhoneCode(ctx, u, phoneTokenName, hashRefresh(strings.TrimSpace(code)))
}

// ConfirmPhoneNumber validates an SMS code and marks the phone confirmed.
func (m *UserManagerOf[T, PT]) ConfirmPhoneNumber(ctx context.Context, u PT, code string) error {
	ok, err := m.VerifyPhoneToken(ctx, u, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidToken
	}
	b := u.Base()
	b.PhoneNumberConfirmed = true
	return m.Store.Update(ctx, u)
}

// GetPhoneNumberConfirmed reports whether the user's phone number is confirmed.
func (m *UserManagerOf[T, PT]) GetPhoneNumberConfirmed(u PT) bool {
	return u.Base().PhoneNumberConfirmed
}

// SetPhoneNumber sets the phone number directly (administrative path, no SMS
// challenge). The number is marked unconfirmed and the security stamp rotated.
func (m *UserManagerOf[T, PT]) SetPhoneNumber(ctx context.Context, u PT, phone string) error {
	b := u.Base()
	b.PhoneNumber = phone
	b.PhoneNumberConfirmed = false
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}

// GenerateChangePhoneNumberToken issues a 6-digit code bound to newPhone, so the
// code can only confirm a change to that exact number. The plaintext code is
// returned for the caller to deliver (e.g. via SMS to newPhone).
func (m *UserManagerOf[T, PT]) GenerateChangePhoneNumberToken(ctx context.Context, u PT, newPhone string) (string, error) {
	code := randomDigits(6)
	exp := nowFn().Add(PhoneTokenTTL).Unix()
	value := phoneCodeValue(hashRefresh(code+"|"+newPhone), exp, 0)
	if err := m.Store.SetToken(ctx, u, internalProvider, changePhoneTokenName, value); err != nil {
		return "", err
	}
	return code, nil
}

// SendChangePhoneNumberToken generates a change-phone code and delivers it to
// newPhone via the configured SMSSender.
func (m *UserManagerOf[T, PT]) SendChangePhoneNumberToken(ctx context.Context, u PT, newPhone string) error {
	if m.SMS == nil {
		return newErr("NoSMSSender", "no SMS sender configured")
	}
	if newPhone == "" {
		return newErr("NoPhoneNumber", "new phone number is empty")
	}
	code, err := m.GenerateChangePhoneNumberToken(ctx, u, newPhone)
	if err != nil {
		return err
	}
	return m.SMS.Send(ctx, newPhone, fmt.Sprintf("Your verification code is %s", code))
}

// ChangePhoneNumber validates a code previously issued for newPhone (see
// [GenerateChangePhoneNumberToken]) and, on success, sets the number, marks it
// confirmed, rotates the security stamp and consumes the token. The token only
// matches the exact number it was issued for.
func (m *UserManagerOf[T, PT]) ChangePhoneNumber(ctx context.Context, u PT, newPhone, code string) error {
	want := hashRefresh(strings.TrimSpace(code) + "|" + newPhone)
	ok, err := m.consumePhoneCode(ctx, u, changePhoneTokenName, want)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidToken
	}
	b := u.Base()
	b.PhoneNumber = newPhone
	b.PhoneNumberConfirmed = true
	b.SecurityStamp = newStamp()
	return m.Store.Update(ctx, u)
}

func randomDigits(n int) string {
	const digits = "0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			panic("identity: cannot read random digit: " + err.Error())
		}
		b[i] = digits[idx.Int64()]
	}
	return string(b)
}
