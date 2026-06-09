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

const phoneTokenName = "PhoneToken"

// PhoneTokenTTL is how long an issued SMS code stays valid.
var PhoneTokenTTL = 5 * time.Minute

// WithSMSSender attaches an SMS sender, enabling SendPhoneToken. Returns the
// manager for chaining.
func (m *UserManagerOf[T, PT]) WithSMSSender(s SMSSender) *UserManagerOf[T, PT] {
	m.SMS = s
	return m
}

// GeneratePhoneToken creates a 6-digit code, stores it hashed with an expiry,
// and returns the plaintext code. Mirrors PhoneNumberTokenProvider in .NET.
func (m *UserManagerOf[T, PT]) GeneratePhoneToken(ctx context.Context, u PT) (string, error) {
	code := randomDigits(6)
	// stored value: "<hash>:<expiryUnix>"
	exp := nowFn().Add(PhoneTokenTTL).Unix()
	value := hashRefresh(code) + ":" + strconv.FormatInt(exp, 10)
	if err := m.Store.SetToken(ctx, u, internalProvider, phoneTokenName, value); err != nil {
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
// expiry-checked). On success the token is consumed.
func (m *UserManagerOf[T, PT]) VerifyPhoneToken(ctx context.Context, u PT, code string) (bool, error) {
	stored, err := m.Store.GetToken(ctx, u, internalProvider, phoneTokenName)
	if err != nil || stored == "" {
		return false, err
	}
	hashPart, expPart, ok := strings.Cut(stored, ":")
	if !ok {
		return false, nil
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil || nowFn().After(time.Unix(exp, 0)) {
		return false, nil // expired or malformed
	}
	if subtle.ConstantTimeCompare([]byte(hashPart), []byte(hashRefresh(strings.TrimSpace(code)))) != 1 {
		return false, nil
	}
	// consume the token so it can't be replayed
	_ = m.Store.RemoveToken(ctx, u, internalProvider, phoneTokenName)
	return true, nil
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
