package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 (time-based one-time passwords), the algorithm
// behind authenticator apps such as Google Authenticator and Authy.
type TOTP struct {
	Digits int           // number of digits (default 6)
	Period time.Duration // time step (default 30s)
	Skew   int           // allowed steps before/after now (default 1)
}

// DefaultTOTP returns 6-digit, 30s, ±1 step settings (the common defaults).
func DefaultTOTP() TOTP { return TOTP{Digits: 6, Period: 30 * time.Second, Skew: 1} }

func (t TOTP) digits() int {
	if t.Digits == 0 {
		return 6
	}
	return t.Digits
}
func (t TOTP) period() time.Duration {
	if t.Period == 0 {
		return 30 * time.Second
	}
	return t.Period
}

// GenerateSecret returns a new random base32-encoded shared secret (160 bits).
func GenerateSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("identity: cannot read random secret: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// Code computes the TOTP code for a given time using the base32 secret.
func (t TOTP) Code(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", ErrInvalidToken
	}
	counter := uint64(at.Unix()) / uint64(t.period().Seconds())
	return hotp(key, counter, t.digits()), nil
}

// Validate reports whether code is valid for secret at the current time,
// tolerating ±Skew steps for clock drift. Constant-time comparison.
func (t TOTP) Validate(secret, code string, now time.Time) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	step := uint64(t.period().Seconds())
	counter := uint64(now.Unix()) / step
	skew := t.Skew
	if skew == 0 {
		skew = 1
	}
	for i := -skew; i <= skew; i++ {
		c := counter
		if i < 0 {
			c -= uint64(-i)
		} else {
			c += uint64(i)
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, c, t.digits())), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp is RFC 4226 HMAC-based OTP.
func hotp(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// AuthenticatorURI builds the otpauth:// URI for QR-code provisioning.
func AuthenticatorURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}
