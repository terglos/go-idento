package identity

import (
	"crypto/sha256"
	"encoding/base64"
)

// hashRefresh stores refresh tokens hashed at rest, so a leaked DB does not
// expose usable tokens. SHA-256 is sufficient here since the token is already
// high-entropy random (no brute-force concern, unlike passwords).
func hashRefresh(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}
