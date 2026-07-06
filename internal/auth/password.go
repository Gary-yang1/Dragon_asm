package auth

import "golang.org/x/crypto/bcrypt"

// bcryptCost is the work factor for password hashing. bcrypt.DefaultCost (10) is
// a sound baseline; it is named here so the choice is explicit and adjustable.
const bcryptCost = bcrypt.DefaultCost

// HashPassword returns a bcrypt hash of the plaintext password. The cost is
// embedded in the returned hash, so CheckPassword needs no external parameter.
func HashPassword(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword reports whether plaintext matches the stored bcrypt hash. It
// returns false (never an error) on any mismatch or malformed hash, so callers
// can treat authentication as a boolean without leaking the failure reason.
func CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// dummyHash is a valid bcrypt hash of a random string, used by the login service
// to perform a constant-time-ish compare when the username does not exist. This
// keeps the "unknown user" and "wrong password" paths similar in cost, reducing
// username-enumeration via response timing. It is not a secret.
var dummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
