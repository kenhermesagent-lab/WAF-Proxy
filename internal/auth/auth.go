// Package auth implements password hashing, TOTP and login rate limiting.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. 64 MiB, 3 passes, 2 lanes.
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// HashPassword returns an argon2id encoded hash.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded argon2id hash in
// constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewTOTPSecret returns a fresh base32 TOTP secret.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// TOTPCode computes the 6 digit code for a secret and time.
func TOTPCode(secret string, at time.Time) (string, error) {
	raw, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("invalid totp secret: %w", err)
	}
	counter := uint64(at.Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, raw)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// ValidateTOTPStep accepts the current code and one step either side, and
// returns the time step it matched so the caller can refuse to accept the same
// code twice.
func ValidateTOTPStep(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return 0, false
	}
	for _, delta := range []int64{-1, 0, 1} {
		when := at.Add(time.Duration(delta) * 30 * time.Second)
		want, err := TOTPCode(secret, when)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return when.Unix() / 30, true
		}
	}
	return 0, false
}

// ValidateTOTP reports whether a code is currently valid.
func ValidateTOTP(secret, code string, at time.Time) bool {
	_, ok := ValidateTOTPStep(secret, code, at)
	return ok
}

// OTPAuthURL builds the provisioning URI for authenticator apps.
func OTPAuthURL(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, account, secret, issuer)
}

// NewRecoveryCodes returns ten single-use codes and their stored hash form.
// The plaintext codes are shown to the operator exactly once.
func NewRecoveryCodes() (plain []string, stored string, err error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		buf := make([]byte, 5)
		if _, err := rand.Read(buf); err != nil {
			return nil, "", err
		}
		code := strings.ToUpper(hex.EncodeToString(buf))
		codes[i] = code[:5] + "-" + code[5:]
		sum := sha256.Sum256([]byte(codes[i]))
		hashes[i] = hex.EncodeToString(sum[:])
	}
	return codes, strings.Join(hashes, ","), nil
}

// ConsumeRecoveryCode verifies a recovery code and returns the remaining
// hashes with the used one removed. A code can therefore only be used once.
func ConsumeRecoveryCode(stored, candidate string) (string, bool) {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(candidate))))
	want := hex.EncodeToString(sum[:])
	matched := false
	kept := []string{}
	for _, h := range strings.Split(stored, ",") {
		if h == "" {
			continue
		}
		if !matched && subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			matched = true
			continue
		}
		kept = append(kept, h)
	}
	if !matched {
		return stored, false
	}
	return strings.Join(kept, ","), true
}

// DummyVerify performs one argon2id derivation so a login attempt for an
// unknown username costs the same as one for a real account.
func DummyVerify(password string) {
	salt := []byte("wafproxy-dummy!!")
	_ = argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}
