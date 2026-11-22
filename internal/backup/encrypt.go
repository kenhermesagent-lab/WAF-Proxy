package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// encryptedPrefix marks a file this package wrote under a passphrase, so a
// restore can tell a plain JSON backup from an encrypted one.
var encryptedPrefix = []byte("WAFPROXY-ENC1")

// IsEncrypted reports whether data is an encrypted backup.
func IsEncrypted(data []byte) bool {
	return len(data) > len(encryptedPrefix) && string(data[:len(encryptedPrefix)]) == string(encryptedPrefix)
}

// Encrypt seals a backup with AES-256-GCM. The key comes from scrypt, so a
// human-chosen passphrase is expensive to guess offline.
func Encrypt(passphrase string, plain []byte) ([]byte, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), encryptedPrefix...)
	out = append(out, salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, nil), nil
}

// Decrypt opens a file produced by Encrypt.
func Decrypt(passphrase string, data []byte) ([]byte, error) {
	const head = 16 + 12
	if !IsEncrypted(data) {
		return nil, errors.New("this file is not an encrypted backup")
	}
	body := data[len(encryptedPrefix):]
	if len(body) < head {
		return nil, errors.New("this encrypted backup is truncated")
	}
	salt, nonce, ciphertext := body[:16], body[16:head], body[head:]
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or damaged backup")
	}
	return plain, nil
}
