package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// envelope is the signed wrapper around a manifest. The payload is base64 of
// the exact signed bytes: encoding/json compacts a json.RawMessage while
// marshalling, which would silently change the bytes the signature covers.
type envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id,omitempty"`
}

// GenerateKey returns a new ed25519 key pair for a publisher.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// PrivateKeyHex renders a private key as hex for a file or environment
// variable.
func PrivateKeyHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv)
}

// ParsePrivateKey accepts a hex or base64 ed25519 private key, either the raw
// 64-byte form or the 32-byte seed.
func ParsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty private key")
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, err
	}
	switch len(key) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(key), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(key), nil
	}
	return nil, fmt.Errorf("ed25519 private key is %d bytes, want %d or %d", len(key), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// ParsePublicKey accepts a hex or base64 ed25519 public key.
func ParsePublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty public key")
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func decodeKey(raw string) ([]byte, error) {
	if len(raw)%2 == 0 {
		if key, err := hex.DecodeString(raw); err == nil {
			return key, nil
		}
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return key, nil
	}
	if key, err := base64.RawStdEncoding.DecodeString(raw); err == nil {
		return key, nil
	}
	return nil, errors.New("key is neither hex nor base64")
}

// KeyID is a short, stable fingerprint shown in the console so an operator can
// confirm which publisher signed the channel.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// SignManifest serialises a manifest and signs it. The result is the file the
// channel serves.
func SignManifest(m Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("signing needs a full ed25519 private key")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	env := envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
		KeyID:     KeyID(priv.Public().(ed25519.PublicKey)),
	}
	return json.MarshalIndent(env, "", "  ")
}

// ParseManifest verifies the signature before it decodes the payload. A
// manifest whose signature does not match is rejected wholesale.
func ParseManifest(data []byte, pub ed25519.PublicKey) (Manifest, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Manifest{}, errors.New("no publisher key configured")
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest envelope: %w", err)
	}
	if env.Payload == "" {
		return Manifest{}, errors.New("manifest has no payload")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Manifest{}, fmt.Errorf("decode manifest payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return Manifest{}, fmt.Errorf("decode manifest signature: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return Manifest{}, errors.New("manifest signature does not match the publisher key")
	}
	var m Manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	return m, nil
}
