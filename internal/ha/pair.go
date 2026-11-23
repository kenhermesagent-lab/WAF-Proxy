package ha

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Pair is one node's record of the other. It is node-local: the cluster secret
// is shared, but each side pins the other's fingerprint separately.
type Pair struct {
	ClusterID       string `json:"cluster_id"`
	NodeID          string `json:"node_id"`
	PeerAddr        string `json:"peer_addr"`
	PeerFingerprint string `json:"peer_fingerprint"`
	Secret          string `json:"secret"`
	CreatedAt       string `json:"created_at"`
}

// LoadPair returns the pair record, or nil when this node is not paired.
func LoadPair(dataDir string) (*Pair, error) {
	raw, err := os.ReadFile(filepath.Join(RoleDir(dataDir), "pair.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pair
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.ClusterID == "" || p.PeerFingerprint == "" || !validSecret(p.Secret) {
		return nil, errors.New("ha: malformed pair file")
	}
	return &p, nil
}

// SavePair writes the pair record atomically with owner-only permissions.
func SavePair(dataDir string, p *Pair) error {
	if p.ClusterID == "" || p.PeerFingerprint == "" || !validSecret(p.Secret) {
		return errors.New("ha: incomplete pair record")
	}
	if p.CreatedAt == "" {
		p.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	dir := RoleDir(dataDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "pair.json"), raw)
}

// NewPair returns a pair record with a fresh cluster id and 256-bit secret.
func NewPair(nodeID, peerAddr, peerFingerprint string) (*Pair, error) {
	cluster := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(cluster); err != nil {
		return nil, err
	}
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &Pair{
		ClusterID:       hex.EncodeToString(cluster),
		NodeID:          nodeID,
		PeerAddr:        peerAddr,
		PeerFingerprint: peerFingerprint,
		Secret:          hex.EncodeToString(secret),
	}, nil
}

const masterKeyInfo = "wafproxy-ha-masterkey-v1"

// SealMasterKey encrypts the master key for the joining node. The key never
// appears in the clear on the wire, even inside TLS: only a node holding the
// cluster secret can open it.
func SealMasterKey(secret []byte, clusterID string, key []byte) (string, error) {
	if len(secret) != 32 || len(key) != 32 {
		return "", errors.New("ha: sealing needs a 32-byte cluster secret and a 32-byte master key")
	}
	salt := sha256.Sum256([]byte("wafproxy-ha-salt\x00" + clusterID))
	derived, err := hkdf.Key(sha256.New, secret, salt[:], masterKeyInfo, 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, key, []byte(clusterID))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenMasterKey reverses SealMasterKey.
func OpenMasterKey(secret []byte, clusterID, blob string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, errors.New("ha: malformed master-key envelope")
	}
	salt := sha256.Sum256([]byte("wafproxy-ha-salt\x00" + clusterID))
	derived, err := hkdf.Key(sha256.New, secret, salt[:], masterKeyInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ha: truncated master-key envelope")
	}
	key, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(clusterID))
	if err != nil {
		return nil, errors.New("ha: the master-key envelope did not authenticate")
	}
	if len(key) != 32 {
		return nil, errors.New("ha: the master key is not 32 bytes")
	}
	return key, nil
}

// SaveMasterKey stores the cluster's master key in data/ha/master.key, which
// the service prefers over a locally generated data/master.key. It refuses to
// replace a different key: silently overwriting it would make every secret
// already sealed on this node unreadable.
func SaveMasterKey(dataDir string, key []byte) error {
	if len(key) != 32 {
		return errors.New("ha: master key must be 32 bytes")
	}
	path := filepath.Join(RoleDir(dataDir), "master.key")
	encoded := base64.StdEncoding.EncodeToString(key)
	if existing, err := os.ReadFile(path); err == nil {
		if subtle.ConstantTimeCompare(bytesTrimSpace(existing), []byte(encoded)) == 1 {
			return nil
		}
		return errors.New("ha: this node already has a different master key; move data/ha/master.key aside to adopt the cluster key")
	}
	if err := os.MkdirAll(RoleDir(dataDir), 0o700); err != nil {
		return err
	}
	return writeAtomic(path, []byte(encoded))
}

// LoadMasterKey reads data/ha/master.key, or returns nil when absent.
func LoadMasterKey(dataDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(RoleDir(dataDir), "master.key"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(string(bytesTrimSpace(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("ha: data/ha/master.key is corrupt")
	}
	return key, nil
}

// Unpair detaches this node from its peer. The role and the master key are
// deliberately kept: an active node must not stop serving because its operator
// removed the pairing, and the key may still decrypt local data.
func Unpair(dataDir string) error {
	for _, name := range []string{"pair.json", "pairing.json"} {
		if err := os.Remove(filepath.Join(RoleDir(dataDir), name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	node, err := Load(dataDir)
	if err != nil {
		return nil // a damaged role file already means standby; nothing to clear
	}
	if node.Peer == "" {
		return nil
	}
	node.Peer = ""
	return Save(dataDir, node)
}

func bytesTrimSpace(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

// validSecret accepts exactly 32 bytes, hex encoded (64 characters).
func validSecret(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32
}

// PairSecret decodes the stored hex secret.
func (p *Pair) PairSecret() ([]byte, error) {
	return hex.DecodeString(p.Secret)
}

// NewPairingCode returns a 128-bit code in five groups, prefixed so an
// operator recognises it as a pairing code rather than a password.
func NewPairingCode() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	groups := make([]string, 0, len(raw)/4)
	for len(raw) > 4 {
		groups = append(groups, raw[:4])
		raw = raw[4:]
	}
	groups = append(groups, raw)
	return "WAF-" + strings.Join(groups, "-"), nil
}

type pendingCode struct {
	Hash      string `json:"hash"`
	ExpiresAt string `json:"expires_at"`
}

// PairingCodeTTL is how long a pending pairing code stays usable.
const PairingCodeTTL = 10 * time.Minute

// WritePairingCode stores a hash of a fresh code with a short expiry. Only the
// hash is written, so a copy of the data directory cannot be used to join.
func WritePairingCode(dataDir string) (string, error) {
	code, err := NewPairingCode()
	if err != nil {
		return "", err
	}
	p := pendingCode{Hash: codeHash(code), ExpiresAt: time.Now().Add(PairingCodeTTL).UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(RoleDir(dataDir), 0o700); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(RoleDir(dataDir), "pairing.json"), raw); err != nil {
		return "", err
	}
	return code, nil
}

// CheckPairingCode reports whether code is the unexpired pending code.
func CheckPairingCode(dataDir, code string) error {
	raw, err := os.ReadFile(filepath.Join(RoleDir(dataDir), "pairing.json"))
	if err != nil {
		return errors.New("ha: no pairing code on this node")
	}
	var p pendingCode
	if err := json.Unmarshal(raw, &p); err != nil {
		return errors.New("ha: unreadable pairing code")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || time.Now().After(expires) {
		return errors.New("ha: pairing code expired")
	}
	if !hmac.Equal([]byte(codeHash(code)), []byte(p.Hash)) {
		return errors.New("ha: wrong pairing code")
	}
	return nil
}

// ClearPairingCode removes the pending code after a successful join.
func ClearPairingCode(dataDir string) {
	_ = os.Remove(filepath.Join(RoleDir(dataDir), "pairing.json"))
}

func codeHash(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	sum := sha256.Sum256([]byte("wafproxy-pairing\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

// writeAtomic writes data through a temporary file, fsyncs it and renames it.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// validatePeerAddr rejects a join target without a host and port.
func validatePeerAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("ha: peer address %q must be host:port", addr)
	}
	return nil
}
