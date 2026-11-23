package ha

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

const (
	snapshotInfo    = "wafproxy-ha-snapshot-v1"
	snapshotVersion = 1
	// maxSnapshot is the decompressed ceiling the plan fixes at 64 MiB.
	maxSnapshot = 64 << 20
)

// snapshotEnvelope carries a compressed snapshot sealed under the cluster
// secret. The header stays readable so a wrong cluster or schema fails before
// any decryption work.
type snapshotEnvelope struct {
	Version   int    `json:"v"`
	ClusterID string `json:"cluster"`
	Schema    string `json:"schema"`
	CreatedAt string `json:"created_at"`
	SHA256    string `json:"sha256"`
	Payload   string `json:"payload"`
}

// SealSnapshot compresses and encrypts a snapshot for the peer.
func SealSnapshot(secret []byte, clusterID string, snap *store.Snapshot) ([]byte, error) {
	if snap == nil {
		return nil, errors.New("ha: no snapshot")
	}
	plain, err := store.MarshalSnapshot(snap)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(plain)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	key, err := snapshotKey(secret, clusterID)
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
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := snapshotAAD(clusterID, snap.SchemaVersion, snap.CreatedAt, hex.EncodeToString(sum[:]))
	sealed := gcm.Seal(nonce, nonce, compressed.Bytes(), []byte(aad))
	return json.Marshal(snapshotEnvelope{
		Version: snapshotVersion, ClusterID: clusterID, Schema: snap.SchemaVersion,
		CreatedAt: snap.CreatedAt, SHA256: hex.EncodeToString(sum[:]),
		Payload: base64.StdEncoding.EncodeToString(sealed),
	})
}

// OpenSnapshot verifies and decrypts a snapshot received from the peer.
func OpenSnapshot(secret []byte, clusterID string, raw []byte) (*store.Snapshot, error) {
	var env snapshotEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("ha: malformed snapshot envelope")
	}
	if env.Version != snapshotVersion {
		return nil, fmt.Errorf("ha: snapshot version %d is not supported", env.Version)
	}
	if env.ClusterID != clusterID {
		return nil, errors.New("ha: snapshot belongs to another cluster")
	}
	if env.Schema != store.SchemaVersion() {
		return nil, fmt.Errorf("ha: snapshot schema %q does not match this node's %q", env.Schema, store.SchemaVersion())
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, errors.New("ha: malformed snapshot payload")
	}
	key, err := snapshotKey(secret, clusterID)
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
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ha: truncated snapshot")
	}
	aad := snapshotAAD(env.ClusterID, env.Schema, env.CreatedAt, env.SHA256)
	compressed, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(aad))
	if err != nil {
		return nil, errors.New("ha: the snapshot did not authenticate")
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, maxSnapshot+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > maxSnapshot {
		return nil, errors.New("ha: snapshot is larger than 64 MiB")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != env.SHA256 {
		return nil, errors.New("ha: snapshot hash mismatch")
	}
	var snap store.Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// Pull fetches the peer's snapshot and applies it to this node's store. It is
// only safe on a standby, which is why the caller checks the role first.
func Pull(ctx context.Context, dataDir string, st *store.Store) (*store.Snapshot, error) {
	pair, err := LoadPair(dataDir)
	if err != nil {
		return nil, err
	}
	if pair == nil {
		return nil, errors.New("ha: this node is not paired")
	}
	secret, err := pair.PairSecret()
	if err != nil {
		return nil, err
	}
	id, err := LoadOrCreateIdentity(dataDir)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: id.ClientConfig(pair.PeerFingerprint)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+pair.PeerAddr+"/ha/snapshot", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha: fetch snapshot: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*maxSnapshot))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("ha: snapshot refused: %s", e.Error)
		}
		return nil, fmt.Errorf("ha: snapshot refused with status %d", resp.StatusCode)
	}
	snap, err := OpenSnapshot(secret, pair.ClusterID, raw)
	if err != nil {
		return nil, err
	}
	if err := st.Restore(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// SyncLoop pulls a snapshot every interval until ctx ends. It is the temporary
// bridge until the row-level outbox lands: a failover can lose the writes made
// in the last interval.
func SyncLoop(ctx context.Context, dataDir string, st *store.Store, interval time.Duration, onErr func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := Pull(ctx, dataDir, st); err != nil && ctx.Err() == nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func snapshotKey(secret []byte, clusterID string) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("ha: snapshot sealing needs the 32-byte cluster secret")
	}
	salt := sha256.Sum256([]byte("wafproxy-ha-snapshot-salt\x00" + clusterID))
	return hkdf.Key(sha256.New, secret, salt[:], snapshotInfo, 32)
}

func snapshotAAD(clusterID, schema, createdAt, hash string) string {
	return clusterID + "\x00" + schema + "\x00" + createdAt + "\x00" + hash
}
