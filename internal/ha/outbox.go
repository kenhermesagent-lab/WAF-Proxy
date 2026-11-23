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
	"strconv"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// The outbox carries per-record state (sessions, bans, audit, gate activity)
// from the active to the standby, a page at a time. Configuration still travels
// as a whole snapshot: it is small, changes rarely, and a snapshot is easier to
// reason about than a stream of rows.
const (
	outboxInfo    = "wafproxy-ha-outbox-v1"
	outboxVersion = 1
	outboxPage    = 500
	// maxOutboxBatch is the decompressed ceiling one page may claim.
	maxOutboxBatch = 8 << 20
)

// outboxLimit is the size at which streaming stops. It is a variable so a test
// can exercise the overflow path without writing a hundred megabytes.
var outboxLimit int64 = store.MaxOutboxBytes

var (
	// ErrOutboxOverflow means the stream grew past the plan's 100 MiB limit and
	// the standby has to take a full snapshot instead.
	ErrOutboxOverflow = errors.New("ha: outbox overflow; a snapshot is required")
)

// outboxBatch is one page of the stream. Head and Min describe the responder's
// queue, so the reader can tell a finished stream from a pruned one.
type outboxBatch struct {
	Head    int64               `json:"head"`
	Min     int64               `json:"min"`
	After   int64               `json:"after"`
	Entries []store.OutboxEntry `json:"entries"`
}

// outboxBlob is the sealed form of a batch. The cluster id stays readable so a
// batch from the wrong cluster is refused before any key work.
type outboxBlob struct {
	Version   int    `json:"v"`
	ClusterID string `json:"cluster"`
	SHA256    string `json:"sha256"`
	Payload   string `json:"payload"`
}

// ---------- server ----------

// outbox serves the stream to a paired peer. The listener's TLS config already
// pins that peer, so reaching the handler is the authorization.
func (s *JoinServer) outbox(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJoinError(w, http.StatusServiceUnavailable, "this node has no store to stream")
		return
	}
	pair, err := LoadPair(s.dataDir)
	if err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if after < 0 {
		after = 0
	}
	stats, err := s.store.OutboxStats()
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the outbox")
		return
	}
	if stats.Bytes > outboxLimit {
		s.log.Warn("ha outbox overflow; asking the standby for a snapshot",
			"bytes", stats.Bytes, "depth", stats.Depth)
		writeJoinError(w, http.StatusConflict, ErrOutboxOverflow.Error())
		return
	}
	entries, err := s.store.OutboxEntries(after, outboxPage)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the outbox")
		return
	}
	secret, err := pair.PairSecret()
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "pair secret unreadable")
		return
	}
	plain, err := json.Marshal(outboxBatch{Head: stats.MaxSeq, Min: stats.MinSeq, After: after, Entries: entries})
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot encode the outbox")
		return
	}
	raw, err := sealBlob(secret, pair.ClusterID, plain)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot seal the outbox")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// outboxAck records how far the peer has consumed this node's stream, then
// discards everything at or below it. A snapshot request also acknowledges, so
// an overflow clears itself.
func (s *JoinServer) outboxAck(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJoinError(w, http.StatusServiceUnavailable, "this node has no store to acknowledge")
		return
	}
	pair, err := LoadPair(s.dataDir)
	if err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	var in struct {
		Seq int64 `json:"seq"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil || in.Seq < 0 {
		writeJoinError(w, http.StatusBadRequest, "invalid acknowledgement")
		return
	}
	if err := s.store.AckPeer(pair.PeerFingerprint, in.Seq); err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot record the acknowledgement")
		return
	}
	if err := s.store.PruneOutbox(in.Seq); err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot prune the outbox")
		return
	}
	writeJoinJSON(w, http.StatusOK, map[string]int64{"acked": in.Seq})
}

// ---------- client ----------

// peerConn is the pinned connection to the paired node.
type peerConn struct {
	pair   *Pair
	secret []byte
	client *http.Client
}

func dialPeer(dataDir string, timeout time.Duration) (*peerConn, error) {
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
	return &peerConn{
		pair:   pair,
		secret: secret,
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: id.ClientConfig(pair.PeerFingerprint)},
		},
	}, nil
}

// SyncResult reports what one catch-up pass did.
type SyncResult struct {
	Applied  int   `json:"applied"`
	AckedSeq int64 `json:"acked_seq"`
	// Snapshot is true when the outbox could not be used and a full snapshot
	// was applied instead.
	Snapshot bool `json:"snapshot"`
	// ConfigHash is the configuration the copy now holds. The loop remembers it
	// so an unchanged configuration does not trigger another restore.
	ConfigHash string `json:"config_hash,omitempty"`
}

// configVersion is the active's cheap answer to "has configuration changed?"
// and to "does this pair still agree on the basics?".
type configVersion struct {
	Hash      string `json:"hash"`
	OutboxSeq int64  `json:"outbox_seq"`
	Time      string `json:"time"`
	ClusterID string `json:"cluster_id"`
	Epoch     int64  `json:"epoch"`
	Schema    string `json:"schema"`
	Protocol  int    `json:"protocol"`
}

// SyncOnce applies one page from the peer and acknowledges it. A gap or an
// overflow falls back to a sealed snapshot, which is the only way back to a
// consistent state when the stream no longer starts where this node left off.
// It is safe on a standby; an active node must not run it.
func SyncOnce(ctx context.Context, dataDir string, st *store.Store) (SyncResult, error) {
	var res SyncResult
	conn, err := dialPeer(dataDir, 30*time.Second)
	if err != nil {
		return res, err
	}
	after, _, err := st.PeerAck(conn.pair.PeerFingerprint)
	if err != nil {
		return res, err
	}
	batch, err := fetchOutbox(ctx, conn, after)
	if errors.Is(err, ErrOutboxOverflow) {
		return resyncFromSnapshot(ctx, st, conn)
	}
	if err != nil {
		return res, err
	}
	if batch.After != after {
		return res, fmt.Errorf("ha: the peer answered for seq %d, asked for %d", batch.After, after)
	}
	// The retained stream starts after the next change this node needs: the
	// changes in between are gone, so only a snapshot can repair the copy.
	if batch.Head > after && (batch.Min == 0 || batch.Min > after+1) {
		return resyncFromSnapshot(ctx, st, conn)
	}
	if len(batch.Entries) == 0 {
		return res, nil
	}
	if batch.Entries[0].Seq != after+1 {
		return resyncFromSnapshot(ctx, st, conn)
	}
	for i, e := range batch.Entries {
		if e.Seq != after+1+int64(i) {
			return resyncFromSnapshot(ctx, st, conn)
		}
	}
	applied, err := st.ApplyOutbox(batch.Entries)
	if err != nil {
		// A batch that cannot be applied - a session whose user only exists in a
		// configuration snapshot the standby has not pulled yet, or a row the
		// local schema rejects - is a consistency problem no retry can fix.
		// Replacing the copy from a snapshot repairs it and resets the stream.
		return resyncFromSnapshot(ctx, st, conn)
	}
	next := after + int64(len(batch.Entries))
	if err := st.AckPeer(conn.pair.PeerFingerprint, next); err != nil {
		return res, err
	}
	_ = st.PruneApplied(next)
	if err := sendAck(ctx, conn, next); err != nil {
		return res, err
	}
	res.Applied = applied.Applied
	res.AckedSeq = next
	return res, nil
}

// resyncFromSnapshot replaces this node's copy with a sealed snapshot and
// acknowledges the stream position the snapshot already contains. It reuses the
// connection that just failed, so a repair costs one handshake, not two.
func resyncFromSnapshot(ctx context.Context, st *store.Store, conn *peerConn) (SyncResult, error) {
	snap, err := fetchSnapshot(ctx, conn)
	if err != nil {
		return SyncResult{}, err
	}
	return applySnapshot(ctx, conn, st, snap)
}

// SyncSnapshotOnce pulls the whole database and applies it. Configuration still
// travels this way because it changes rarely and a snapshot is easier to verify
// than a stream; the outbox covers the per-record state. A copy newer than the
// snapshot is kept, so an in-flight snapshot can never roll the standby back.
func SyncSnapshotOnce(ctx context.Context, dataDir string, st *store.Store) (SyncResult, error) {
	conn, err := dialPeer(dataDir, 60*time.Second)
	if err != nil {
		return SyncResult{}, err
	}
	watermark, _, err := st.PeerAck(conn.pair.PeerFingerprint)
	if err != nil {
		return SyncResult{}, err
	}
	snap, err := fetchSnapshot(ctx, conn)
	if err != nil {
		return SyncResult{}, err
	}
	if snap.OutboxSeq < watermark {
		return SyncResult{AckedSeq: watermark}, nil
	}
	return applySnapshot(ctx, conn, st, snap)
}

// applySnapshot restores a snapshot and tells the active it may prune through
// the position the snapshot already contains.
func applySnapshot(ctx context.Context, conn *peerConn, st *store.Store, snap *store.Snapshot) (SyncResult, error) {
	res := SyncResult{Snapshot: true}
	if err := st.Restore(snap); err != nil {
		return res, err
	}
	if err := st.AckPeer(conn.pair.PeerFingerprint, snap.OutboxSeq); err != nil {
		return res, err
	}
	if err := sendAck(ctx, conn, snap.OutboxSeq); err != nil {
		return res, err
	}
	res.AckedSeq = snap.OutboxSeq
	res.ConfigHash = snap.ConfigHash
	return res, nil
}

func fetchOutbox(ctx context.Context, conn *peerConn, after int64) (*outboxBatch, error) {
	url := "https://" + conn.pair.PeerAddr + "/ha/outbox?after=" + strconv.FormatInt(after, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := conn.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha: fetch outbox: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*maxOutboxBatch))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		// 409 is the peer asking for a snapshot: either the stream outgrew its
		// ceiling or it no longer starts where this node is. Both are repaired
		// the same way, so the sentinel has to survive the message.
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%w: %s", ErrOutboxOverflow, e.Error)
		}
		return nil, ErrOutboxOverflow
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("ha: outbox refused: %s", e.Error)
		}
		return nil, fmt.Errorf("ha: outbox refused with status %d", resp.StatusCode)
	}
	plain, err := openBlob(conn.secret, conn.pair.ClusterID, raw)
	if err != nil {
		return nil, err
	}
	var batch outboxBatch
	if err := json.Unmarshal(plain, &batch); err != nil {
		return nil, err
	}
	return &batch, nil
}

func sendAck(ctx context.Context, conn *peerConn, seq int64) error {
	body, err := json.Marshal(map[string]int64{"seq": seq})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+conn.pair.PeerAddr+"/ha/outbox/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := conn.client.Do(req)
	if err != nil {
		return fmt.Errorf("ha: acknowledge outbox: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ha: acknowledgement refused with status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// ConfigVersion asks the active for a digest of its configuration. It is a few
// hundred bytes, so a standby can poll it every 30 seconds without moving the
// database or touching a single session row.
func ConfigVersion(ctx context.Context, dataDir string) (*configVersion, error) {
	conn, err := dialPeer(dataDir, 15*time.Second)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+conn.pair.PeerAddr+"/ha/config", nil)
	if err != nil {
		return nil, err
	}
	resp, err := conn.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha: fetch config version: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ha: config version refused with status %d", resp.StatusCode)
	}
	var v configVersion
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// configHandler answers the cheap poll. The pinned TLS listener is the
// authorization, as on the other link endpoints; the answer carries no data.
func (s *JoinServer) configHandler(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJoinError(w, http.StatusServiceUnavailable, "this node has no store to describe")
		return
	}
	if pair, err := LoadPair(s.dataDir); err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	hash, err := s.store.ConfigHash()
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot hash the configuration")
		return
	}
	seq, err := s.store.OutboxSeq()
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the outbox")
		return
	}
	node, err := Load(s.dataDir)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the node role")
		return
	}
	pair, err := LoadPair(s.dataDir)
	if err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	writeJoinJSON(w, http.StatusOK, configVersion{
		Hash: hash, OutboxSeq: seq, Time: time.Now().UTC().Format(time.RFC3339Nano),
		ClusterID: pair.ClusterID, Epoch: node.Epoch,
		Schema: store.SchemaVersion(), Protocol: ProtocolVersion,
	})
}

// OutboxLoop keeps a standby current in near real time, and takes a full
// snapshot every snapshotEvery ticks only when the active's configuration hash
// has actually changed. A failed pass backs off up to 30 seconds instead of
// hammering an unreachable peer.
func OutboxLoop(ctx context.Context, dataDir string, st *store.Store, interval time.Duration, snapshotEvery int, onErr func(error)) {
	if interval <= 0 {
		interval = time.Second
	}
	if snapshotEvery < 1 {
		snapshotEvery = 30
	}
	failures := 0
	ticks := 0
	// Empty means no snapshot has been applied yet, so the first tick pulls one.
	configHash := ""
	for {
		var err error
		if ticks%snapshotEvery == 0 {
			version, verr := ConfigVersion(ctx, dataDir)
			if verr == nil && version.Hash != "" && version.Hash == configHash {
				// Configuration is unchanged: keep the copy, leave its session
				// table and everything else the stream already updated alone.
			} else {
				var res SyncResult
				res, err = SyncSnapshotOnce(ctx, dataDir, st)
				if err == nil && res.ConfigHash != "" {
					configHash = res.ConfigHash
				} else if verr == nil {
					configHash = version.Hash
				}
			}
		} else {
			_, err = SyncOnce(ctx, dataDir, st)
		}
		ticks++
		wait := interval
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			if onErr != nil {
				onErr(err)
			}
			backoff := interval * time.Duration(min(failures, 30))
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			wait = backoff
		} else {
			failures = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// ---------- sealing ----------

func outboxKey(secret []byte, clusterID string) ([]byte, error) {
	if len(secret) != 32 {
		return nil, errors.New("ha: outbox sealing needs the 32-byte cluster secret")
	}
	salt := sha256.Sum256([]byte("wafproxy-ha-outbox-salt\x00" + clusterID))
	return hkdf.Key(sha256.New, secret, salt[:], outboxInfo, 32)
}

func sealBlob(secret []byte, clusterID string, plain []byte) ([]byte, error) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	key, err := outboxKey(secret, clusterID)
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
	sum := sha256.Sum256(plain)
	hash := hex.EncodeToString(sum[:])
	sealed := gcm.Seal(nonce, nonce, compressed.Bytes(), []byte(clusterID+"\x00"+hash))
	return json.Marshal(outboxBlob{
		Version: outboxVersion, ClusterID: clusterID, SHA256: hash,
		Payload: base64.StdEncoding.EncodeToString(sealed),
	})
}

func openBlob(secret []byte, clusterID string, raw []byte) ([]byte, error) {
	var blob outboxBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, errors.New("ha: malformed outbox batch")
	}
	if blob.Version != outboxVersion {
		return nil, fmt.Errorf("ha: outbox version %d is not supported", blob.Version)
	}
	if blob.ClusterID != clusterID {
		return nil, errors.New("ha: outbox batch belongs to another cluster")
	}
	sealed, err := base64.StdEncoding.DecodeString(blob.Payload)
	if err != nil {
		return nil, errors.New("ha: malformed outbox payload")
	}
	key, err := outboxKey(secret, clusterID)
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
		return nil, errors.New("ha: truncated outbox batch")
	}
	compressed, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():],
		[]byte(clusterID+"\x00"+blob.SHA256))
	if err != nil {
		return nil, errors.New("ha: the outbox batch did not authenticate")
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, maxOutboxBatch+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > maxOutboxBatch {
		return nil, errors.New("ha: outbox batch is larger than 8 MiB")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != blob.SHA256 {
		return nil, errors.New("ha: outbox batch hash mismatch")
	}
	return plain, nil
}
