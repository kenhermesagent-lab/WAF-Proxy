package ha

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// joinRequest is what a joining node proves: who it is, the key it will pin,
// and the one-time code the active printed.
type joinRequest struct {
	NodeID      string `json:"node_id"`
	Fingerprint string `json:"fingerprint"`
	Code        string `json:"code"`
}

type joinReply struct {
	ClusterID   string `json:"cluster_id"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
	NodeID      string `json:"node_id"`
	// MasterKey is the active's master key sealed under the cluster secret.
	MasterKey string `json:"master_key,omitempty"`
}

// JoinServer answers /ha/join on the HA link. It is separate from the console
// on purpose: the join endpoint must never be reachable through the admin UI.
type JoinServer struct {
	id        *Identity
	dataDir   string
	masterKey []byte
	store     *store.Store
	log       *slog.Logger
	limit     *attemptLimiter
	quiesce   *Quiesce
}

// NewJoinServer builds the handler for one node. masterKey is handed to a
// joining node sealed under the cluster secret; nil sends none, leaving the
// operator to copy the key out of band.
func NewJoinServer(id *Identity, dataDir string, masterKey []byte, st *store.Store, log *slog.Logger) *JoinServer {
	if log == nil {
		log = slog.Default()
	}
	return &JoinServer{id: id, dataDir: dataDir, masterKey: masterKey, store: st, log: log, limit: newAttemptLimiter(5, 10*time.Minute)}
}

// TLSConfig requires a client certificate and pins the peer once a pair exists.
func (s *JoinServer) TLSConfig() *tls.Config {
	pin := ""
	if p, err := LoadPair(s.dataDir); err == nil && p != nil {
		pin = p.PeerFingerprint
	}
	return s.id.ServerConfig(pin)
}

// Handler serves the join endpoint. Everything else is a 404: this listener has
// exactly one job.
func (s *JoinServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ha/join", s.join)
	mux.HandleFunc("GET /ha/snapshot", s.snapshot)
	mux.HandleFunc("GET /ha/outbox", s.outbox)
	mux.HandleFunc("POST /ha/outbox/ack", s.outboxAck)
	mux.HandleFunc("GET /ha/config", s.configHandler)
	mux.HandleFunc("POST /ha/quiesce", s.quiesceNode)
	return mux
}

func (s *JoinServer) join(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.limit.allow(host, time.Now()) {
		writeJoinError(w, http.StatusTooManyRequests, "too many pairing attempts")
		return
	}
	var req joinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJoinError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.NodeID == "" || len(req.Fingerprint) != 64 {
		writeJoinError(w, http.StatusBadRequest, "node id and fingerprint are required")
		return
	}
	if err := CheckPairingCode(s.dataDir, req.Code); err != nil {
		s.log.Warn("pairing attempt refused", "from", host, "err", err)
		writeJoinError(w, http.StatusForbidden, err.Error())
		return
	}

	pair, err := LoadPair(s.dataDir)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "pair record unreadable")
		return
	}
	if pair == nil {
		pair, err = NewPair(s.id.Node, host, normalizeFingerprint(req.Fingerprint))
		if err != nil {
			writeJoinError(w, http.StatusInternalServerError, "cannot create the pair")
			return
		}
	} else {
		pair.PeerAddr = host
		pair.PeerFingerprint = normalizeFingerprint(req.Fingerprint)
	}
	if err := SavePair(s.dataDir, pair); err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot save the pair")
		return
	}
	ClearPairingCode(s.dataDir)
	reply := joinReply{
		ClusterID: pair.ClusterID, Secret: pair.Secret,
		Fingerprint: Fingerprint(s.id.Leaf), NodeID: s.id.Node,
	}
	if len(s.masterKey) == 32 {
		secret, err := pair.PairSecret()
		if err != nil {
			writeJoinError(w, http.StatusInternalServerError, "pair secret unreadable")
			return
		}
		blob, err := SealMasterKey(secret, pair.ClusterID, s.masterKey)
		if err != nil {
			writeJoinError(w, http.StatusInternalServerError, "cannot seal the master key")
			return
		}
		reply.MasterKey = blob
	}
	s.log.Info("node joined the pair", "peer", pair.PeerAddr, "node", req.NodeID)
	writeJoinJSON(w, http.StatusOK, reply)
}

// snapshot serves the replicated tables to a paired peer. The listener's TLS
// config already pins that peer, so reaching the handler is the authorization.
func (s *JoinServer) snapshot(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJoinError(w, http.StatusServiceUnavailable, "this node has no store to snapshot")
		return
	}
	pair, err := LoadPair(s.dataDir)
	if err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	secret, err := pair.PairSecret()
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "pair secret unreadable")
		return
	}
	snap, err := s.store.Snapshot()
	if err != nil {
		s.log.Error("snapshot failed", "err", err)
		writeJoinError(w, http.StatusInternalServerError, "cannot build a snapshot")
		return
	}
	raw, err := SealSnapshot(secret, pair.ClusterID, snap)
	if err != nil {
		s.log.Error("sealing the snapshot failed", "err", err)
		writeJoinError(w, http.StatusInternalServerError, "cannot seal the snapshot")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// Join pairs this node with an active one. It pins the active's fingerprint, so
// a machine-in-the-middle cannot substitute its own key during the exchange.
func Join(ctx context.Context, dataDir, activeAddr, pin, code string) (*Pair, error) {
	if err := validatePeerAddr(activeAddr); err != nil {
		return nil, err
	}
	if normalizeFingerprint(pin) == "" {
		return nil, errors.New("ha: the active node's fingerprint is required")
	}
	id, err := LoadOrCreateIdentity(dataDir)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(joinRequest{NodeID: id.Node, Fingerprint: Fingerprint(id.Leaf), Code: strings.TrimSpace(code)})
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: id.ClientConfig(pin)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+activeAddr+"/ha/join", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ha: join %s: %w", activeAddr, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("ha: join refused: %s", e.Error)
		}
		return nil, fmt.Errorf("ha: join refused with status %d", resp.StatusCode)
	}
	var reply joinReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	secret, err := hex.DecodeString(reply.Secret)
	if err != nil || len(secret) != 32 {
		return nil, errors.New("ha: the active node returned a malformed cluster secret")
	}
	pair := &Pair{
		ClusterID: reply.ClusterID, NodeID: id.Node, PeerAddr: activeAddr,
		PeerFingerprint: normalizeFingerprint(reply.Fingerprint), Secret: reply.Secret,
	}
	if reply.Fingerprint != normalizeFingerprint(pin) {
		return nil, fmt.Errorf("ha: the active node's fingerprint %s does not match the pinned %s", reply.Fingerprint, pin)
	}
	if reply.MasterKey != "" {
		master, err := OpenMasterKey(secret, reply.ClusterID, reply.MasterKey)
		if err != nil {
			return nil, err
		}
		if err := SaveMasterKey(dataDir, master); err != nil {
			return nil, err
		}
	}
	if err := SavePair(dataDir, pair); err != nil {
		return nil, err
	}
	return pair, nil
}

// attemptLimiter slows repeated join guesses from one address.
type attemptLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newAttemptLimiter(limit int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (l *attemptLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func writeJoinError(w http.ResponseWriter, status int, message string) {
	writeJoinJSON(w, status, map[string]string{"error": message})
}

func writeJoinJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
