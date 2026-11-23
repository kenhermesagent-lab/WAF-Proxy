package ha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Quiesce stops a node from accepting new configuration writes while a move is
// prepared. Reads and the HA routes stay open, so the operator can still see
// what is happening and reverse it. It is deliberately in memory: a crash
// releases it, and a crashed node is not serving anyway.
type Quiesce struct {
	on atomic.Bool
}

// NewQuiesce returns an open gate.
func NewQuiesce() *Quiesce { return &Quiesce{} }

// Set stops or resumes writes.
func (q *Quiesce) Set(v bool) { q.on.Store(v) }

// Active reports whether writes are currently refused. A nil gate is open, so a
// build or test without HA behaves as before.
func (q *Quiesce) Active() bool { return q != nil && q.on.Load() }

// SetQuiesce installs the gate the link's quiesce endpoint flips.
func (s *JoinServer) SetQuiesce(q *Quiesce) { s.quiesce = q }

// quiesceNode is the peer half of a planned move: the promoting node asks the
// active to stop writing, then drains its stream. The pinned TLS listener is
// the authorization.
func (s *JoinServer) quiesceNode(w http.ResponseWriter, r *http.Request) {
	if pair, err := LoadPair(s.dataDir); err != nil || pair == nil {
		writeJoinError(w, http.StatusConflict, "this node is not paired")
		return
	}
	var in struct {
		Quiesced *bool `json:"quiesced"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in); err != nil || in.Quiesced == nil {
		writeJoinError(w, http.StatusBadRequest, "quiesced is required")
		return
	}
	if s.quiesce == nil {
		writeJoinError(w, http.StatusServiceUnavailable, "this node cannot quiesce writes")
		return
	}
	s.quiesce.Set(*in.Quiesced)
	node, err := Load(s.dataDir)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the node role")
		return
	}
	s.log.Info("configuration writes quiesced for a move", "quiesced", *in.Quiesced, "role", node.Role)
	writeJoinJSON(w, http.StatusOK, map[string]any{
		"quiesced": *in.Quiesced, "epoch": node.Epoch, "role": node.Role,
	})
}

// SetPeerQuiesced asks the paired node to stop or resume accepting writes.
func SetPeerQuiesced(ctx context.Context, dataDir string, quiesce bool) error {
	conn, err := dialPeer(dataDir, 10*time.Second)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]bool{"quiesced": quiesce})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+conn.pair.PeerAddr+"/ha/quiesce", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := conn.client.Do(req)
	if err != nil {
		return fmt.Errorf("ha: quiesce the peer: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("ha: the peer refused to quiesce: %s", e.Error)
		}
		return fmt.Errorf("ha: the peer refused to quiesce with status %d", resp.StatusCode)
	}
	return nil
}
