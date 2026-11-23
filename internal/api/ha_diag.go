package api

import (
	"net/http"
	"time"
)

// haDiagnostics reports replication without opening SQLite by hand: the outbox
// depth, its per-kind breakdown, and how far the peer has acknowledged. A single
// kind with a growing depth is how a transaction bug in one write path shows up.
func (s *Server) haDiagnostics(w http.ResponseWriter, r *http.Request) {
	status := s.haStatusOf()
	body := map[string]any{
		"enabled": status.Enabled,
		"role":    status.Role,
		"state":   status.State,
		"serving": status.Serving,
		"epoch":   status.Epoch,
		"peer":    status.Peer,
	}
	st := s.db(r).Unscoped()
	stats, err := st.OutboxStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	body["outbox"] = stats
	ack := map[string]any{"seq": int64(0)}
	if status.PeerFingerprint != "" {
		if seq, at, err := st.PeerAck(status.PeerFingerprint); err == nil {
			ack["seq"] = seq
			if !at.IsZero() {
				ack["at"] = at.UTC().Format(time.RFC3339)
			}
		}
	}
	body["ack"] = ack
	writeJSON(w, http.StatusOK, body)
}
