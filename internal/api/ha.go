package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/rbac"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// HAOps is the process side of the HA routes. cmd/wafproxy implements it with
// the same move manager, join server and role files the CLI uses, so a click in
// the console runs the identical sequence.
type HAOps interface {
	Pair(ctx context.Context) (string, error)
	Join(ctx context.Context, addr, fingerprint, code string) error
	Sync(ctx context.Context) (ha.SyncResult, error)
	Failover(ctx context.Context, opts ha.MoveOptions) (ha.Result, error)
	Failback(ctx context.Context, opts ha.MoveOptions) (ha.Result, error)
	Retry(context.Context) error
	Unpair(ctx context.Context) error
	Notify(ctx context.Context, role string) (ha.Result, error)
	MaxFailovers() int
	SetMaxFailovers(n int) error
}

// HAEvent is one HA action taken from the console. It is process-local: a
// restart clears it, and the durable record stays in the audit log.
type HAEvent struct {
	At         string `json:"at"`
	Action     string `json:"action"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Epoch      int64  `json:"epoch,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// SetHAOps installs the process side; without it the mutating routes answer 409.
func (s *Server) SetHAOps(o HAOps) { s.haOps = o }

// SetHAChange installs the live switch the settings route calls after saving
// ha_enabled, so turning HA off stops its loops instead of only hiding it. The
// second argument is the cluster id the operator typed, if any. A refused
// change rolls the setting back and answers 409. The bool reports whether the
// caller must restart the process for the new state to take effect.
func (s *Server) SetHAChange(fn func(bool, string) (bool, error)) { s.haChange = fn }

// haStatusOf reads the live role, falling back to standalone when HA is off.
func (s *Server) haStatusOf() HAStatus {
	st := HAStatus{Role: "standalone", State: "standalone", Serving: true}
	if s.haStatus != nil {
		st = s.haStatus()
	}
	return st
}

func (s *Server) recordHAEvent(action string, res *ha.Result, err error) {
	ev := HAEvent{At: time.Now().UTC().Format(time.RFC3339), Action: action, OK: err == nil}
	if err != nil {
		ev.Error = err.Error()
	}
	if res != nil {
		ev.Epoch = res.Epoch
		ev.DurationMS = res.DurationMS
	}
	s.haMu.Lock()
	s.haLog = append([]HAEvent{ev}, s.haLog...)
	if len(s.haLog) > 20 {
		s.haLog = s.haLog[:20]
	}
	s.haMu.Unlock()
}

func (s *Server) haLogCopy() []HAEvent {
	s.haMu.Lock()
	defer s.haMu.Unlock()
	return append([]HAEvent{}, s.haLog...)
}

// haRoute serves GET /api/ha. It answers while HA is disabled too, so the page
// can explain why instead of 404ing.
func (s *Server) haRoute(w http.ResponseWriter, r *http.Request) {
	st := s.haStatusOf()
	canWrite := false
	if sess := sessionFrom(r); sess != nil {
		canWrite = sess.Can(rbac.Permission("ha", "write"))
	}
	reason := st.Reason
	switch {
	case !st.Enabled && st.Paired && !st.Serving:
		reason = "this node is a paired standby; it stays out of service while high availability is off"
	case !st.Enabled:
		reason = "high availability is turned off in Settings"
	}
	body := map[string]any{
		"enabled": st.Enabled,
		"paired":  st.Paired, "cluster_id": st.ClusterID,
		"role": st.Role, "state": st.State, "serving": st.Serving, "epoch": st.Epoch,
		"peer": st.Peer, "peer_fingerprint": st.PeerFingerprint, "reason": reason,
		"can_write": canWrite,
	}
	if st.RuntimeError != "" {
		body["runtime_error"] = st.RuntimeError
	}
	if s.haOps != nil {
		body["max_failovers_per_hour"] = s.haOps.MaxFailovers()
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) haEventsRoute(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": s.haLogCopy()})
}

type haActionRequest struct {
	ClusterID   string `json:"cluster_id"`
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	Code        string `json:"code"`
	Role        string `json:"role"`
	DryRun      bool   `json:"dry_run"`
	Force       bool   `json:"force"`
	Password    string `json:"password"`
	TOTP        string `json:"totp"`
	Recovery    string `json:"recovery"`
}

// haAction serves POST /api/ha/{pair,join,sync,failover,failback,retry,unpair,notify}.
// Every mutation needs ha.write, a fresh credential check and the cluster id for
// the two actions that change who serves.
func (s *Server) haAction(w http.ResponseWriter, r *http.Request) {
	action := strings.ToLower(strings.TrimSpace(r.PathValue("action")))
	switch action {
	case "pair", "join", "sync", "failover", "failback", "retry", "unpair", "notify":
	default:
		writeError(w, http.StatusNotFound, "unknown HA action")
		return
	}
	st := s.haStatusOf()
	if !st.Enabled {
		writeError(w, http.StatusConflict, "HA is not enabled on this host")
		return
	}
	if s.haOps == nil {
		writeError(w, http.StatusConflict, "HA is not running in this process")
		return
	}
	var in haActionRequest
	if err := decode(r, &in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	sess, ok := s.reauthHA(w, r, in.Password, in.TOTP, in.Recovery)
	if !ok {
		return
	}
	if action == "failover" || action == "unpair" {
		if st.ClusterID == "" || strings.TrimSpace(in.ClusterID) != st.ClusterID {
			writeError(w, http.StatusConflict, "type the cluster id to confirm this action")
			return
		}
	}
	if action == "join" {
		if strings.TrimSpace(in.Address) == "" || strings.TrimSpace(in.Fingerprint) == "" || strings.TrimSpace(in.Code) == "" {
			writeError(w, http.StatusBadRequest, "address, fingerprint and code are required")
			return
		}
	}

	var res ha.Result
	var err error
	switch action {
	case "pair":
		code, err := s.haOps.Pair(r.Context())
		if err != nil {
			s.haFail(w, "pair", nil, err)
			return
		}
		s.db(r).AddAudit(sess.Username, "ha.pair", "", clientIP(r))
		s.recordHAEvent("pair", nil, nil)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "code": code,
			"expires_at": time.Now().Add(ha.PairingCodeTTL).UTC().Format(time.RFC3339),
		})
		return
	case "join":
		err := s.haOps.Join(r.Context(), strings.TrimSpace(in.Address), strings.TrimSpace(in.Fingerprint), strings.TrimSpace(in.Code))
		if err != nil {
			s.haFail(w, "join", nil, err)
			return
		}
		s.db(r).AddAudit(sess.Username, "ha.join", in.Address, clientIP(r))
		s.recordHAEvent("join", nil, nil)
		// Joining makes this node the standby and writes the pair, both of which
		// the next boot reads, so the supervisor is asked to restart it.
		if s.restartFn != nil {
			go func() {
				time.Sleep(500 * time.Millisecond)
				s.restartFn()
			}()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": true})
		return
	case "sync":
		syncRes, err := s.haOps.Sync(r.Context())
		if err != nil {
			s.haFail(w, "sync", nil, err)
			return
		}
		s.db(r).AddAudit(sess.Username, "ha.sync", "", clientIP(r))
		s.recordHAEvent("sync", nil, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": syncRes})
		return
	case "failover":
		res, err = s.haOps.Failover(r.Context(), ha.MoveOptions{DryRun: in.DryRun, Force: in.Force})
	case "failback":
		res, err = s.haOps.Failback(r.Context(), ha.MoveOptions{DryRun: in.DryRun, Force: in.Force})
	case "retry":
		err = s.haOps.Retry(r.Context())
	case "unpair":
		err = s.haOps.Unpair(r.Context())
	case "notify":
		role := strings.ToUpper(strings.TrimSpace(in.Role))
		if role != "MASTER" && role != "BACKUP" && role != "FAULT" {
			writeError(w, http.StatusBadRequest, "role must be MASTER, BACKUP or FAULT")
			return
		}
		res, err = s.haOps.Notify(r.Context(), role)
	}
	if err != nil {
		s.haFail(w, action, &res, err)
		return
	}
	s.db(r).AddAudit(sess.Username, "ha."+action, "", clientIP(r))
	s.recordHAEvent(action, &res, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
}

// reauthHA re-checks the signed-in user's own credentials before a mutation,
// and answers 401 with the session when it succeeds.
func (s *Server) reauthHA(w http.ResponseWriter, r *http.Request, password, totp, recovery string) (*store.Session, bool) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	user, err := s.db(r).UserByID(sess.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	// verifyAdminSecret consumes a recovery code when one is used, so a lost
	// factor can still confirm a move once.
	if !s.verifyAdminSecret(r, user, password, totp, recovery) {
		writeError(w, http.StatusUnauthorized, "re-enter your password and, when enrolled, a current authenticator code")
		return nil, false
	}
	return sess, true
}

// haFail records the attempt and maps a refused move to 409 with the check that
// stopped it, so the page can show the reason and the fix.
func (s *Server) haFail(w http.ResponseWriter, action string, res *ha.Result, err error) {
	s.recordHAEvent(action, res, err)
	var blocked *ha.BlockedError
	if errors.As(err, &blocked) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "check": blocked.Check})
		return
	}
	writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
}

// haConfigRoute serves PUT /api/ha/config. Only the flap budget is live
// configurable; addresses, tokens and the witness come from the environment.
func (s *Server) haConfigRoute(w http.ResponseWriter, r *http.Request) {
	st := s.haStatusOf()
	if !st.Enabled {
		writeError(w, http.StatusConflict, "HA is not enabled on this host")
		return
	}
	if s.haOps == nil {
		writeError(w, http.StatusConflict, "HA is not running in this process")
		return
	}
	var in struct {
		MaxFailovers *int   `json:"max_failovers_per_hour"`
		Password     string `json:"password"`
		TOTP         string `json:"totp"`
		Recovery     string `json:"recovery"`
	}
	if err := decode(r, &in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	sess, ok := s.reauthHA(w, r, in.Password, in.TOTP, in.Recovery)
	if !ok {
		return
	}
	if in.MaxFailovers == nil || *in.MaxFailovers < 1 || *in.MaxFailovers > 100 {
		writeError(w, http.StatusBadRequest, "max_failovers_per_hour must be between 1 and 100")
		return
	}
	if err := s.haOps.SetMaxFailovers(*in.MaxFailovers); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.st.SetSetting("ha_max_failovers_per_hour", strconv.Itoa(*in.MaxFailovers)); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save the setting")
		return
	}
	s.db(r).AddAudit(sess.Username, "ha.config", "max_failovers_per_hour", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "max_failovers_per_hour": *in.MaxFailovers})
}
