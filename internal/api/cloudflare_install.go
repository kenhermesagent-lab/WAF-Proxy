package api

import (
	"context"
	"net/http"
	"time"

	cf "github.com/kenhermesagent-lab/waf-proxy-docker/internal/cloudflared"
	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

func (s *Server) getCloudflareInstall(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cloudflaredInstallStatus())
}

// startCloudflareInstall runs the fixed installer in the background: adding
// Cloudflare's repository and installing the package takes a minute, so the page
// polls instead of holding one request open.
func (s *Server) startCloudflareInstall(w http.ResponseWriter, r *http.Request) {
	st := s.cloudflaredInstallStatus()
	if st.Installed {
		writeError(w, http.StatusConflict, "cloudflared is already installed")
		return
	}
	if !st.Supported {
		writeError(w, http.StatusConflict, st.Reason)
		return
	}
	s.cfMu.Lock()
	if s.cfRunning {
		s.cfMu.Unlock()
		writeError(w, http.StatusConflict, "a connector install is already running")
		return
	}
	s.cfRunning, s.cfErr, s.cfOutput = true, "", ""
	s.cfMu.Unlock()

	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "cloudflare.install", "install the Cloudflare connector", clientIP(r))
	go s.runCloudflareInstall()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "installing"})
}

func (s *Server) runCloudflareInstall() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := s.updates.RunHelper(ctx, updatepkg.HelperRequest{Action: updatepkg.HelperActionCloudflaredInstall})
	message, output := "", ""
	switch {
	case err != nil:
		message = err.Error()
	case !resp.OK:
		message = helperMessage(resp.Error)
		output = tail(resp.Output, 2000)
	default:
		output = tail(resp.Output, 2000)
	}
	if message == "" {
		message = s.startConnectorAfterInstall()
	}
	s.cfMu.Lock()
	s.cfRunning, s.cfErr, s.cfOutput = false, message, output
	s.cfMu.Unlock()
}

// startConnectorAfterInstall picks up a token the operator saved before the
// connector existed, so installing is the only step left.
func (s *Server) startConnectorAfterInstall() string {
	if s.cloudflared == nil {
		return ""
	}
	kv, err := s.st.Settings()
	if err != nil {
		return ""
	}
	cfg := cf.Load(kv, s.box)
	s.cloudflared.RefreshVersion(true)
	if !cfg.Enabled || cfg.Token == "" {
		return ""
	}
	if err := s.cloudflared.Start(cfg.Token); err != nil {
		return err.Error()
	}
	return ""
}
