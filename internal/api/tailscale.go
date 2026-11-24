package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
)

// TailscaleState records what was actually started at boot. It is set by main
// before the API starts; the GET handler combines it with the saved settings to
// report whether a restart is needed.
type TailscaleState struct {
	AdminAddr  string
	ProxyAddr  string
	DNSAddr    string
	AdminOn    bool
	ProxyOn    bool
	DNSOn      bool
	AdminUp    bool
	DNSUp      bool
	DNSError   string
	AdminError string
	ProxyError string
}

type tailscaleView struct {
	Available       bool   `json:"available"`
	IP              string `json:"ip"`
	Error           string `json:"error"`
	AdminEnabled    bool   `json:"admin_enabled"`
	AdminActive     bool   `json:"admin_active"`
	AdminURL        string `json:"admin_url"`
	AdminError      string `json:"admin_error,omitempty"`
	ProxyEnabled    bool   `json:"proxy_enabled"`
	ProxyActive     bool   `json:"proxy_active"`
	ProxyAddr       string `json:"proxy_addr,omitempty"`
	ProxyError      string `json:"proxy_error,omitempty"`
	DNSEnabled      bool   `json:"dns_enabled"`
	DNSActive       bool   `json:"dns_active"`
	DNSAddr         string `json:"dns_addr,omitempty"`
	DNSError        string `json:"dns_error,omitempty"`
	RestartRequired bool   `json:"restart_required"`
	BaseDomain      string `json:"base_domain"`
	GUIPort         int    `json:"gui_port"`
	WANPort         int    `json:"wan_port"`
}

// SetTailscaleState is called once during startup. Fields are not written
// afterwards, so the API can read them without a lock.
func (s *Server) SetTailscaleState(v TailscaleState) { s.tailscale = v }

func (s *Server) getTailscale(w http.ResponseWriter, r *http.Request) {
	kv, err := s.db(r).Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	ip, ipErr := config.TailscaleIPv4()
	available := ipErr == nil
	errText := ""
	if ipErr != nil {
		errText = ipErr.Error()
	}
	guiPort := settingPort(kv["gui_port"], 8443)
	wanPort := settingPort(kv["wan_port"], 443)

	adminSaved := kv["tailscale_admin_enabled"] == "1"
	proxySaved := kv["tailscale_proxy_enabled"] == "1"
	dnsSaved := kv["tailscale_dns_enabled"] != "0"

	adminActive := adminSaved && s.tailscale.AdminOn && s.tailscale.AdminUp && s.tailscale.AdminAddr != ""
	proxyActive := proxySaved && s.tailscale.ProxyOn && s.tailscale.ProxyAddr != ""
	proxyErr := s.tailscale.ProxyError
	if proxyActive {
		if err := s.proxy.ListenerError(s.tailscale.ProxyAddr); err != "" {
			proxyErr = err
		}
		proxyActive = proxyErr == ""
	}
	dnsActive := dnsSaved && s.tailscale.DNSOn && s.tailscale.DNSUp && s.tailscale.DNSAddr != ""
	adminURL := ""
	if adminActive {
		adminURL = "http://" + s.tailscale.AdminAddr
	}

	restart := adminSaved != s.tailscale.AdminOn ||
		proxySaved != s.tailscale.ProxyOn ||
		dnsSaved != s.tailscale.DNSOn
	if ip != s.cfg.TailscaleIP {
		restart = true
	}

	writeJSON(w, http.StatusOK, tailscaleView{
		Available:       available,
		IP:              ip,
		Error:           errText,
		AdminEnabled:    adminSaved,
		AdminActive:     adminActive,
		AdminURL:        adminURL,
		AdminError:      s.tailscale.AdminError,
		ProxyEnabled:    proxySaved,
		ProxyActive:     proxyActive,
		ProxyAddr:       s.tailscale.ProxyAddr,
		ProxyError:      proxyErr,
		DNSEnabled:      dnsSaved,
		DNSActive:       dnsActive,
		DNSAddr:         s.tailscale.DNSAddr,
		DNSError:        s.tailscale.DNSError,
		RestartRequired: restart,
		BaseDomain:      kv["base_domain"],
		GUIPort:         guiPort,
		WANPort:         wanPort,
	})
}

type tailscaleRequest struct {
	AdminEnabled bool `json:"admin_enabled"`
	ProxyEnabled bool `json:"proxy_enabled"`
	DNSEnabled   bool `json:"dns_enabled"`
}

func (s *Server) putTailscale(w http.ResponseWriter, r *http.Request) {
	var req tailscaleRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	kv, err := s.db(r).Settings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if err := validateTailscale(req, kv, config.TailscaleIPv4OrEmpty() != ""); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next := map[string]string{
		"tailscale_admin_enabled": boolSetting(req.AdminEnabled),
		"tailscale_proxy_enabled": boolSetting(req.ProxyEnabled),
		"tailscale_dns_enabled":   boolSetting(req.DNSEnabled),
	}
	if err := s.db(r).SetSettings(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot save settings")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "tailscale.update", "tailscale listeners changed", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "restart_required": true})
}

func validateTailscale(req tailscaleRequest, kv map[string]string, available bool) error {
	if (req.AdminEnabled || req.ProxyEnabled) && !available {
		return fmt.Errorf("tailscale is not connected: tailscale0 has no IPv4 address")
	}
	if req.AdminEnabled && req.ProxyEnabled &&
		settingPort(kv["gui_port"], 8443) == settingPort(kv["wan_port"], 443) {
		return fmt.Errorf("the admin and proxy tailnet listeners cannot share a port")
	}
	return nil
}

func settingPort(raw string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
}
