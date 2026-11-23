// Package config loads runtime configuration from the environment.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/tailnet"
)

// Config is the process-wide configuration. Operational settings such as the
// WAN bind address are stored in the database and edited through the setup
// wizard; this struct only holds what is needed to boot.
type Config struct {
	DataDir string
	// ListenHTTP serves ACME HTTP-01 and redirects to HTTPS; empty disables it.
	ListenHTTP string
	ListenWAN  string
	ListenGUI  string
	// ListenGUITLS serves the console over HTTPS using the certificate that
	// matches GUIHost from the certificate manager.
	ListenGUITLS   bool
	GUIHost        string
	WANIface       string
	LANIface       string
	GUIPrivateOnly bool
	// TrustedProxies lists the CIDRs whose X-Forwarded-For may name the
	// client. Empty means nothing is trusted and the socket peer always wins.
	TrustedProxies []string
	// MaxInflight bounds the requests that may be buffered at once, which is
	// what keeps a burst of large uploads from exhausting a small host.
	MaxInflight int
	// TailscaleIP is the tailscale0 IPv4 address captured at boot. Settings
	// decide whether it is used; a missing interface leaves it empty and the
	// service continues with only the LAN/WAN listeners.
	TailscaleIP string
	MasterKey   []byte
	CrowdSecURL string
	CrowdSecKey string
	// MCPToken is an optional static bearer token for the agent gateway. It is
	// empty when tokens are managed in the console instead.
	MCPToken string
	MCPActor string
	// MetricsToken is the bearer token a Prometheus scraper sends to
	// /metrics. Empty leaves the endpoint closed.
	MetricsToken string
	// ACMEDirectory overrides the Let's Encrypt directory, for a private ACME
	// server (step-ca, Pebble). ACMECAFile is the PEM bundle to trust for it.
	ACMEDirectory string
	ACMECAFile    string
	// BundleProvidersJSON lists the signed signature-bundle channels as a JSON
	// array of {name, url, public_key}. BundleURL and BundlePublicKey are the
	// original single channel and still work as the provider named "default".
	// A provider without both a URL and a key is left off, and the service then
	// serves whatever packs are already installed.
	BundleProvidersJSON string
	BundleURL           string
	BundlePublicKey     string
	// BundleIntervalSeconds is the manifest refresh period. The manager never
	// checks more often than every five minutes.
	BundleIntervalSeconds int
	// HAEnabled is the boot-time master switch for high availability. When it
	// is off, no HA route or loop exists and the node serves on its own.
	HAEnabled bool
	// HAMgmtListen is this node's own console address in HA mode. The service
	// address belongs to whichever node is active, so the standby needs a
	// management listener that never moves.
	HAMgmtListen string
	// HALinkListen serves pairing and, later, replication on the private link
	// between the pair. Empty leaves the node able to run but not to pair.
	HALinkListen string
}

// Load reads configuration from the environment, applying safe defaults.
func Load() (*Config, error) {
	c := &Config{
		DataDir:        envOr("WAFPROXY_DATA_DIR", "./data"),
		ListenWAN:      envOr("WAFPROXY_LISTEN_WAN", ":8443"),
		ListenGUI:      envOr("WAFPROXY_LISTEN_GUI", "127.0.0.1:8080"),
		ListenGUITLS:   envBoolOr("WAFPROXY_LISTEN_GUI_TLS", false),
		GUIHost:        strings.ToLower(strings.TrimSpace(os.Getenv("WAFPROXY_GUI_HOST"))),
		ListenHTTP:     envOr("WAFPROXY_LISTEN_HTTP", ""),
		WANIface:       strings.TrimSpace(os.Getenv("WAFPROXY_WAN_IFACE")),
		LANIface:       strings.TrimSpace(os.Getenv("WAFPROXY_LAN_IFACE")),
		GUIPrivateOnly: envBoolOr("WAFPROXY_GUI_PRIVATE_ONLY", true),
		TrustedProxies: splitList(os.Getenv("WAFPROXY_TRUSTED_PROXIES")),
		MaxInflight:    envInt("WAFPROXY_MAX_INFLIGHT", 128),
		TailscaleIP:    tailscaleIPv4(),
		CrowdSecURL:    strings.TrimSpace(os.Getenv("WAFPROXY_CROWDSEC_URL")),
		CrowdSecKey:    strings.TrimSpace(os.Getenv("WAFPROXY_CROWDSEC_KEY")),
		MCPToken:       strings.TrimSpace(os.Getenv("WAFPROXY_MCP_TOKEN")),
		MCPActor:       envOr("WAFPROXY_MCP_ACTOR", "hermes-agent"),
		MetricsToken:   strings.TrimSpace(os.Getenv("WAFPROXY_METRICS_TOKEN")),
		ACMEDirectory:  strings.TrimSpace(os.Getenv("WAFPROXY_ACME_DIRECTORY")),
		ACMECAFile:     strings.TrimSpace(os.Getenv("WAFPROXY_ACME_CA_FILE")),

		BundleProvidersJSON:   strings.TrimSpace(os.Getenv("WAFPROXY_BUNDLE_PROVIDERS")),
		BundleURL:             strings.TrimSpace(os.Getenv("WAFPROXY_BUNDLE_URL")),
		BundlePublicKey:       strings.TrimSpace(os.Getenv("WAFPROXY_BUNDLE_PUBKEY")),
		BundleIntervalSeconds: envInt("WAFPROXY_BUNDLE_INTERVAL", 3600),
		HAEnabled:             envBoolOr("WAFPROXY_HA_ENABLE", false),
		HAMgmtListen:          strings.TrimSpace(os.Getenv("WAFPROXY_HA_MGMT_LISTEN")),
		HALinkListen:          strings.TrimSpace(os.Getenv("WAFPROXY_HA_LINK_LISTEN")),
	}
	if c.HAEnabled && c.HAMgmtListen == "" {
		return nil, errors.New("WAFPROXY_HA_MGMT_LISTEN is required when WAFPROXY_HA_ENABLE=1")
	}
	if c.ListenGUITLS && c.GUIHost == "" {
		return nil, errors.New("WAFPROXY_GUI_HOST is required when WAFPROXY_LISTEN_GUI_TLS is set")
	}
	if c.MCPToken != "" && len(c.MCPToken) < 32 {
		return nil, errors.New("WAFPROXY_MCP_TOKEN must be at least 32 characters")
	}
	if c.MetricsToken != "" && len(c.MetricsToken) < 32 {
		return nil, errors.New("WAFPROXY_METRICS_TOKEN must be at least 32 characters")
	}
	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	key, err := loadMasterKey(c.DataDir)
	if err != nil {
		return nil, err
	}
	c.MasterKey = key
	return c, nil
}

// IsLocalAddress reports whether a listen address can be bound here. An empty
// host or the unspecified address (":8080", "0.0.0.0", "[::]") binds every
// interface and is always valid; any other IP must be configured on one of the
// host's interfaces. A single-NIC host has one address and uses it for both the
// WAN and LAN settings, so this check is what keeps a stale address from leaving
// the admin GUI unreachable after a DHCP change.
func IsLocalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// Cannot inspect the host: let the bind report its own error instead of
		// overriding a possibly valid address.
		return true
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// TailscaleIPv4 returns the first 100.64.0.0/10 IPv4 address on tailscale0.
// It is intentionally a pure interface lookup: the unprivileged service does
// not need the Tailscale control socket to serve tailnet listeners.
func TailscaleIPv4() (string, error) {
	iface, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return "", fmt.Errorf("tailscale0 interface not found")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("read tailscale0 addresses: %w", err)
	}
	ip := tailnet.IPv4FromAddrs(addrs)
	if ip == "" {
		return "", fmt.Errorf("tailscale0 has no Tailscale IPv4 address")
	}
	return ip, nil
}

func tailscaleIPv4() string {
	ip, _ := TailscaleIPv4()
	return ip
}

// TailscaleIPv4OrEmpty is the non-error form used by request validation.
func TailscaleIPv4OrEmpty() string { return tailscaleIPv4() }

func loadMasterKey(dir string) ([]byte, error) {
	if raw := os.Getenv("WAFPROXY_MASTER_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, errors.New("WAFPROXY_MASTER_KEY must be base64 encoded")
		}
		if len(key) != 32 {
			return nil, errors.New("WAFPROXY_MASTER_KEY must decode to 32 bytes")
		}
		return key, nil
	}

	// A paired node stores the cluster key under ha/. It takes precedence over
	// the locally generated key, so a standby decrypts the same secrets as the
	// active. Refusing a mismatch happens at pairing time, not here.
	haPath := filepath.Join(dir, "ha", "master.key")
	path := filepath.Join(dir, "master.key")
	if b, err := os.ReadFile(haPath); err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if decErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("ha/master.key at %s is corrupt", haPath)
		}
		return key, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if decErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("master.key at %s is corrupt", path)
		}
		return key, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("persist master key: %w", err)
	}
	return key, nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBoolOr(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func splitList(raw string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, v)
	}
	return out
}
