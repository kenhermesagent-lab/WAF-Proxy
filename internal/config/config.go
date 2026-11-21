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
	"strings"
)

// Config is the process-wide configuration. Operational settings such as the
// WAN bind address are stored in the database and edited through the setup
// wizard; this struct only holds what is needed to boot.
type Config struct {
	DataDir     string
	ListenWAN   string
	ListenGUI   string
	MasterKey   []byte
	CrowdSecURL string
	CrowdSecKey string
}

// Load reads configuration from the environment, applying safe defaults.
func Load() (*Config, error) {
	c := &Config{
		DataDir:     envOr("WAFPROXY_DATA_DIR", "./data"),
		ListenWAN:   envOr("WAFPROXY_LISTEN_WAN", ":8443"),
		ListenGUI:   envOr("WAFPROXY_LISTEN_GUI", ":8080"),
		CrowdSecURL: strings.TrimSpace(os.Getenv("WAFPROXY_CROWDSEC_URL")),
		CrowdSecKey: strings.TrimSpace(os.Getenv("WAFPROXY_CROWDSEC_KEY")),
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

	path := filepath.Join(dir, "master.key")
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
