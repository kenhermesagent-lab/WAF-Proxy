// Package config loads runtime configuration from the environment.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the process-wide configuration. Operational settings such as the
// WAN bind address are stored in the database and edited through the setup
// wizard; this struct only holds what is needed to boot.
type Config struct {
	DataDir             string
	ListenWAN           string
	ListenGUI           string
	MasterKey           []byte
	Dev                 bool
	LogLevel            string
	TrustedProxyHeaders bool
	CrowdSecURL         string
	CrowdSecKey         string
}

// Load reads configuration from the environment, applying safe defaults.
func Load() (*Config, error) {
	c := &Config{
		DataDir:     envOr("WAFPROXY_DATA_DIR", "./data"),
		ListenWAN:   envOr("WAFPROXY_LISTEN_WAN", ":8443"),
		ListenGUI:   envOr("WAFPROXY_LISTEN_GUI", ":8080"),
		LogLevel:    strings.ToLower(envOr("WAFPROXY_LOG_LEVEL", "info")),
		Dev:         os.Getenv("WAFPROXY_DEV") == "1",
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
