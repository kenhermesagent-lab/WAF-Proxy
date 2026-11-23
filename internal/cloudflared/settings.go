// Package cloudflared stores the Cloudflare Tunnel settings and runs the
// connector process the console manages.
package cloudflared

import (
	"encoding/json"
	"sort"
	"strings"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

// Settings is the tunnel configuration the admin page edits. The token is
// sealed in the database and only ever held in memory here.
type Settings struct {
	Enabled      bool
	Token        string
	TunnelID     string
	StrictOrigin bool
	// Nonce marks responses the connector delivered; the edge check compares it
	// with the health header to prove the request reached this process.
	Nonce string
	// ClearToken deletes the stored token; a request that omits the token keeps
	// the one already saved, because the page never receives it to send back.
	ClearToken bool
}

const (
	keyEnabled      = "cloudflare_enabled"
	keyToken        = "cloudflare_tunnel_token"
	keyTunnelID     = "cloudflare_tunnel_id"
	keyStrictOrigin = "cloudflare_strict_origin"
	keyNonce        = "cloudflare_check_nonce"
	// KeyPublished is per site: the hostnames that site serves through the one
	// host-wide tunnel.
	KeyPublished = "cloudflare_published_hosts"
)

// Published reads the hostnames a site publishes through the tunnel.
func Published(kv map[string]string) []string {
	raw := strings.TrimSpace(kv[KeyPublished])
	if raw == "" {
		return nil
	}
	var hosts []string
	if err := json.Unmarshal([]byte(raw), &hosts); err != nil {
		return nil
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// EncodePublished stores a hostname list, sorted so the page and the audit log
// show the same order on every save.
func EncodePublished(hosts []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	blob, _ := json.Marshal(out)
	return string(blob)
}

// IsPublished reports whether hostname is served through the tunnel.
func IsPublished(kv map[string]string, hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	for _, h := range Published(kv) {
		if strings.EqualFold(h, hostname) {
			return true
		}
	}
	return false
}

// Load reads the settings, decrypting the token. A token that cannot be
// decrypted is reported as missing rather than crashing the console; the page
// then asks for it again.
func Load(kv map[string]string, box *wfcrypto.Box) Settings {
	s := Settings{
		Enabled:      kv[keyEnabled] == "1",
		TunnelID:     strings.TrimSpace(kv[keyTunnelID]),
		StrictOrigin: kv[keyStrictOrigin] != "0",
		Nonce:        strings.TrimSpace(kv[keyNonce]),
	}
	if sealed := strings.TrimSpace(kv[keyToken]); sealed != "" && box != nil {
		if token, err := box.Open(sealed); err == nil {
			s.Token = token
		}
	}
	return s
}

// Apply turns settings into the key/value rows to store. The sealed token is
// omitted when no new token is supplied, so saving the page cannot wipe a
// secret the browser never saw.
func Apply(box *wfcrypto.Box, in Settings) (map[string]string, error) {
	next := map[string]string{
		keyEnabled:      boolSetting(in.Enabled),
		keyTunnelID:     strings.TrimSpace(in.TunnelID),
		keyStrictOrigin: boolSetting(in.StrictOrigin),
	}
	switch {
	case in.ClearToken:
		next[keyToken] = ""
	case in.Token != "":
		sealed, err := box.Seal(in.Token)
		if err != nil {
			return nil, err
		}
		next[keyToken] = sealed
	}
	if in.Nonce != "" {
		next[keyNonce] = in.Nonce
	}
	return next, nil
}

func boolSetting(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
