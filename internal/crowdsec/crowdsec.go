// Package crowdsec streams ban decisions from a CrowdSec LAPI and applies them
// through the local ban engine.
package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
)

// Decision is one entry of the CrowdSec decisions stream.
type Decision struct {
	ID        int64  `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

type streamResponse struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

// Manager polls the LAPI stream endpoint.
type Manager struct {
	base   string
	key    string
	bans   *ban.Engine
	log    *slog.Logger
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	lastPoll time.Time
	lastErr  string
	applied  int
	startup  bool
}

// New returns a manager even when the bouncer is disabled, so the console can
// enable it later without restarting the process. A nil ban engine still yields
// a nil manager because there is nothing to apply decisions to.
func New(base, key string, bans *ban.Engine, log *slog.Logger) *Manager {
	if bans == nil {
		return nil
	}
	return &Manager{
		base: strings.TrimRight(strings.TrimSpace(base), "/"), key: strings.TrimSpace(key),
		bans: bans, log: log,
		client:  &http.Client{Timeout: 20 * time.Second},
		now:     time.Now,
		startup: true,
	}
}

// SetConfig changes the LAPI endpoint and bouncer key at runtime. An empty
// endpoint or key disables polling but keeps the manager available.
func (m *Manager) SetConfig(base, key string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.base = strings.TrimRight(strings.TrimSpace(base), "/")
	m.key = strings.TrimSpace(key)
	m.lastPoll = time.Time{}
	m.lastErr = ""
	m.startup = true
	m.mu.Unlock()
}

// Start begins polling. It is a no-op on a nil manager.
func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	go func() {
		for {
			m.mu.Lock()
			base, key, startup := m.base, m.key, m.startup
			m.mu.Unlock()
			if base != "" && key != "" {
				if err := m.poll(ctx, base, key, startup); err != nil {
					m.log.Warn("crowdsec poll failed", "err", err)
				} else {
					m.mu.Lock()
					if m.base == base && m.key == key {
						m.startup = false
					}
					m.mu.Unlock()
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
		}
	}()
}

// Status reports the last successful poll for the API.
func (m *Manager) Status() map[string]any {
	if m == nil {
		return map[string]any{"configured": false, "lapi_configured": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var lastPoll any
	if !m.lastPoll.IsZero() {
		lastPoll = m.lastPoll
	}
	lapiConfigured := m.base != ""
	return map[string]any{
		"configured": lapiConfigured && m.key != "", "lapi_configured": lapiConfigured,
		"lapi": redactURL(m.base), "mode": "stream",
		"last_poll": lastPoll, "last_error": m.lastErr, "applied": m.applied,
	}
}

// Probe verifies that the engine is reachable and that the bouncer key is
// accepted. It reads one decision rather than the stream so a test does not
// change the polling cursor.
func (m *Manager) Probe(ctx context.Context, base, key string) error {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	key = strings.TrimSpace(key)
	if base == "" || key == "" {
		return fmt.Errorf("LAPI URL and bouncer key are required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/decisions?limit=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")
	var client *http.Client
	if m != nil {
		client = m.client
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to CrowdSec LAPI: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("the LAPI rejected the bouncer key")
	default:
		return fmt.Errorf("LAPI returned HTTP %d", resp.StatusCode)
	}
}

// redactURL keeps the LAPI endpoint visible for troubleshooting without
// leaking credentials embedded in the URL.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

func (m *Manager) poll(ctx context.Context, base, key string, startup bool) error {
	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t&scopes=Ip,Range", base, startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		m.recordErr(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("lapi returned %d", resp.StatusCode)
		m.recordErr(err)
		return err
	}
	var stream streamResponse
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		m.recordErr(err)
		return err
	}
	for _, d := range stream.New {
		m.apply(d)
	}
	for _, d := range stream.Deleted {
		m.remove(d)
	}
	m.mu.Lock()
	m.lastPoll = m.now()
	m.lastErr = ""
	m.mu.Unlock()
	return nil
}

func (m *Manager) recordErr(err error) {
	m.mu.Lock()
	m.lastErr = err.Error()
	m.mu.Unlock()
}

func (m *Manager) apply(d Decision) {
	if d.Simulated || (d.Type != "" && d.Type != "ban") {
		return
	}
	cidr, ok := decisionCIDR(d)
	if !ok {
		m.log.Debug("crowdsec decision skipped", "scope", d.Scope, "value", d.Value)
		return
	}
	ttl := 4 * time.Hour
	if d.Duration != "" {
		if parsed, err := time.ParseDuration(d.Duration); err == nil && parsed > 0 {
			ttl = parsed
		}
	}
	reason := "crowdsec"
	if d.Scenario != "" {
		reason = "crowdsec: " + d.Scenario
	}
	if _, err := m.bans.Add(cidr, reason, "crowdsec", "crowdsec", ttl); err != nil {
		m.log.Debug("crowdsec ban failed", "cidr", cidr, "err", err)
		return
	}
	m.mu.Lock()
	m.applied++
	m.mu.Unlock()
	m.log.Info("crowdsec ban applied", "cidr", cidr, "scenario", d.Scenario, "ttl", ttl.String())
}

// remove lifts a local ban when CrowdSec withdraws the decision. Only bans
// whose source is crowdsec are touched.
func (m *Manager) remove(d Decision) {
	cidr, ok := decisionCIDR(d)
	if !ok {
		return
	}
	m.bans.RemoveIfSource(cidr, "crowdsec")
}

func decisionCIDR(d Decision) (string, bool) {
	value := strings.TrimSpace(d.Value)
	switch d.Scope {
	case "Range":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", false
		}
		return p.Masked().String(), true
	case "Ip", "":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return "", false
		}
		if addr.Is4() {
			return addr.String() + "/32", true
		}
		return addr.String() + "/128", true
	}
	return "", false
}
