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
}

// New returns nil when the bouncer is not configured.
func New(base, key string, bans *ban.Engine, log *slog.Logger) *Manager {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" || key == "" || bans == nil {
		return nil
	}
	return &Manager{
		base: base, key: key, bans: bans, log: log,
		client: &http.Client{Timeout: 20 * time.Second},
		now:    time.Now,
	}
}

// Start begins polling. It is a no-op on a nil manager.
func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	go func() {
		startup := true
		for {
			if err := m.poll(ctx, startup); err != nil {
				m.log.Warn("crowdsec poll failed", "err", err)
			} else {
				startup = false
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
		return map[string]any{"configured": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var lastPoll any
	if !m.lastPoll.IsZero() {
		lastPoll = m.lastPoll
	}
	return map[string]any{
		"configured": true, "lapi": redactURL(m.base), "mode": "stream",
		"last_poll": lastPoll, "last_error": m.lastErr, "applied": m.applied,
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

func (m *Manager) poll(ctx context.Context, startup bool) error {
	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t&scopes=Ip,Range", m.base, startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", m.key)
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
