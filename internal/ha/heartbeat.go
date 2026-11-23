package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

// PeerPing is the heartbeat's answer. It carries the facts a promotion gate
// needs to tell a live peer from a wedged one, over the same pinned link as
// replication.
type PeerPing struct {
	OK       bool   `json:"ok"`
	Node     string `json:"node"`
	Role     Role   `json:"role"`
	State    State  `json:"state"`
	Epoch    int64  `json:"epoch"`
	Schema   string `json:"schema"`
	Protocol int    `json:"protocol"`
	Version  string `json:"version"`
	Time     string `json:"time"`
}

// pingNode answers the peer's heartbeat.
func (s *JoinServer) pingNode(w http.ResponseWriter, r *http.Request) {
	node, err := Load(s.dataDir)
	if err != nil {
		writeJoinError(w, http.StatusInternalServerError, "cannot read the node role")
		return
	}
	writeJoinJSON(w, http.StatusOK, PeerPing{
		OK: true, Node: s.id.Node, Role: node.Role, State: node.EffectiveState(),
		Epoch: node.Epoch, Schema: store.SchemaVersion(), Protocol: ProtocolVersion, Version: version.Version,
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// PingPeer asks the paired node whether it is alive. It is deliberately the
// application's own signal, not VRRP's: a node that lost the VIP can still be
// alive, and a node holding it can still be unable to answer.
func PingPeer(ctx context.Context, dataDir string) (PeerPing, error) {
	conn, err := dialPeer(dataDir, 5*time.Second)
	if err != nil {
		return PeerPing{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+conn.pair.PeerAddr+"/ha/ping", nil)
	if err != nil {
		return PeerPing{}, err
	}
	resp, err := conn.client.Do(req)
	if err != nil {
		return PeerPing{}, fmt.Errorf("ha: ping the peer: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return PeerPing{}, fmt.Errorf("ha: the peer answered the heartbeat with status %d", resp.StatusCode)
	}
	var ping PeerPing
	if err := json.Unmarshal(raw, &ping); err != nil {
		return PeerPing{}, err
	}
	if !ping.OK {
		return PeerPing{}, fmt.Errorf("ha: the peer reported itself unhealthy")
	}
	return ping, nil
}

// Health is the liveness the heartbeat has observed.
type Health struct {
	Reachable bool   `json:"reachable"`
	Failures  int    `json:"failures"`
	LastSeen  string `json:"last_seen,omitempty"`
	ChangedAt string `json:"changed_at,omitempty"`
}

// Monitor turns probes into one liveness decision. Two lost beats are a blip a
// keepalive or a GC pause can produce; acting on them is how a pair flaps.
type Monitor struct {
	Probe     func(context.Context) error
	Period    time.Duration
	Threshold int
	Now       func() time.Time
	OnChange  func(Health)

	mu     sync.Mutex
	health Health
}

// NewMonitor builds a monitor with the plan's 1 s period and three-beat
// threshold.
func NewMonitor(probe func(context.Context) error) *Monitor {
	return &Monitor{Probe: probe, Period: time.Second, Threshold: 3, Now: time.Now, health: Health{Reachable: true}}
}

// Health reports the current judgement.
func (m *Monitor) Health() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health
}

// Beat runs one probe and updates the judgement. It reports whether the peer
// is currently considered reachable, so a caller can gate a move on it.
func (m *Monitor) Beat(ctx context.Context) bool {
	err := m.Probe(ctx)
	now := m.Now()
	m.mu.Lock()
	before := m.health.Reachable
	if err == nil {
		m.health.Failures = 0
		m.health.Reachable = true
		m.health.LastSeen = now.UTC().Format(time.RFC3339)
	} else {
		m.health.Failures++
		m.health.Reachable = m.health.Failures < m.Threshold
	}
	if m.health.Reachable != before {
		m.health.ChangedAt = now.UTC().Format(time.RFC3339)
	}
	after := m.health
	changed := after.Reachable != before
	m.mu.Unlock()
	if changed && m.OnChange != nil {
		m.OnChange(after)
	}
	return after.Reachable
}

// Run probes until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.Period)
	defer ticker.Stop()
	for {
		m.Beat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
