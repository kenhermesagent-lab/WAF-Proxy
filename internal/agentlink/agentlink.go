// Package agentlink delivers console events to an external agent over a signed
// webhook. The agent does the thinking; the console only reports and audits.
package agentlink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Dispatcher posts events to every enabled link.
type Dispatcher struct {
	st  *store.Store
	box *crypto.Box
	log *slog.Logger
}

// New returns a dispatcher.
func New(st *store.Store, box *crypto.Box, log *slog.Logger) *Dispatcher {
	return &Dispatcher{st: st, box: box, log: log}
}

type envelope struct {
	Type   string             `json:"type"`
	SentAt time.Time          `json:"sent_at"`
	Event  model.AnomalyEvent `json:"event"`
}

// Publish sends one anomaly event to every enabled link. Delivery is
// best-effort and off the detection path: a slow agent must not stall a tick.
func (d *Dispatcher) Publish(e model.AnomalyEvent) {
	links, err := d.st.ListAgentLinks()
	if err != nil {
		d.log.Warn("agent links unavailable", "err", err)
		return
	}
	body, err := json.Marshal(envelope{Type: "anomaly", SentAt: time.Now().UTC(), Event: e})
	if err != nil {
		return
	}
	for _, l := range links {
		if !l.Enabled {
			continue
		}
		go func(l model.AgentLink) {
			if err := d.deliver(context.Background(), l, body); err != nil {
				d.log.Warn("agent delivery failed", "agent", l.Name, "err", err)
			}
		}(l)
	}
}

// SendTest posts a synthetic event so an admin can prove the link works.
func (d *Dispatcher) SendTest(ctx context.Context, l model.AgentLink) error {
	body, err := json.Marshal(envelope{
		Type:   "test",
		SentAt: time.Now().UTC(),
		Event: model.AnomalyEvent{
			ID: 0, Kind: "rate_spike", ProxyHost: "test.example.com",
			Detail: "test event from the console", State: "open",
		},
	})
	if err != nil {
		return err
	}
	return d.deliver(ctx, l, body)
}

func (d *Dispatcher) deliver(ctx context.Context, l model.AgentLink, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wafproxy-Event", "anomaly")
	req.Header.Set("X-Wafproxy-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	if secret, err := d.box.Open(l.Secret); err == nil && secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Wafproxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("agent answered %d", resp.StatusCode)
	}
	return nil
}
