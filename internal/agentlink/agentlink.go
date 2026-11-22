// Package agentlink delivers console events to an external agent over a signed
// webhook. The agent does the thinking; the console only reports and audits.
//
// Delivery is durable: a payload is written to the queue before any network
// call, retried with exponential backoff, and its outcome is recorded so an
// operator can see whether the agent is actually receiving events.
package agentlink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// MaxAttempts is how many times a payload is tried before it is marked failed.
const MaxAttempts = 8

// BaseBackoff is the delay after the first failure; each later attempt doubles
// it, capped at one hour.
const BaseBackoff = 30 * time.Second

// client never follows a redirect. The endpoint is checked when it is saved,
// and a 302 from an allowed host to a metadata service would walk straight
// around that check.
var client = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Backoff returns the wait after a given attempt number (1-based).
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := BaseBackoff << (attempt - 1)
	if d > time.Hour || d <= 0 {
		return time.Hour
	}
	return d
}

// Dispatcher queues and delivers events to every enabled link.
type Dispatcher struct {
	st    *store.Store
	box   *crypto.Box
	log   *slog.Logger
	now   func() time.Time
	allow func(kind string) bool
}

// New returns a dispatcher.
func New(st *store.Store, box *crypto.Box, log *slog.Logger) *Dispatcher {
	return &Dispatcher{st: st, box: box, log: log, now: time.Now}
}

type envelope struct {
	Type   string             `json:"type"`
	SentAt time.Time          `json:"sent_at"`
	Event  model.AnomalyEvent `json:"event"`
}

// SetRouting attaches the event-routing lookup. When a class is muted in the
// notification settings its payloads are still queued (so an operator can see
// them) but suppressed instead of posted.
func (d *Dispatcher) SetRouting(allow func(kind string) bool) { d.allow = allow }

// Publish queues one anomaly event for every enabled link. It never touches the
// network, so a slow or dead agent cannot stall detection.
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
	// A link that exhausted its attempts is reported once by its last failed
	// row; queueing another payload per event would only fill the table.
	last, _ := d.st.LastDeliveries()
	for _, l := range links {
		if !l.Enabled {
			continue
		}
		if prev, ok := last[l.ID]; ok && prev.State == "failed" {
			d.log.Debug("agent link is dead; event not queued", "agent", l.Name)
			continue
		}
		if _, dropped, err := d.st.EnqueueDelivery(l.ID, e.ID, e.Kind, string(body)); err != nil {
			d.log.Warn("agent event could not be queued", "agent", l.Name, "err", err)
		} else if dropped > 0 {
			d.log.Warn("agent queue full; oldest events dropped", "agent", l.Name, "dropped", dropped)
		}
	}
}

// SendTest queues a synthetic event and tries it once, so the admin sees the
// agent's real answer rather than a queued promise.
func (d *Dispatcher) SendTest(ctx context.Context, l model.AgentLink) error {
	body, err := json.Marshal(envelope{
		Type:   "test",
		SentAt: time.Now().UTC(),
		Event: model.AnomalyEvent{
			Kind: "rate_spike", ProxyHost: "test.example.com",
			Detail: "test event from the console", State: "open",
		},
	})
	if err != nil {
		return err
	}
	id, _, err := d.st.EnqueueDelivery(l.ID, 0, "test", string(body))
	if err != nil {
		return err
	}
	del, err := d.st.DeliveryByID(id)
	if err != nil {
		return err
	}
	return d.deliverOne(ctx, *del)
}

// RetryLast puts a link's newest delivery back in the queue.
func (d *Dispatcher) RetryLast(linkID int64) (bool, error) {
	list, err := d.st.DeliveriesForLink(linkID, 1)
	if err != nil || len(list) == 0 {
		return false, err
	}
	return d.st.RetryDelivery(list[0].ID)
}

// Start runs the retry worker until the context is cancelled.
func (d *Dispatcher) Start(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			d.drain(ctx)
		case <-prune.C:
			if err := d.st.PruneDeliveries(); err != nil {
				d.log.Warn("delivery prune failed", "err", err)
			}
		}
	}
}

// drain attempts every due payload once.
func (d *Dispatcher) drain(ctx context.Context) {
	due, err := d.st.DueDeliveries(20)
	if err != nil {
		d.log.Warn("delivery queue unreadable", "err", err)
		return
	}
	for _, del := range due {
		if err := d.deliverOne(ctx, del); err != nil {
			// The failure is already recorded on the delivery row; the log only
			// needs the first occurrence per attempt so a dead agent does not
			// flood it.
			d.log.Debug("agent delivery retrying", "delivery", del.ID, "err", err)
		}
	}
}

// deliverOne posts a stored payload and records the outcome.
func (d *Dispatcher) deliverOne(ctx context.Context, del model.Delivery) error {
	link, err := d.st.GetAgentLink(del.LinkID)
	if err != nil {
		// The link was deleted while the payload was queued.
		_ = d.st.MarkDeliveryAttempt(del.ID, 0, "agent link no longer exists", nil)
		return err
	}
	// Routing is checked at delivery, not only when the event was queued: a
	// class muted while a payload is still waiting must stop it, and a backlog
	// queued by an older build must not outlive the mute. A test payload is a
	// deliberate admin action and always goes.
	if del.Kind != "test" && d.allow != nil && !d.allow(del.Kind) {
		return d.st.MarkDeliverySuppressed(del.ID, "event class is muted")
	}
	status, err := d.post(ctx, *link, []byte(del.Body))
	if err == nil {
		return d.st.MarkDelivered(del.ID, status)
	}
	attempt := del.Attempts + 1
	var next *time.Time
	if attempt >= MaxAttempts {
		d.log.Warn("agent delivery abandoned", "agent", link.Name, "attempts", attempt, "err", err)
	} else {
		at := d.now().Add(Backoff(attempt))
		next = &at
	}
	if mErr := d.st.MarkDeliveryAttempt(del.ID, status, err.Error(), next); mErr != nil {
		d.log.Warn("delivery result not recorded", "err", mErr)
	}
	return err
}

// post sends one signed payload and returns the HTTP status.
func (d *Dispatcher) post(ctx context.Context, l model.AgentLink, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wafproxy-Event", "anomaly")
	req.Header.Set("X-Wafproxy-Timestamp", strconv.FormatInt(d.now().Unix(), 10))
	if secret, err := d.box.Open(l.Secret); err == nil && secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Wafproxy-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("agent answered %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
