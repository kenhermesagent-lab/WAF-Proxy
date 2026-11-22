package agentlink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func newDispatcher(t *testing.T) (*Dispatcher, *store.Store, *crypto.Box) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := crypto.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil))), st, box
}

type received struct {
	body []byte
	sig  string
	ts   string
}

func receiver(t *testing.T, hits *int32, status func(n int32) int) (*httptest.Server, chan received) {
	t.Helper()
	got := make(chan received, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := atomic.AddInt32(hits, 1)
		if status(n) < 300 {
			got <- received{body: body, sig: r.Header.Get("X-Wafproxy-Signature"), ts: r.Header.Get("X-Wafproxy-Timestamp")}
		}
		w.WriteHeader(status(n))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestPublishDeliversSignedEvent(t *testing.T) {
	d, st, box := newDispatcher(t)
	sealed, err := box.Seal("shared-secret")
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	srv, got := receiver(t, &hits, func(int32) int { return http.StatusOK })
	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "hermes", Endpoint: srv.URL, Secret: sealed, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	d.Publish(model.AnomalyEvent{ID: 41, Kind: "egress_spike", ProxyHost: "app.example.com", Value: 9000000})
	d.drain(context.Background())

	select {
	case r := <-got:
		mac := hmac.New(sha256.New, []byte("shared-secret"))
		mac.Write(r.body)
		if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); r.sig != want {
			t.Fatalf("signature = %q, want %q", r.sig, want)
		}
		if r.ts == "" {
			t.Fatal("no timestamp header, replays cannot be rejected")
		}
		var env struct {
			Type  string `json:"type"`
			Event struct {
				ID        int64  `json:"id"`
				Kind      string `json:"kind"`
				ProxyHost string `json:"proxy_host"`
			} `json:"event"`
		}
		if err := json.Unmarshal(r.body, &env); err != nil {
			t.Fatal(err)
		}
		if env.Type != "anomaly" || env.Event.Kind != "egress_spike" || env.Event.ID != 41 {
			t.Fatalf("unexpected envelope: %s", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the agent never received the event")
	}

	list, err := st.DeliveriesForLink(1, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("deliveries = %v, err %v", list, err)
	}
	if list[0].State != "delivered" || list[0].DeliveredAt == nil {
		t.Fatalf("a successful delivery was not recorded: %+v", list[0])
	}
}

// A failed delivery stays queued with a growing backoff and its error recorded,
// so an agent that was down still receives the event later.
func TestFailedDeliveryIsQueuedWithBackoff(t *testing.T) {
	d, st, _ := newDispatcher(t)
	var hits int32
	srv, _ := receiver(t, &hits, func(int32) int { return http.StatusBadGateway })
	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "down", Endpoint: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	d.Publish(model.AnomalyEvent{Kind: "rate_spike", ProxyHost: "app.example.com"})
	d.drain(context.Background())

	list, err := st.DeliveriesForLink(1, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("deliveries = %v, err %v", list, err)
	}
	del := list[0]
	if del.State != "pending" || del.Attempts != 1 {
		t.Fatalf("a failed delivery was not kept for retry: %+v", del)
	}
	if del.LastStatus != http.StatusBadGateway || del.LastError == "" {
		t.Fatalf("the agent's failure was not recorded: %+v", del)
	}
	if wait := time.Until(del.NextAttemptAt); wait < 20*time.Second || wait > 2*time.Minute {
		t.Fatalf("next attempt in %v, want the first backoff step", wait)
	}

	// Nothing is due yet, so a second drain must not retry early.
	d.drain(context.Background())
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("agent was called %d times before the backoff elapsed", n)
	}
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	if got := Backoff(1); got != 30*time.Second {
		t.Fatalf("first backoff = %v", got)
	}
	if got := Backoff(2); got != time.Minute {
		t.Fatalf("second backoff = %v", got)
	}
	if got := Backoff(20); got != time.Hour {
		t.Fatalf("backoff did not cap: %v", got)
	}
}

func TestPausedLinkReceivesNothing(t *testing.T) {
	d, st, _ := newDispatcher(t)
	var hits int32
	srv, _ := receiver(t, &hits, func(int32) int { return http.StatusOK })
	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "paused", Endpoint: srv.URL, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	d.Publish(model.AnomalyEvent{Kind: "rate_spike"})
	d.drain(context.Background())
	if list, _ := st.DeliveriesForLink(1, 10); len(list) != 0 {
		t.Fatalf("a paused link was queued: %+v", list)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("a paused link was called %d times", n)
	}
}

// A muted class is queued but never posted, so the agent receives only the
// event classes that are still enabled under Notifications -> Event routing.
func TestMutedClassIsQueuedButNotPosted(t *testing.T) {
	d, st, _ := newDispatcher(t)
	var hits int32
	srv, _ := receiver(t, &hits, func(int32) int { return http.StatusOK })
	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "hermes", Endpoint: srv.URL, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d.SetRouting(func(kind string) bool { return kind == "rate_spike" })

	d.Publish(model.AnomalyEvent{Kind: "egress_spike", ProxyHost: "app.example.com"})
	d.Publish(model.AnomalyEvent{Kind: "rate_spike", ProxyHost: "app.example.com"})
	d.drain(context.Background())

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("posted %d payloads, want only the enabled class", n)
	}
	list, err := st.DeliveriesForLink(1, 10)
	if err != nil || len(list) != 2 {
		t.Fatalf("deliveries = %v, err %v", list, err)
	}
	states := map[string]string{}
	for _, del := range list {
		states[del.Kind] = del.State
	}
	if states["egress_spike"] != "suppressed" || states["rate_spike"] != "delivered" {
		t.Fatalf("delivery states = %v", states)
	}
}
