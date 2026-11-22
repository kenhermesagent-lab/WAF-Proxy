package agentlink

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestPublishSignsTheEventBody(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, err := crypto.New(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("shared-secret")
	if err != nil {
		t.Fatal(err)
	}

	type received struct {
		body []byte
		sig  string
		ts   string
	}
	got := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- received{body: body, sig: r.Header.Get("X-Wafproxy-Signature"), ts: r.Header.Get("X-Wafproxy-Timestamp")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "hermes", Endpoint: srv.URL, Secret: sealed, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	d := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.Publish(model.AnomalyEvent{Kind: "egress_spike", ProxyHost: "app.example.com", Value: 9000000})

	select {
	case r := <-got:
		mac := hmac.New(sha256.New, []byte("shared-secret"))
		mac.Write(r.body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if r.sig != want {
			t.Fatalf("signature = %q, want %q", r.sig, want)
		}
		if r.ts == "" {
			t.Fatal("no timestamp header, replays cannot be rejected")
		}
		var env struct {
			Type  string `json:"type"`
			Event struct {
				Kind      string `json:"kind"`
				ProxyHost string `json:"proxy_host"`
			} `json:"event"`
		}
		if err := json.Unmarshal(r.body, &env); err != nil {
			t.Fatal(err)
		}
		if env.Type != "anomaly" || env.Event.Kind != "egress_spike" || env.Event.ProxyHost != "app.example.com" {
			t.Fatalf("unexpected envelope: %s", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the agent never received the event")
	}
}

func TestPausedLinkReceivesNothing(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	box, _ := crypto.New(bytes.Repeat([]byte{6}, 32))
	hits := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits <- struct{}{} }))
	defer srv.Close()
	if _, err := st.CreateAgentLink(&model.AgentLink{Name: "paused", Endpoint: srv.URL, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil))).Publish(model.AnomalyEvent{Kind: "rate_spike"})
	select {
	case <-hits:
		t.Fatal("a paused link received an event")
	case <-time.After(300 * time.Millisecond):
	}
}
