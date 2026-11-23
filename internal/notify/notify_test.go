package notify

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestNormalizeTelegramChat(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"-1001234567890":              "-1001234567890",
		"123456789":                   "123456789",
		"@channel":                    "@channel",
		"channel":                     "@channel",
		"https://t.me/channel":        "@channel",
		"http://t.me/channel/":        "@channel",
		"https://telegram.me/channel": "@channel",
		"https://t.me/@channel":       "@channel",
	}
	for in, want := range cases {
		if got := normalizeTelegramChat(in); got != want {
			t.Errorf("normalizeTelegramChat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTelegramPayloadUsesBooleanPreviewFlag(t *testing.T) {
	raw, err := json.Marshal(telegramMessage{
		ChatID:                "@channel",
		Text:                  "test",
		ParseMode:             "HTML",
		DisableWebPagePreview: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["disable_web_page_preview"] != true {
		t.Fatalf("disable_web_page_preview = %#v, want true", payload["disable_web_page_preview"])
	}
}

func TestEscapeTelegramHTML(t *testing.T) {
	if got, want := escapeTelegramHTML(`a & <b> "c"`), `a &amp; &lt;b&gt; "c"`; got != want {
		t.Fatalf("escapeTelegramHTML = %q, want %q", got, want)
	}
}

func TestBanClassRoutesCrowdSecSeparately(t *testing.T) {
	cases := []struct {
		source    string
		permanent bool
		want      string
	}{
		{"crowdsec", false, KindCrowdSecBan},
		{"CrowdSec", true, KindCrowdSecBan},
		{"  crowdsec: firehol_cruzit_web_attacks  ", false, KindCrowdSecBan},
		{"manual", false, KindBan},
		{"manual", true, KindPermanentBan},
	}
	for _, c := range cases {
		if got := BanClass(c.source, c.permanent); got != c.want {
			t.Fatalf("BanClass(%q, %v) = %q, want %q", c.source, c.permanent, got, c.want)
		}
	}
}

type notifyFixture struct {
	mgr  *Manager
	st   *store.Store
	hits *int32
}

func newNotifyFixture(t *testing.T) notifyFixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := wfcrypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	sealed, err := box.Seal(srv.URL + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{
		"notify_webhook_enabled": "1",
		"notify_webhook_url":     sealed,
	}); err != nil {
		t.Fatal(err)
	}
	return notifyFixture{
		mgr:  New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil))),
		st:   st,
		hits: &hits,
	}
}

func (f notifyFixture) setEvents(t *testing.T, value string) {
	t.Helper()
	if err := f.st.SetSettings(map[string]string{"notify_events": value}); err != nil {
		t.Fatal(err)
	}
}

// TestMutedClassIsNeitherQueuedNorDelivered covers the first half of the bug: a
// ban whose class is muted never enters the queue at all.
func TestMutedClassIsNeitherQueuedNorDelivered(t *testing.T) {
	f := newNotifyFixture(t)
	f.setEvents(t, "ban")

	f.mgr.Enqueue(KindCrowdSecBan, "Temporary ban: 203.0.113.1/32 — crowdsec (source: crowdsec)", "ban:203.0.113.1", false)
	if alerts, _ := f.st.PendingAlerts(10); len(alerts) != 0 {
		t.Fatalf("a muted class was queued: %+v", alerts)
	}

	f.mgr.Enqueue(KindBan, "Temporary ban: 203.0.113.2/32 — scan (source: scan)", "ban:203.0.113.2", false)
	f.mgr.process(false)
	if n := atomic.LoadInt32(f.hits); n != 1 {
		t.Fatalf("the enabled class made %d deliveries, want 1", n)
	}
}

// TestQueuedAlertsStopWhenTheirClassIsMuted covers the second half: an alert
// that was already pending when the class was muted must not be delivered.
func TestQueuedAlertsStopWhenTheirClassIsMuted(t *testing.T) {
	f := newNotifyFixture(t)
	f.setEvents(t, "")
	f.mgr.Enqueue(KindCrowdSecBan, "Temporary ban: 203.0.113.3/32 — crowdsec (source: crowdsec)", "ban:203.0.113.3", false)

	f.setEvents(t, "ban,permanent_ban")
	f.mgr.process(false)

	if n := atomic.LoadInt32(f.hits); n != 0 {
		t.Fatalf("an alert of a muted class was delivered %d time(s)", n)
	}
	alerts, err := f.st.RecentAlerts(10)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts = %v, err %v", alerts, err)
	}
	if alerts[0].State != "suppressed" {
		t.Fatalf("queued alert state = %q, want suppressed", alerts[0].State)
	}
}

// TestLegacyBanRowWithCrowdSecSourceIsSuppressed covers rows an older build
// stored as kind "ban": the source is only in the message, and muting CrowdSec
// must still stop them.
func TestLegacyBanRowWithCrowdSecSourceIsSuppressed(t *testing.T) {
	f := newNotifyFixture(t)
	f.setEvents(t, "ban,permanent_ban")
	if err := f.st.EnqueueAlertState("webhook", KindBan, "ban:203.0.113.4",
		"Temporary ban: 203.0.113.4/32 — crowdsec: firehol_cruzit_web_attacks (source: crowdsec)", "pending"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.EnqueueAlertState("webhook", KindBan, "ban:203.0.113.5",
		"Temporary ban: 203.0.113.5/32 — port scan (source: scan)", "pending"); err != nil {
		t.Fatal(err)
	}

	f.mgr.process(false)

	if n := atomic.LoadInt32(f.hits); n != 1 {
		t.Fatalf("made %d deliveries, want only the non-CrowdSec ban", n)
	}
	alerts, err := f.st.RecentAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, a := range alerts {
		states[a.Payload] = a.State
	}
	if states["Temporary ban: 203.0.113.4/32 — crowdsec: firehol_cruzit_web_attacks (source: crowdsec)"] != "suppressed" {
		t.Fatalf("legacy CrowdSec row was not suppressed: %v", states)
	}
	if states["Temporary ban: 203.0.113.5/32 — port scan (source: scan)"] != "sent" {
		t.Fatalf("an ordinary ban was not delivered: %v", states)
	}
}

func TestTestSendsAREalWebhook(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, err := wfcrypto.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- string(body)
	}))
	defer srv.Close()
	sealed, err := box.Seal(srv.URL + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{"notify_webhook_enabled": "1", "notify_webhook_url": sealed}); err != nil {
		t.Fatal(err)
	}
	m := New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Test("webhook"); err != nil {
		t.Fatalf("test delivery: %v", err)
	}
	select {
	case body := <-bodies:
		if !strings.Contains(body, "Test notification from WAF-Proxy") {
			t.Fatalf("webhook body = %q", body)
		}
	default:
		t.Fatal("the test notification was not delivered")
	}
	if err := m.Test("carrier-pigeon"); err == nil {
		t.Fatal("an unknown channel was accepted")
	}
}

func TestEnqueueDeduplicatesTheSameKey(t *testing.T) {
	f := newNotifyFixture(t)
	f.setEvents(t, "")
	f.mgr.Enqueue("rate_spike", "Request-rate spike: app.example.com", "anomaly:rate_spike:4", true)
	f.mgr.Enqueue("rate_spike", "Request-rate spike: app.example.com", "anomaly:rate_spike:4", true)
	alerts, err := f.st.PendingAlerts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("queued %d alerts for one key, want 1", len(alerts))
	}
	f.mgr.Enqueue("rate_spike", "Request-rate spike: app.example.com", "anomaly:rate_spike:5", true)
	if alerts, _ := f.st.PendingAlerts(10); len(alerts) != 2 {
		t.Fatalf("a different key was deduplicated: %d alerts", len(alerts))
	}
}
