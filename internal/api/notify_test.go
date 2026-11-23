package api

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestNotificationTestEndpointSends(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer hook.Close()
	sealed, err := box.Seal(hook.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{"notify_webhook_enabled": "1", "notify_webhook_url": sealed}); err != nil {
		t.Fatal(err)
	}
	s := &Server{notify: notify.New(st, box, slog.New(slog.DiscardHandler))}

	call := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.testNotification(rec, httptest.NewRequest(http.MethodPost, "/api/notifications/test", strings.NewReader(body)))
		return rec
	}
	if rec := call(`{"channel":"webhook"}`); rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatal("the webhook was not called")
	}
	if rec := call(`{"channel":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown channel = %d", rec.Code)
	}
	if rec := call(`{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty channel = %d", rec.Code)
	}
}

func TestNotificationsReturns500WhenRecentAlertsFail(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{st: st, notify: notify.New(st, box, slog.New(slog.DiscardHandler))}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "wafproxy.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE alerts"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	rec := httptest.NewRecorder()
	s.getNotifications(rec, httptest.NewRequest(http.MethodGet, "/api/notifications", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("recent-alert failure = %d: %s", rec.Code, rec.Body.String())
	}
}
