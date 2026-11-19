package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func newObservabilityServer(t *testing.T) (*Server, *store.Store, string, string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := st.CreateUser("admin", hash, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := wfcrypto.RandomToken(32)
	csrf, _ := wfcrypto.RandomToken(24)
	if err := st.CreateSession(token, uid, csrf, "127.0.0.1", "test", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.InsertEvents([]model.Event{
		{TS: now.Add(-time.Minute), SrcIP: "203.0.113.7", Country: "RU", ASN: 64500, Host: "app.example.com",
			Method: "GET", Path: "/.env", Status: 403, Action: "ban", Stage: "decoy", UA: "=cmd|test"},
		{TS: now.Add(-30 * time.Second), SrcIP: "203.0.113.7", Country: "RU", ASN: 64500, Host: "app.example.com",
			Method: "GET", Path: "/", Status: 200, Action: "allow", Stage: "route"},
	}); err != nil {
		t.Fatal(err)
	}
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, box, &config.Config{}, nil, nil, bans, nil, nil, nil, metrics.New("", ""), nil, nil, log)
	t.Cleanup(func() { _ = st.Close() })
	return srv, st, token, csrf
}

func TestEventCSVExportAndIPExplorer(t *testing.T) {
	srv, _, token, _ := newObservabilityServer(t)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	csvRec := get("/api/events/export.csv?hours=24")
	if csvRec.Code != http.StatusOK {
		t.Fatalf("CSV status = %d: %s", csvRec.Code, csvRec.Body.String())
	}
	if ct := csvRec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("CSV content type = %q", ct)
	}
	body := csvRec.Body.String()
	if !strings.Contains(body, "time,src_ip,country") || !strings.Contains(body, "203.0.113.7") {
		t.Fatalf("CSV body missing expected content: %q", body)
	}
	// A user agent beginning with = must be neutralised for spreadsheets.
	if strings.Contains(body, ",=cmd") || !strings.Contains(body, "'=cmd") {
		t.Fatalf("CSV formula was not neutralised: %q", body)
	}

	listRec := get("/api/ips?hours=24")
	if listRec.Code != http.StatusOK {
		t.Fatalf("IP list status = %d: %s", listRec.Code, listRec.Body.String())
	}
	var list struct {
		IPs []struct {
			IP       string `json:"ip"`
			Requests int64  `json:"requests"`
		} `json:"ips"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.IPs) != 1 || list.IPs[0].IP != "203.0.113.7" || list.IPs[0].Requests != 2 {
		t.Fatalf("unexpected IP list: %+v", list)
	}

	detailRec := get("/api/ips/203.0.113.7?hours=24")
	if detailRec.Code != http.StatusOK {
		t.Fatalf("IP detail status = %d: %s", detailRec.Code, detailRec.Body.String())
	}
	var detail struct {
		Summary struct {
			IP      string `json:"ip"`
			Blocked int64  `json:"blocked"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Summary.IP != "203.0.113.7" || detail.Summary.Blocked != 1 {
		t.Fatalf("unexpected IP summary: %+v", detail.Summary)
	}
	missing := get("/api/ips/192.0.2.99?hours=24")
	if missing.Code != http.StatusOK {
		t.Fatalf("missing IP detail status = %d: %s", missing.Code, missing.Body.String())
	}

	csRec := get("/api/crowdsec/status")
	if csRec.Code != http.StatusOK || !strings.Contains(csRec.Body.String(), "\"configured\":false") {
		t.Fatalf("crowdsec status = %d %s", csRec.Code, csRec.Body.String())
	}
}
