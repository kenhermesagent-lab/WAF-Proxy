package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLookupIP(t *testing.T) {
	srv, _, token, _ := newObservabilityServer(t)
	get := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/intel/lookup?ip="+ip, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := get("not-an-ip"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid address status = %d, want 400", rec.Code)
	}

	var out struct {
		IP   string          `json:"ip"`
		Feed json.RawMessage `json:"feed"`
		Ban  *struct {
			CIDR      string `json:"cidr"`
			Reason    string `json:"reason"`
			Source    string `json:"source"`
			Permanent bool   `json:"permanent"`
		} `json:"ban"`
	}
	rec := get("203.0.113.7")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Ban != nil {
		t.Fatalf("an unchecked address reported a ban: %s", rec.Body)
	}

	if _, err := srv.bans.Add("203.0.113.7", "crowdsec: ssh:bruteforce", "crowdsec", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	rec = get("203.0.113.7")
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Ban == nil || out.Ban.Source != "crowdsec" || out.Ban.Permanent || !strings.Contains(out.Ban.Reason, "bruteforce") {
		t.Fatalf("ban not reported: %s", rec.Body)
	}
}
