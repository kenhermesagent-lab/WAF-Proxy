package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/threatintel"
)

const testAbuseKey = "0123456789abcdef0123456789abcdef"

// fakeIntel points the console's client at a local pair of endpoints so the
// tests never touch the public APIs.
func fakeIntel(t *testing.T, h *accountHarness, abuseStatus int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"SELECTEL-NET","startAddress":"5.42.64.0","endAddress":"5.42.64.255",
			"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Selectel"]]]}]}`))
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != testAbuseKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "999")
		w.Header().Set("X-RateLimit-Reset", "2026-11-25T00:00:00Z")
		if abuseStatus != http.StatusOK {
			w.WriteHeader(abuseStatus)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":100,"totalReports":2,"numDistinctUsers":2}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	h.srv.threat.Configure(srv.URL+"/ip/", srv.URL+"/check")
}

// The key is a credential: it is sealed in the database, and the page only ever
// sees a masked tail.
func TestThreatIntelKeyIsSealedAndMasked(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": testAbuseKey})
	if rec.Code != http.StatusOK {
		t.Fatalf("save key = %d: %s", rec.Code, rec.Body.String())
	}
	sealed, err := h.st.GetSetting(threatintel.KeyKey)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || sealed == testAbuseKey || strings.Contains(sealed, testAbuseKey) {
		t.Fatalf("key stored as %q", sealed)
	}

	get := h.get(t, "/api/threat-intel")
	if get.Code != http.StatusOK {
		t.Fatalf("status = %d", get.Code)
	}
	if strings.Contains(get.Body.String(), testAbuseKey) {
		t.Fatal("the status leaked the key")
	}
	var view threatIntelView
	if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Configured || !view.RDAP {
		t.Fatalf("view = %+v", view)
	}
	if view.KeyTail != "••••"+testAbuseKey[len(testAbuseKey)-4:] {
		t.Fatalf("key tail = %q", view.KeyTail)
	}
	// The probe that proves the key also captures the allowance the API reports.
	if view.Quota == nil || view.Quota.Limit != 1000 || view.Quota.Remaining != 999 {
		t.Fatalf("quota = %+v", view.Quota)
	}
	if view.Plan == nil || view.Plan.Name != "Individual (free)" {
		t.Fatalf("plan = %+v", view.Plan)
	}
}

func TestThreatIntelRejectsBadKeys(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": "too-short"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("short key = %d", rec.Code)
	}
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": "0123456789abcdef0123456789abcdef\nX: 1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("key with a newline = %d", rec.Code)
	}
}

// A key the API refuses must not be stored: otherwise the card would claim a
// working integration while every lookup failed.
func TestThreatIntelRefusedKeyIsNotStored(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusUnauthorized)
	rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": "fedcba9876543210fedcba9876543210"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("refused key = %d: %s", rec.Code, rec.Body.String())
	}
	if stored, _ := h.st.GetSetting(threatintel.KeyKey); stored != "" {
		t.Fatal("a refused key was stored")
	}
}

func TestThreatIntelClearKey(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": testAbuseKey}); rec.Code != http.StatusOK {
		t.Fatalf("save = %d", rec.Code)
	}
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear = %d", rec.Code)
	}
	get := h.get(t, "/api/threat-intel")
	var view threatIntelView
	if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Configured || view.KeyTail != "" {
		t.Fatalf("after clear = %+v", view)
	}
}

func TestThreatIntelLookup(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": testAbuseKey}); rec.Code != http.StatusOK {
		t.Fatalf("save = %d", rec.Code)
	}
	rec := h.get(t, "/api/threat-intel/lookup?ip=5.42.64.19")
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup = %d: %s", rec.Code, rec.Body.String())
	}
	var res threatintel.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.RDAP.Org != "Selectel" || res.Abuse == nil || res.Abuse.Score != 100 {
		t.Fatalf("result = %+v", res)
	}
	if res.Quota == nil || res.Quota.Remaining != 999 {
		t.Fatalf("quota = %+v", res.Quota)
	}
}

// The endpoint forwards to fixed hosts, so the address is validated before any
// request is built: a path or hostname must never reach the upstream URL.
func TestThreatIntelLookupRejectsNonIP(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	for _, bad := range []string{"example.com", "5.42.64.19/24", "../check", ""} {
		rec := h.get(t, "/api/threat-intel/lookup?ip="+bad)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q = %d: %s", bad, rec.Code, rec.Body.String())
		}
	}
}

// The quota block is persisted with the last lookup so the card still has it
// after a restart, and it is stored without the key.
func TestThreatIntelQuotaIsPersisted(t *testing.T) {
	h := newAccountHarness(t)
	fakeIntel(t, h, http.StatusOK)
	if rec := h.send(t, http.MethodPut, "/api/threat-intel", map[string]any{"abuseipdb_key": testAbuseKey}); rec.Code != http.StatusOK {
		t.Fatalf("save = %d", rec.Code)
	}
	raw, err := h.st.GetSetting(threatintel.KeyQuota)
	if err != nil {
		t.Fatal(err)
	}
	q := threatintel.DecodeQuota(raw)
	if q == nil || q.Limit != 1000 || q.Remaining != 999 {
		t.Fatalf("stored quota = %q", raw)
	}
	if !strings.Contains(raw, strconv.Itoa(1000)) {
		t.Fatalf("stored quota = %q", raw)
	}
}
