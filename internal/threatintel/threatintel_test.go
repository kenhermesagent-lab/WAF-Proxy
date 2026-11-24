package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

const rdapAnswer = `{
  "handle": "5.42.64.0 - 5.42.64.255",
  "name": "SELECTEL-NET",
  "startAddress": "5.42.64.0",
  "endAddress": "5.42.64.255",
  "events": [{"eventAction": "registration", "eventDate": "2012-06-14T09:12:03Z"}],
  "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Selectel"]]]},
    {"roles": ["abuse"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Selectel Abuse"], ["email", {}, "text", "abuse@selectel.ru"]]]}
  ]
}`

const abuseAnswer = `{"data": {
  "abuseConfidenceScore": 100,
  "totalReports": 3410,
  "numDistinctUsers": 486,
  "lastReportedAt": "2026-11-24T17:41:00+00:00",
  "usageType": "Data Center/Web Hosting/Transit",
  "isp": "Selectel",
  "domain": "selectel.ru",
  "countryCode": "RU"
}}`

// fakeAPIs serves both endpoints and counts the AbuseIPDB checks, so a test can
// prove the cache saved a lookup.
func fakeAPIs(t *testing.T, status int) (*httptest.Server, *int32) {
	t.Helper()
	var checks int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(rdapAnswer))
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&checks, 1)
		if got := r.Header.Get("Key"); got != "0123456789abcdef0123456789abcdef" {
			http.Error(w, `{"errors":[{"detail":"authentication failed"}]}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "871")
		w.Header().Set("X-RateLimit-Reset", "2026-11-25T00:00:00Z")
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(abuseAnswer))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &checks
}

func newTestClient(t *testing.T, status int) (*Client, *int32) {
	t.Helper()
	srv, checks := fakeAPIs(t, status)
	c := New()
	c.Configure(srv.URL+"/ip/", srv.URL+"/check")
	c.TTL = time.Hour
	return c, checks
}

func TestLookupReadsRDAPAndQuota(t *testing.T) {
	c, _ := newTestClient(t, http.StatusOK)
	res, err := c.Lookup(context.Background(), "5.42.64.19", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if res.RDAP.Network != "5.42.64.0 – 5.42.64.255" || res.RDAP.Name != "SELECTEL-NET" {
		t.Fatalf("rdap = %+v", res.RDAP)
	}
	if res.RDAP.Org != "Selectel" || res.RDAP.Abuse != "abuse@selectel.ru" {
		t.Fatalf("rdap entities = %+v", res.RDAP)
	}
	if res.RDAP.Registered != "2012-06-14" {
		t.Fatalf("registered = %q", res.RDAP.Registered)
	}
	if res.Abuse == nil || res.Abuse.Score != 100 || res.Abuse.Reports != 3410 || res.Abuse.Reporters != 486 {
		t.Fatalf("abuse = %+v", res.Abuse)
	}
	if res.Quota == nil || res.Quota.Limit != 1000 || res.Quota.Remaining != 871 {
		t.Fatalf("quota = %+v", res.Quota)
	}
	if plan := PlanFor(res.Quota.Limit); plan == nil || plan.Name != "Individual (free)" {
		t.Fatalf("plan = %+v", plan)
	}
}

// The note above the source drawer promises a six-hour cache; a second open of
// the same address must not spend another check.
func TestLookupIsCached(t *testing.T) {
	c, checks := newTestClient(t, http.StatusOK)
	for i := 0; i < 3; i++ {
		if _, err := c.Lookup(context.Background(), "5.42.64.19", "0123456789abcdef0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
	}
	if n := atomic.LoadInt32(checks); n != 1 {
		t.Fatalf("AbuseIPDB checks = %d, want 1", n)
	}
}

// A spent quota is reported, not cached: the next open should try again once the
// allowance resets.
func TestLookupReportsSpentQuota(t *testing.T) {
	c, _ := newTestClient(t, http.StatusTooManyRequests)
	res, err := c.Lookup(context.Background(), "5.42.64.19", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if res.Abuse == nil || !strings.Contains(res.Abuse.Error, "quota") {
		t.Fatalf("abuse = %+v", res.Abuse)
	}
	if res.Quota == nil || res.Quota.Remaining != 871 {
		t.Fatalf("quota = %+v", res.Quota)
	}
}

func TestLookupNeedsNoKeyForRDAP(t *testing.T) {
	c, checks := newTestClient(t, http.StatusOK)
	res, err := c.Lookup(context.Background(), "5.42.64.19", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.RDAP.Name == "" || res.Abuse != nil {
		t.Fatalf("result = %+v", res)
	}
	if n := atomic.LoadInt32(checks); n != 0 {
		t.Fatalf("AbuseIPDB was called without a key")
	}
}

func TestLookupRejectsNonIP(t *testing.T) {
	c, _ := newTestClient(t, http.StatusOK)
	if _, err := c.Lookup(context.Background(), "example.com", "k"); err == nil {
		t.Fatal("a hostname was accepted as an address")
	}
}

func TestPlanForUnknownCeiling(t *testing.T) {
	if PlanFor(42) != nil {
		t.Fatal("an unknown ceiling was given a plan")
	}
	if PlanFor(5000).Name != "Supporter" {
		t.Fatalf("5000 = %+v", PlanFor(5000))
	}
}

func TestValidKeyRejectsHeaderInjection(t *testing.T) {
	if ValidKey("short") {
		t.Fatal("a short key was accepted")
	}
	if ValidKey("0123456789abcdef0123456789abcdef\r\nX-Evil: 1") {
		t.Fatal("a key with a newline was accepted")
	}
	if !ValidKey("0123456789abcdef0123456789abcdef") {
		t.Fatal("a normal key was refused")
	}
}

func TestSealedKeyRoundTrip(t *testing.T) {
	box, err := wfcrypto.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	key := "0123456789abcdef0123456789abcdef"
	sealed, err := SealKey(box, key)
	if err != nil {
		t.Fatal(err)
	}
	if sealed == key || strings.Contains(sealed, key) {
		t.Fatal("the key was stored in the clear")
	}
	if got := LoadKey(map[string]string{KeyKey: sealed}, box); got != key {
		t.Fatalf("LoadKey = %q", got)
	}
	// A key sealed by another master key reads as missing, so the console asks
	// for it again instead of showing an empty card.
	other, _ := wfcrypto.New([]byte(strings.Repeat("z", 32)))
	if got := LoadKey(map[string]string{KeyKey: sealed}, other); got != "" {
		t.Fatalf("LoadKey with the wrong box = %q", got)
	}
}

func TestQuotaCodec(t *testing.T) {
	q := &Quota{Limit: 1000, Remaining: 12, ResetAt: "2026-11-25T00:00:00Z"}
	raw := EncodeQuota(q)
	blob, err := json.Marshal(DecodeQuota(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"remaining":12`) {
		t.Fatalf("round trip = %s", blob)
	}
	if DecodeQuota("not json") != nil {
		t.Fatal("garbage quota decoded")
	}
}
