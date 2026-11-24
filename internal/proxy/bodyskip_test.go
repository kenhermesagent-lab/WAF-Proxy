package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// attachBodySkip stores the body settings on the harness proxy and reloads it
// the way the console does after a save.
func attachBodySkip(t *testing.T, h *harness, maxBody int64, entries []model.BodySkip) {
	t.Helper()
	h.proxy.MaxBody = maxBody
	h.proxy.BodySkip = entries
	if err := h.st.UpdateProxy(&h.proxy); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A skip path carries an upload past the ceiling and outside the buffer budget:
// the bytes reach the app, the event says the body was not inspected, and the
// budget is left as it was.
func TestBodySkipStreamsUploadPastTheCeiling(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})

	payload := strings.Repeat("x", 2<<20)
	rec := h.request(http.MethodPost, testHost, "/upload", payload, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("streamed upload = %d: %s", rec.Code, rec.Body.String())
	}
	if want := "size:2097152"; rec.Body.String() != want {
		t.Fatalf("upstream received %q, want %q", rec.Body.String(), want)
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "body-skip" })
	if e.BytesIn != int64(len(payload)) {
		t.Fatalf("event recorded %d bytes in, want %d", e.BytesIn, len(payload))
	}
	if st := h.px.budget.snapshot(); st.bytes != 0 || st.count != 0 {
		t.Fatalf("a streamed body was charged to the budget: %+v", st)
	}
}

// The exemption is one method and one path: everything else is still buffered
// and still refused over the site ceiling.
func TestBodySkipIsBoundToItsMethodAndPath(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})

	big := strings.Repeat("x", 2<<20)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/index.html"},
		{http.MethodPost, "/uploader"}, // a segment boundary, not a string prefix
		{http.MethodPut, "/upload"},    // the right path, the wrong method
	} {
		if rec := h.request(tc.method, testHost, tc.path, big, nil); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s %s = %d, want 413", tc.method, tc.path, rec.Code)
		}
	}
}

// The body is unseen, so no body rule can catch what it carries; the rest of
// the pipeline still applies, and a ban is still a ban.
func TestBodySkipStillHonoursABan(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})
	if _, err := h.bans.Add(testIP+"/32", "test", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}

	before := h.hits.Load()
	rec := h.request(http.MethodPost, testHost, "/upload", strings.Repeat("x", 2<<20), nil)
	if rec.Code == http.StatusOK {
		t.Fatal("a banned address reached the app through a skip path")
	}
	if h.hits.Load() != before {
		t.Fatal("the upstream saw a request from a banned address")
	}
}

// A skip entry that names lists exempts those sources only; everyone else is
// still inspected, so trusting a CIDR does not open the path to the internet.
func TestBodySkipListNarrowsTheExemption(t *testing.T) {
	h := newHarness(t)
	list := model.AccessList{Name: "trusted", Kind: "whitelist", IPs: "10.0.0.0/8"}
	if err := h.st.CreateAccessList(&list); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload", ListIDs: []int64{list.ID}}})

	big := strings.Repeat("x", 2<<20)
	if rec := h.request(http.MethodPost, testHost, "/upload", big, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a client outside the trust list = %d, want 413", rec.Code)
	}
	if rec := h.requestFrom("10.1.2.3", http.MethodPost, testHost, "/upload", big, nil); rec.Code != http.StatusOK {
		t.Fatalf("a client inside the trust list = %d: %s", rec.Code, rec.Body.String())
	}
}

// slowBody sends a request body in paced pieces, so a transfer takes longer than
// a short deadline.
type slowBody struct {
	total int
	read  int
	pause time.Duration
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.read >= b.total {
		return 0, io.EOF
	}
	time.Sleep(b.pause)
	n := len(p)
	if left := b.total - b.read; n > left {
		n = left
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	b.read += n
	return n, nil
}

func (h *harness) requestStream(method, host, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	req.Host = host
	req.URL.Scheme = "https"
	req.URL.Host = host
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = testIP + ":43210"
	rec := httptest.NewRecorder()
	h.px.ServeHTTP(rec, req)
	return rec
}

// A slow upload on a skip path outlives the site's whole-exchange timeout: the
// client sets the pace of a streamed body, so a 60-second upstream timeout must
// not cut a ten-minute upload.
func TestBodySkipOutlivesTheUpstreamTimeout(t *testing.T) {
	h := newHarness(t)
	h.proxy.UpstreamTimeout = 1
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})

	rec := h.requestStream(http.MethodPost, testHost, "/upload", &slowBody{total: 512 << 10, pause: 100 * time.Millisecond})
	if rec.Code != http.StatusOK {
		t.Fatalf("slow streamed upload = %d: %s", rec.Code, rec.Body.String())
	}
	if want := "size:524288"; rec.Body.String() != want {
		t.Fatalf("upstream received %q, want %q", rec.Body.String(), want)
	}
}

// The body is only streamed once the access gate lets the request through: a
// skip path is an inspection exemption, not a way around sign-in.
func TestBodySkipIsStillGated(t *testing.T) {
	h := newHarness(t)
	h.proxy.GateMode = "passphrase"
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})

	before := h.hits.Load()
	rec := h.request(http.MethodPost, testHost, "/upload", strings.Repeat("x", 2<<20), nil)
	if strings.HasPrefix(rec.Body.String(), "size:") {
		t.Fatal("the body reached the app without passing the gate")
	}
	if h.hits.Load() != before {
		t.Fatal("the upstream saw a request the gate should have answered")
	}
}

// The site ceiling replaces the host-wide one, and zero hands the site back to
// it instead of meaning "no bodies at all".
func TestSiteBodyCeilingOverridesTheHostSetting(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<20, nil)

	if rec := h.request(http.MethodPost, testHost, "/index.html", strings.Repeat("x", 512<<10), nil); rec.Code != http.StatusOK {
		t.Fatalf("512 KiB under a 1 MiB ceiling = %d, want 200", rec.Code)
	}
	if rec := h.request(http.MethodPost, testHost, "/index.html", strings.Repeat("x", 2<<20), nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("2 MiB over a 1 MiB ceiling = %d, want 413", rec.Code)
	}

	attachBodySkip(t, h, 0, nil)
	if rec := h.request(http.MethodPost, testHost, "/index.html", strings.Repeat("x", 2<<20), nil); rec.Code != http.StatusOK {
		t.Fatalf("2 MiB under the inherited 64 MiB ceiling = %d, want 200", rec.Code)
	}
}
