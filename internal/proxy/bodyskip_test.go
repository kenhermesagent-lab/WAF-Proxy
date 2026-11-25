package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// A sync or backup client sends its whole file as application/octet-stream,
// which the CRS refuses as a content type outside its policy list before it
// reads a byte. That refusal protects a body the WAF inspects; on a skip path
// there is none, so the raw upload must still stream.
func TestBodySkipAcceptsARawUploadContentType(t *testing.T) {
	h := newHarness(t)
	// Skip first: attachBodySkip stores the harness's own copy of the site, so
	// enabling the WAF afterwards must be the last write.
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: http.MethodPut, Prefix: "/upload"}})
	enableBlockingWAF(t, h)
	raw := map[string]string{"Content-Type": "application/octet-stream"}

	// The same content type on a buffered path keeps its policy answer.
	if rec := h.request(http.MethodPut, testHost, "/index.html", "x", raw); rec.Code != http.StatusForbidden {
		t.Fatalf("octet-stream on a buffered path = %d, want 403", rec.Code)
	}

	payload := strings.Repeat("x", 2<<20)
	rec := h.request(http.MethodPut, testHost, "/upload", payload, raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw upload on a skip path = %d: %s", rec.Code, rec.Body.String())
	}
	if want := "size:2097152"; rec.Body.String() != want {
		t.Fatalf("upstream received %q, want %q", rec.Body.String(), want)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "body-skip" }); e.RuleID != "path" {
		t.Fatalf("event = %+v, want a body-skip event", e)
	}
}

// Streaming skips CRS's own method list, not the profile's: a method the
// profile does not allow is refused before the exemption applies.
func TestBodySkipStillHonoursTheProfileMethodList(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: http.MethodPut, Prefix: "/upload"}})
	attachProfile(t, h, model.Profile{Name: "no-put", AllowedMethods: "GET,HEAD,POST", MaxBody: 1 << 20})

	rec := h.request(http.MethodPut, testHost, "/upload", "x", map[string]string{"Content-Type": "application/octet-stream"})
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT outside the profile list = %d, want 405", rec.Code)
	}
}

// A buffered request is inspected, so the CRS method policy runs on it: it must
// read the profile's list rather than its own default, which has no PUT or
// PROPFIND. A method the profile leaves out is still refused.
func TestBufferedRequestHonoursTheProfileMethodList(t *testing.T) {
	h := newHarness(t)
	h.proxy.WAFMode = "block"
	attachProfile(t, h, model.Profile{Name: "webdav", AllowedMethods: "GET,HEAD,POST,PUT,PROPFIND", MaxBody: 1 << 20})
	// attachProfile saves the row; compiling it is what the console's save does
	// next, and without it the request falls back to the default engine.
	if err := h.pol.ReloadWAF(); err != nil {
		t.Fatal(err)
	}

	if rec := h.request(http.MethodPut, testHost, "/file", "payload", nil); rec.Code != http.StatusOK {
		t.Fatalf("buffered PUT allowed by the profile = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.request("PROPFIND", testHost, "/dir/", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("buffered PROPFIND allowed by the profile = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.request(http.MethodDelete, testHost, "/file", "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE outside the profile list = %d, want 405", rec.Code)
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

// The file-sync preset exempts Seafile's web upload root, so a POST there
// streams a whole file to the app, and the same entry with a trust list exempts
// only those sources: everyone else is still held to the ceiling.
func TestSeafileWebUploadStreamsAndTrustListsNarrowIt(t *testing.T) {
	h := newHarness(t)
	const upload = "/seafhttp/upload-aj/34a4ee81-4254-4f7f?ret-json=1"
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: http.MethodPost, Prefix: "/seafhttp/"}})

	payload := strings.Repeat("x", 2<<20)
	rec := h.request(http.MethodPost, testHost, upload, payload, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a Seafile web upload = %d: %s", rec.Code, rec.Body.String())
	}
	if want := "size:2097152"; rec.Body.String() != want {
		t.Fatalf("upstream received %q, want %q", rec.Body.String(), want)
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "body-skip" }); e.RuleID != "path" || e.BytesIn != int64(len(payload)) {
		t.Fatalf("event = %+v, want a streaming path event carrying %d bytes", e, len(payload))
	}
	// The prefix stops at a segment boundary, so a lookalike path is buffered.
	if rec := h.request(http.MethodPost, testHost, "/seafhttpfoo", payload, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a lookalike path = %d, want 413", rec.Code)
	}

	// A trust list exempts its own sources only; the fixture's address is outside.
	list := model.AccessList{Name: "home", Kind: "whitelist", IPs: "10.0.0.0/8"}
	if err := h.st.CreateAccessList(&list); err != nil {
		t.Fatal(err)
	}
	if err := h.pol.Reload(); err != nil {
		t.Fatal(err)
	}
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: http.MethodPost, Prefix: "/seafhttp/", ListIDs: []int64{list.ID}}})
	if rec := h.request(http.MethodPost, testHost, upload, payload, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a client outside the trust list = %d, want 413", rec.Code)
	}
	if rec := h.requestFrom("10.1.2.3", http.MethodPost, testHost, upload, payload, nil); rec.Code != http.StatusOK {
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

// A client that stops sending is dropped once the stall guard expires: the
// transfer itself has no deadline, so this is what keeps a dead upload from
// holding an upstream connection forever.
func TestBodySkipDropsAStalledUpload(t *testing.T) {
	h := newHarness(t)
	h.px.skipStall = 150 * time.Millisecond
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/upload"}})

	srv := httptest.NewServer(h.px)
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\n"+
		"Content-Type: application/octet-stream\r\nContent-Length: 1000000\r\n\r\npartial", testHost); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("a stalled upload got no answer: %v", err)
	}
	defer resp.Body.Close()
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the stall guard took %s to fire", waited)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a stalled upload = %d, want it dropped", resp.StatusCode)
	}
	e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "body-skip" && e.RuleID == "stalled" })
	if e.BytesIn != int64(len("partial")) {
		t.Fatalf("event recorded %d bytes in, want the 7 that arrived", e.BytesIn)
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

// noDeadlineWriter refuses a per-read deadline the way an HTTP/2 response does,
// so the watchdog path is exercised.
type noDeadlineWriter struct{}

func (noDeadlineWriter) Header() http.Header         { return http.Header{} }
func (noDeadlineWriter) Write(p []byte) (int, error) { return len(p), nil }
func (noDeadlineWriter) WriteHeader(int)             {}

// blockingBody never returns from Read until it is closed.
type blockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestStallReaderClosesABlockedBodyWithoutADeadline(t *testing.T) {
	body := &blockingBody{closed: make(chan struct{})}
	sr := newStallReader(body, 80*time.Millisecond, http.NewResponseController(noDeadlineWriter{}))
	start := time.Now()
	if _, err := sr.Read(make([]byte, 16)); err == nil {
		t.Fatal("a stalled body read returned no error")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("the watchdog took %s to close a blocked body", waited)
	}
	if !sr.didStall() {
		t.Fatal("the stalled read was not recorded")
	}
	if sr.bytes() != 0 {
		t.Fatalf("bytes = %d, want 0", sr.bytes())
	}
}

// A trailing star is the wildcard shorthand route matchers use, so an operator
// can write the path a Seafile client actually posts to. The segment boundary
// still holds, so the wildcard does not open a lookalike path.
func TestBodySkipWildcardCoversASubtree(t *testing.T) {
	h := newHarness(t)
	attachBodySkip(t, h, 1<<10, []model.BodySkip{{Method: "POST", Prefix: "/seafhttp/upload-aj/*"}})
	h.proxy.WAFMode = "block"

	big := strings.Repeat("x", 2<<20)
	rec := h.request(http.MethodPost, testHost, "/seafhttp/upload-aj/45caf4b6-abc7-4a7e", big,
		map[string]string{"Content-Type": "multipart/form-data; boundary=abc"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a wildcard skip path refused the upload: %d %s", rec.Code, rec.Body.String())
	}
	ev := h.waitEvent(t, func(e model.Event) bool { return strings.HasPrefix(e.Path, "/seafhttp/upload-aj/") })
	if ev.Stage != "body-skip" || ev.RuleID != "path" {
		t.Fatalf("stage = %q rule = %q, want body-skip/path", ev.Stage, ev.RuleID)
	}
	if ev.BytesIn != int64(len(big)) {
		t.Fatalf("bytes in = %d, want %d", ev.BytesIn, len(big))
	}

	// The named node itself and everything below it are covered.
	if rec := h.request(http.MethodPost, testHost, "/seafhttp/upload-aj", big, nil); rec.Code != http.StatusOK {
		t.Fatalf("/seafhttp/upload-aj = %d, want the wildcard to cover the node itself", rec.Code)
	}
	for _, path := range []string{"/seafhttp/upload-ajfoo", "/seafhttp/other"} {
		if rec := h.request(http.MethodPost, testHost, path, big, nil); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s = %d, want 413 from the buffered ceiling", path, rec.Code)
		}
	}
}

// The console asks which entry matched and whether the source was trusted, so a
// still-inspected upload can say why instead of looking like a missing entry.
func TestSkipMatchReportsAnUntrustedEntry(t *testing.T) {
	entries := []model.BodySkip{
		{Method: "POST", Prefix: "/seafhttp/*", ListIDs: []int64{7}},
		{Method: "POST", Prefix: "/api/assets"},
	}
	trusted := func(ids []int64) bool { return false }
	entry, ok := SkipMatch(entries, "POST", "/seafhttp/upload-aj/x", trusted)
	if entry == nil || ok || entry.Prefix != "/seafhttp/*" {
		t.Fatalf("entry = %+v, trusted = %v, want the untrusted /seafhttp/* entry", entry, ok)
	}
	entry, ok = SkipMatch(entries, "POST", "/api/assets", trusted)
	if entry == nil || !ok {
		t.Fatalf("an entry without lists was not trusted: %+v %v", entry, ok)
	}
	if entry, _ := SkipMatch(entries, "GET", "/seafhttp/x", trusted); entry != nil {
		t.Fatalf("a GET matched POST entry %q", entry.Prefix)
	}
}
