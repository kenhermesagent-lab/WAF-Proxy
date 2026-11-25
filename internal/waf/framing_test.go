package waf

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Go's server keeps the framing on the request instead of in Header, so the
// engine has to be handed it back. Without this, every POST and PUT the proxy
// forwards matches CRS 920180 and starts out carrying protocol-violation
// anomaly points, which is enough for a legitimate upload to be refused once
// any other notice lands on top.
func TestEngineSeesTheRequestFraming(t *testing.T) {
	e, err := compile(model.Profile{ID: 1, Name: "test", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.10")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte("A"), 512)); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	upload := buf.Bytes()

	// A POST with a declared length: the header is gone, r.ContentLength holds it.
	req := httptest.NewRequest("POST", "/seafhttp/upload-aj/34a4ee81?ret-json=1", bytes.NewReader(upload))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if _, ok := req.Header["Content-Length"]; ok {
		t.Fatalf("test premise broken: Content-Length is still in Header")
	}
	res, matches := e.InspectAllWith(req, upload, ip, InspectOptions{})
	if res.Blocked {
		t.Fatalf("a framed upload was blocked: rule %d %q", res.RuleID, res.Message)
	}
	for _, m := range matches {
		if m.RuleID == 920180 {
			t.Fatalf("920180 fired although the request declares Content-Length %d", req.ContentLength)
		}
	}

	// A chunked upload: Go moves Transfer-Encoding onto the request too.
	chunked := httptest.NewRequest("POST", "/seafhttp/upload-aj/34a4ee81", bytes.NewReader([]byte("data")))
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	chunked.Header.Del("Content-Length")
	chunked.Header.Set("Content-Type", "application/octet-stream")
	res, matches = e.InspectAllWith(chunked, []byte("data"), ip, InspectOptions{BodyStreamed: true})
	if res.Blocked {
		t.Fatalf("a chunked POST was blocked: rule %d %q", res.RuleID, res.Message)
	}
	for _, m := range matches {
		if m.RuleID == 920180 {
			t.Fatalf("920180 fired although the request is chunked")
		}
	}
}
