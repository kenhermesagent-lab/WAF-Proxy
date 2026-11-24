package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// A client that trickles its body must lose its budget slot at the deadline
// instead of holding it for as long as it keeps the connection open.
func TestBodyDeadlineCutsATrickle(t *testing.T) {
	h := newHarness(t)
	h.px.SetBodyTimeout(100 * time.Millisecond)
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.px)
	defer srv.Close()

	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		for i := 0; i < 400; i++ {
			if _, err := pw.Write([]byte("a")); err != nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testHost

	start := time.Now()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("a trickled body ran %s: the deadline did not fire", elapsed)
	}
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestTimeout {
			t.Fatalf("trickled body = %d, want 408", resp.StatusCode)
		}
	}
	h.waitEvent(t, func(e model.Event) bool {
		return e.Stage == "protocol" && e.RuleID == "body-timeout"
	})
	if inflight, _, _ := h.px.Capacity(); inflight != 0 {
		t.Fatalf("%d budget slots still held after the body deadline", inflight)
	}
}

// A response that streams for longer than the body deadline is untouched by it.
func TestStreamedResponseOutlivesTheBodyDeadline(t *testing.T) {
	h := newHarness(t)
	h.px.SetBodyTimeout(100 * time.Millisecond)
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.px)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/trickle", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = testHost
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "chunk-4") {
		t.Fatalf("streamed response was cut: %q", body)
	}
}
