package api

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
)

// The dashboard's request-budget card is fed by the event stream, not by the
// polled endpoint, so the streamed payload has to carry the proxy's budget. It
// did not, and the card sat at 0 / 0 while /api/metrics was correct.
func TestMetricsStreamCarriesTheRequestBudget(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	px, err := proxy.New(proxy.Deps{Store: st, Log: log, Metrics: metrics.New("", "")})
	if err != nil {
		t.Fatal(err)
	}
	px.SetMaxInflight(3)
	srv.proxy = px

	web := httptest.NewServer(srv.Handler())
	defer web.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, web.URL+"/api/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stream = %d", resp.StatusCode)
	}

	// The first tick arrives after a second; read frames until the metrics one.
	lines := bufio.NewReader(resp.Body)
	for {
		line, err := lines.ReadString('\n')
		if err != nil {
			t.Fatalf("no metrics event in the stream: %v", err)
		}
		if !strings.HasPrefix(line, "data: ") || !strings.Contains(line, `"max_inflight"`) {
			continue
		}
		if !strings.Contains(line, `"max_inflight":3`) {
			t.Fatalf("streamed payload has no budget: %s", strings.TrimSpace(line))
		}
		if !strings.Contains(line, `"inflight":0`) {
			t.Fatalf("streamed payload has no in-flight count: %s", strings.TrimSpace(line))
		}
		return
	}
}
