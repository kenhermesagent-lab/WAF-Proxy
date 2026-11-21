package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	updatepkg "github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

// helperStub answers the helper protocol from a Unix socket and reports the
// requests it received.
func helperStub(t *testing.T, reply updatepkg.HelperResponse) (string, chan updatepkg.HelperRequest) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "updates.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	calls := make(chan updatepkg.HelperRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req updatepkg.HelperRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				continue
			}
			calls <- req
			_ = json.NewEncoder(conn).Encode(reply)
			conn.Close()
		}
	}()
	return socket, calls
}

func configureRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/updates/app/config", strings.NewReader(body))
	sess := &store.Session{Username: "admin"}
	return req.WithContext(context.WithValue(req.Context(), sessionKey, sess))
}

func TestConfigureAppUpdateEndpoint(t *testing.T) {
	socket, calls := helperStub(t, updatepkg.HelperResponse{OK: true, Output: "recorded /srv/WAF-Proxy"})
	t.Setenv("WAFPROXY_UPDATE_SOCKET", socket)
	m := updatepkg.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{updates: m, st: st}

	rec := httptest.NewRecorder()
	s.configureAppUpdate(rec, configureRequest(t, `{"path":"/srv/WAF-Proxy"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	select {
	case req := <-calls:
		if req.Action != updatepkg.HelperActionAppConfigure {
			t.Fatalf("action = %q, want %q", req.Action, updatepkg.HelperActionAppConfigure)
		}
		if req.Path != "/srv/WAF-Proxy" {
			t.Fatalf("path = %q", req.Path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the helper was not called")
	}
}

func TestConfigureAppUpdateEndpointRejectsEmptyPath(t *testing.T) {
	_, calls := helperStub(t, updatepkg.HelperResponse{OK: true})
	t.Setenv("WAFPROXY_UPDATE_SOCKET", "")
	m := updatepkg.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{updates: m, st: st}

	rec := httptest.NewRecorder()
	s.configureAppUpdate(rec, configureRequest(t, `{"path":"  "}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	select {
	case req := <-calls:
		t.Fatalf("helper called with %+v for an empty path", req)
	default:
	}
}

func TestConfigureAppUpdateEndpointReportsHelperError(t *testing.T) {
	socket, _ := helperStub(t, updatepkg.HelperResponse{Error: "/srv/WAF-Proxy is not a git checkout (no .git)"})
	t.Setenv("WAFPROXY_UPDATE_SOCKET", socket)
	m := updatepkg.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{updates: m, st: st}

	rec := httptest.NewRecorder()
	s.configureAppUpdate(rec, configureRequest(t, `{"path":"/srv/WAF-Proxy"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no .git") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
