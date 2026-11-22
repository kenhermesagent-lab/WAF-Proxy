package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// A forwarder stores the ids of the lists it enforces, refuses an id that does
// not exist, and will not let that list be deleted behind its back.
func TestStreamingListSelectionIsSavedAndValidated(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.SetStreaming(streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil))))
	list := createList(t, srv, token, csrf, `{"kind":"blocklist","name":"scanners","ips":"203.0.113.9"}`)

	put := func(ids string) *httptest.ResponseRecorder {
		return authed(t, srv, token, csrf, http.MethodPut, "/api/streaming/plex",
			fmt.Sprintf(`{"enabled":false,"listen_ip":"192.168.191.2","port":32400,`+
				`"upstream":"10.0.0.10:32400","allow":"","max_conns":64,"list_ids":%s}`, ids))
	}

	rec := put(fmt.Sprintf("[%d]", list.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/streaming/plex = %d: %s", rec.Code, rec.Body.String())
	}
	kv, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got := kv["stream_plex_lists"]; got != listIDStr(list.ID) {
		t.Fatalf("stream_plex_lists = %q, want %s", got, listIDStr(list.ID))
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/streaming", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/streaming = %d", rec.Code)
	}
	var view struct{ Services []streaming.Status }
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode streaming view: %v", err)
	}
	if len(view.Services) == 0 || len(view.Services[0].ListIDs) != 1 || view.Services[0].ListIDs[0] != list.ID {
		t.Fatalf("saved list ids not reported back: %+v", view.Services)
	}

	if rec := put("[999999]"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown list") {
		t.Fatalf("PUT with an unknown list = %d: %s", rec.Code, rec.Body.String())
	}

	// The port still enforces the list, so deleting it would silently open the
	// port up: the console is told to detach it first.
	rec = authed(t, srv, token, csrf, http.MethodDelete, "/api/lists/"+listIDStr(list.ID), "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Plex forwarder") {
		t.Fatalf("DELETE attached list = %d: %s", rec.Code, rec.Body.String())
	}

	// Detaching it first makes the delete succeed.
	if rec := put("[]"); rec.Code != http.StatusOK {
		t.Fatalf("PUT without lists = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := authed(t, srv, token, csrf, http.MethodDelete, "/api/lists/"+listIDStr(list.ID), ""); rec.Code != http.StatusOK {
		t.Fatalf("DELETE detached list = %d: %s", rec.Code, rec.Body.String())
	}
}
