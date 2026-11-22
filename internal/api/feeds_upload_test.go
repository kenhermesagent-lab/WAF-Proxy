package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/intel"
)

func TestUploadLocalFeedPersistsFileAndDeletesIt(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.cfg.DataDir = t.TempDir()
	srv.feeds = intel.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "blocklist.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("reason,ip\nscanner,203.0.113.7\n")); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("name", "Uploaded test list"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/feeds/upload", &body)
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/feeds/upload = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID      int64 `json:"id"`
		Entries int   `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Entries != 1 {
		t.Fatalf("entries = %d, want 1", created.Entries)
	}

	feed, err := st.FeedByID(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !feed.Local || feed.Filename != "blocklist.csv" || feed.Action != "block" {
		t.Fatalf("feed = %+v", feed)
	}
	if _, err := os.Stat(feed.LocalPath); err != nil {
		t.Fatalf("uploaded file is missing: %v", err)
	}
	path := feed.LocalPath

	// The handler refreshes in the background; wait for it so the test does not
	// delete the file or close the store underneath that refresh.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		refreshed, err := st.FeedByID(created.ID)
		if err == nil && refreshed.LastCount == 1 {
			break
		}
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/feeds/"+strconv.FormatInt(created.ID, 10), nil)
	del.Host = "gui.local"
	del.RemoteAddr = "10.0.0.10:5000"
	del.Header.Set("X-CSRF-Token", csrf)
	del.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	delRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE feed = %d: %s", delRec.Code, delRec.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("uploaded file still exists after delete: %v", err)
	}
}
