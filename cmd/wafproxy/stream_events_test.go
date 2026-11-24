package main

import (
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

type recordingStore struct {
	mu      sync.Mutex
	batches [][]model.Event
}

func (s *recordingStore) InsertEvents(events []model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, append([]model.Event(nil), events...))
	return nil
}

func (s *recordingStore) counts() (batches, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.batches {
		rows += len(b)
	}
	return len(s.batches), rows
}

func TestStreamEventsBatchesFlushes(t *testing.T) {
	st := &recordingStore{}
	w := newStreamEvents(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 3; i++ {
		w.record(model.Event{Host: "plex", Method: "UDP", Path: ":32400"})
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, rows := st.counts(); rows == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, rows := st.counts()
	if rows != 3 {
		t.Fatalf("rows = %d, want 3", rows)
	}
	// Three rows inside one flush window are one transaction, not three.
	if batches != 1 {
		t.Fatalf("batches = %d, want 1", batches)
	}

	// A shutdown flushes what is still queued.
	w.record(model.Event{Host: "plex", Method: "UDP", Path: ":32400"})
	w.stop()
	if _, rows := st.counts(); rows != 4 {
		t.Fatalf("rows after stop = %d, want 4", rows)
	}
}

func TestStreamEventsDropsWhenFull(t *testing.T) {
	// No reader is started, so the buffer is the only space there is.
	w := &streamEvents{ch: make(chan model.Event, 2), done: make(chan struct{})}
	for i := 0; i < 3; i++ {
		w.record(model.Event{Host: "plex"})
	}
	if got := w.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestStreamEventRowCarriesUDPAndThePort(t *testing.T) {
	row := streamEventRow(streaming.Event{Service: "plex", Port: 2457, Method: "UDP",
		Kind: "stream-cap", Detail: "more than 8 sessions from one address"})
	if row.Method != "UDP" || row.Path != ":2457" {
		t.Fatalf("method/path = %q/%q, want UDP/:2457", row.Method, row.Path)
	}
	if row.Host != "plex" || row.Stage != "stream" || row.Status != http.StatusForbidden || row.RuleID != "stream-cap" {
		t.Fatalf("row = %+v", row)
	}
	if row.RuleMsg != "more than 8 sessions from one address" {
		t.Fatalf("detail = %q", row.RuleMsg)
	}
}
