package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// A refused game client retries in a tight loop, so the relay's rows are batched
// the way the HTTP pipeline batches its audit events: one insert per 250 ms or
// 256 rows, and a full buffer drops rather than stalling a relay.
const (
	streamEventBuffer = 1024
	streamEventBatch  = 256
	streamEventFlush  = 250 * time.Millisecond
)

// eventSink is the one store method the writer needs, so a test can spy on it.
type eventSink interface {
	InsertEvents([]model.Event) error
}

// streamEvents is the queue between the relay and the events table.
type streamEvents struct {
	st      eventSink
	log     *slog.Logger
	ch      chan model.Event
	done    chan struct{}
	wg      sync.WaitGroup
	dropped atomic.Int64
}

func newStreamEvents(st eventSink, log *slog.Logger) *streamEvents {
	w := &streamEvents{
		st:   st,
		log:  log,
		ch:   make(chan model.Event, streamEventBuffer),
		done: make(chan struct{}),
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// streamEventRow turns a relay event into the audit row Logs and the attack
// globe read: the service is the host, UDP or TCP rides the method column and
// the listen port is the path.
func streamEventRow(ev streaming.Event) model.Event {
	kind := ev.Kind
	if kind == "" {
		kind = "stream-ban"
	}
	method := ev.Method
	if method == "" {
		method = "TCP"
	}
	return model.Event{
		TS: time.Now(), Host: ev.Service, SrcIP: ev.Addr.String(),
		Method: method, Path: fmt.Sprintf(":%d", ev.Port),
		Status: http.StatusForbidden, Stage: "stream", Action: "block",
		RuleID: kind, RuleMsg: ev.Detail,
	}
}

// record queues a row and returns immediately; the relay must never wait on the
// database.
func (w *streamEvents) record(e model.Event) {
	select {
	case w.ch <- e:
	default:
		w.dropped.Add(1)
	}
}

func (w *streamEvents) run() {
	defer w.wg.Done()
	batch := make([]model.Event, 0, streamEventBatch)
	tick := time.NewTicker(streamEventFlush)
	defer tick.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := append([]model.Event(nil), batch...)
		batch = batch[:0]
		if err := w.st.InsertEvents(out); err != nil {
			w.log.Warn("streaming event insert failed", "rows", len(out), "err", err)
		}
	}
	for {
		select {
		case <-w.done:
			// Drain what the relay queued before stopping, then flush and go.
			for {
				select {
				case e := <-w.ch:
					batch = append(batch, e)
					if len(batch) >= streamEventBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case e := <-w.ch:
			batch = append(batch, e)
			if len(batch) >= streamEventBatch {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// stop flushes the queue and waits for the writer, so a shutdown does not lose
// the last row a demotion produced.
func (w *streamEvents) stop() {
	close(w.done)
	w.wg.Wait()
}

// Dropped returns how many rows were refused because the buffer was full.
func (w *streamEvents) Dropped() int64 { return w.dropped.Load() }
