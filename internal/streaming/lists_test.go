package streaming

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// A forwarder enforces a named blocklist exactly as a proxied site does, and the
// event says which list refused the source so the operator can edit it.
func TestForwarderBlocklistRefusesAndNamesList(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())
	m.SetLists([]List{{ID: 1, Name: "bad hosts", Block: true, Prefixes: []string{"127.0.0.1/32"}}})

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), ListIDs: []int64{1}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a source on the blocklist was not refused")
	}
	waitFor(t, "one refusal event", func() bool { return len(log.all()) == 1 })

	events := log.all()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Kind != "stream-list" || !strings.Contains(events[0].Detail, "bad hosts") {
		t.Fatalf("event = %+v, want a stream-list refusal naming bad hosts", events[0])
	}
}

// Selecting a whitelist makes the port exclusive, and editing the list takes
// effect without rebinding the listener the way a human would expect.
func TestForwarderWhitelistIsExclusiveAndNamed(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())
	m.SetLists([]List{{ID: 2, Name: "office", Prefixes: []string{"198.51.100.0/24"}}})

	port := freePort(t)
	if err := m.Apply("jellyfin", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), ListIDs: []int64{2}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	boundBefore := m.Statuses()[1].ListenAddr

	conn := dialRelay(t, port)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a source outside the whitelist was not refused")
	}
	conn.Close()
	waitFor(t, "one refusal event", func() bool { return len(log.all()) == 1 })
	events := log.all()
	if len(events) != 1 || events[0].Kind != "stream-list" || !strings.Contains(events[0].Detail, "office") {
		t.Fatalf("events = %+v, want a refusal naming the office list", events)
	}

	// The office list now includes loopback: the same listener must accept it.
	m.SetLists([]List{{ID: 2, Name: "office", Prefixes: []string{"198.51.100.0/24", "127.0.0.1/32"}}})
	m.RefreshSources()
	if got := m.Statuses()[1].ListenAddr; got != boundBefore {
		t.Fatalf("listener moved from %q to %q on a list edit", boundBefore, got)
	}
	conn = dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil || string(buf) != "hello" {
		t.Fatalf("listed source was refused: %v %q", err, buf)
	}
}

// A blocklist attached to the same port beats a whitelist, matching the HTTP
// pipeline: an explicit block is the operator's strongest word.
func TestForwarderBlocklistBeatsWhitelist(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	log := &eventLog{}
	m.SetEventSink(log.sink())
	m.SetLists([]List{
		{ID: 1, Name: "bad hosts", Block: true, Prefixes: []string{"127.0.0.1/32"}},
		{ID: 2, Name: "office", Prefixes: []string{"127.0.0.1/32"}},
	})

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), ListIDs: []int64{2, 1}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the blocklist did not override the whitelist")
	}
	waitFor(t, "one refusal event", func() bool { return len(log.all()) == 1 })
	events := log.all()
	if len(events) != 1 || !strings.Contains(events[0].Detail, "bad hosts") {
		t.Fatalf("events = %+v, want the blocklist named", events)
	}
}

// Countries need the GeoIP lookup; without one the rule cannot match, which is
// the same failure mode the HTTP pipeline has.
func TestForwarderCountryListUsesGeoLookup(t *testing.T) {
	upstream := echoServer(t)
	defer upstream.Close()
	m := New(discardLogger())
	defer m.Close()
	m.SetLists([]List{{ID: 3, Name: "no travel", Block: true, Countries: []string{"RU"}}})
	m.SetCountryLookup(func(netip.Addr) string { return "RU" })

	port := freePort(t)
	if err := m.Apply("plex", Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: upstream.Addr().String(), ListIDs: []int64{3}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conn := dialRelay(t, port)
	defer conn.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a source in a blocked country was not refused")
	}
	waitFor(t, "a blocked counter", func() bool { return m.Statuses()[0].Blocked == 1 })
}

// The saved form keeps the list ids; a restart therefore reads the same policy.
func TestStreamingListIDsRoundTrip(t *testing.T) {
	plex, _ := Lookup("plex")
	kv := map[string]string{
		"stream_plex_enabled":   "1",
		"stream_plex_upstream":  "127.0.0.1:32400",
		"stream_plex_allow":     "203.0.113.7",
		"stream_plex_lists":     "4, 9,4",
		"stream_plex_max_conns": "64",
	}
	cfg := ConfigFromSettings(plex, kv)
	if fmt.Sprint(cfg.ListIDs) != "[4 9 4]" {
		t.Fatalf("list ids = %v, want the stored order", cfg.ListIDs)
	}
	norm, err := cfg.Normalize(plex)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(norm.ListIDs) != "[4 9]" {
		t.Fatalf("normalized list ids = %v, want deduplicated", norm.ListIDs)
	}
	if fmt.Sprint(norm.Allow) != "[203.0.113.7/32]" {
		t.Fatalf("allow = %v", norm.Allow)
	}
	// A missing key (an upgraded install) leaves the port open, as before.
	if got := ConfigFromSettings(plex, map[string]string{"stream_plex_upstream": "127.0.0.1:32400"}).ListIDs; len(got) != 0 {
		t.Fatalf("list ids = %v, want none", got)
	}
}
