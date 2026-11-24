package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func udpAddr(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} }

// newTestPlane builds a data plane whose only game card is one UDP forwarder on
// whatever port points at, upstream to a port nothing listens on (a test never
// sends a datagram).
func newTestPlane(t *testing.T, port *int) *dataPlane {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	px, err := proxy.New(proxy.Deps{Log: log, Metrics: metrics.New("", "")})
	if err != nil {
		t.Fatal(err)
	}
	streams := streaming.New(log)
	t.Cleanup(streams.Close)
	load := func() (map[string]streaming.Config, error) {
		return map[string]streaming.Config{"plex": {Enabled: true, Protocol: "udp",
			ListenIP: "127.0.0.1", Port: *port, Upstream: "127.0.0.1:27015"}}, nil
	}
	return newDataPlane(context.Background(), px, streams, load, "127.0.0.1:0", "", "", log)
}

// free reports whether a UDP socket can still bind the port.
func free(t *testing.T, port int) bool {
	t.Helper()
	pc, err := net.ListenUDP("udp", udpAddr(port))
	if err != nil {
		return false
	}
	_ = pc.Close()
	return true
}

// A standby holds no game port, a promotion binds it, a demotion releases it at
// once, and the next promotion binds whatever the store says then.
func TestDataPlaneServeBindsAndDrainReleasesTheGamePort(t *testing.T) {
	port := freeUDPPort(t)
	current := port
	plane := newTestPlane(t, &current)
	defer plane.Close()

	if !free(t, port) {
		t.Fatal("a plane that has not been promoted held the game port")
	}
	if err := plane.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if free(t, port) {
		t.Fatal("the promoted node did not hold the game port")
	}

	plane.Drain(context.Background())
	if !free(t, port) {
		t.Fatal("drain did not release the game port")
	}

	// The card moved while this node was demoted, so the next promotion must
	// bind the new port and leave the old one free.
	moved := freeUDPPort(t)
	current = moved
	if err := plane.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !free(t, port) {
		t.Fatal("the promotion kept the port the card no longer names")
	}
	if free(t, moved) {
		t.Fatal("the promotion did not bind the port the card now names")
	}
}
