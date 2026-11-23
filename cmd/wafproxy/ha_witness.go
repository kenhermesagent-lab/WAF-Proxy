package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
)

// haWitnessCLI runs the witness from the same binary, so a pair needs one
// install and one service unit for it.
func haWitnessCLI(args []string) error {
	fs := flag.NewFlagSet("ha witness", flag.ContinueOnError)
	listen := fs.String("listen", ":9444", "address to serve the witness on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token := strings.TrimSpace(os.Getenv("WAFPROXY_HA_WITNESS_TOKEN"))
	if len(token) < 32 {
		return errors.New("WAFPROXY_HA_WITNESS_TOKEN must be set and at least 32 characters")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("witness listening on %s\n", *listen)
	if err := ha.NewWitness(token).Serve(ctx, *listen); err != nil {
		return err
	}
	return nil
}

// haPingCLI asks the peer for its own view of itself.
func haPingCLI(args []string) error {
	fs := flag.NewFlagSet("ha ping", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ping, err := ha.PingPeer(ctx, dataDir())
	if err != nil {
		return err
	}
	fmt.Printf("peer=%s role=%s state=%s epoch=%d at %s\n",
		ping.Node, ping.Role, ping.State, ping.Epoch, ping.Time)
	return nil
}
