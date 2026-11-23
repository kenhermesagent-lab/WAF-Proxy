package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ha"
)

// haMoveCLI is the operator's half of a planned move. It talks to the local
// control socket, so it works from a shell on the node and never exposes a
// failover endpoint to the network.
func haMoveCLI(command string, args []string) error {
	fs := flag.NewFlagSet("ha "+command, flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "run the preflight checks and change nothing")
	force := fs.Bool("force", false, "continue past a failed check; the tail of the stream may be lost")
	asJSON := fs.Bool("json", false, "print the reply as JSON")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for the move")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	reply, err := ha.Control(ctx, ha.ControlSocketPath(dataDir()), ha.ControlRequest{
		Command: command, DryRun: *dry, Force: *force,
		TimeoutSeconds: int(timeout.Seconds()),
	})
	if err != nil {
		return err
	}
	if *asJSON {
		raw, merr := json.MarshalIndent(reply, "", "  ")
		if merr != nil {
			return merr
		}
		fmt.Println(string(raw))
		if !reply.OK {
			return errors.New(reply.Error)
		}
		return nil
	}
	printMove(reply.Result)
	if !reply.OK {
		return errors.New(reply.Error)
	}
	return nil
}

// printMove renders checks for a dry run and steps for a real move. A refusal
// names the fix, because the operator's next action is the point of the call.
func printMove(res *ha.Result) {
	if res == nil {
		return
	}
	if res.DryRun {
		for _, c := range res.Checks {
			status := "ok"
			if !c.OK {
				status = "FAIL"
			}
			fmt.Printf("%-4s %-18s %s\n", status, c.Name, c.Detail)
			if !c.OK && c.Fix != "" {
				fmt.Printf("     fix: %s\n", c.Fix)
			}
		}
		return
	}
	for _, s := range res.Steps {
		status := "ok"
		if !s.OK {
			status = "FAIL"
		}
		fmt.Printf("%-4s %-16s %4dms %s\n", status, s.Name, s.Millis, s.Detail)
	}
	if len(res.Overridden) > 0 {
		fmt.Printf("forced past: %s\n", strings.Join(res.Overridden, ", "))
	}
	fmt.Printf("epoch %d, %s\n", res.Epoch, (time.Duration(res.DurationMS) * time.Millisecond).Round(time.Millisecond))
}

func haAbortCLI(args []string) error {
	fs := flag.NewFlagSet("ha abort", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reply, err := ha.Control(ctx, ha.ControlSocketPath(dataDir()), ha.ControlRequest{Command: "abort"})
	if err != nil {
		return err
	}
	if !reply.OK {
		return errors.New(reply.Error)
	}
	fmt.Println("cancelled the move before it reached the data plane")
	return nil
}

// haNotifyCLI is what keepalived calls. A refusal exits non-zero, so the VRRP
// instance shows FAULT instead of a node that believes it is serving.
func haNotifyCLI(args []string) error {
	fs := flag.NewFlagSet("ha notify", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: wafproxy ha notify MASTER|BACKUP|FAULT")
	}
	role := strings.ToUpper(strings.TrimSpace(fs.Arg(0)))
	// A takeover gets the full drain budget; stepping down is quicker.
	budget := 4 * time.Minute
	if role != "MASTER" {
		budget = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget+30*time.Second)
	defer cancel()
	reply, err := ha.Control(ctx, ha.ControlSocketPath(dataDir()), ha.ControlRequest{
		Command: "notify", Role: role, TimeoutSeconds: int(budget.Seconds()),
	})
	if err != nil {
		return err
	}
	if !reply.OK {
		fmt.Fprintln(os.Stderr, "ha notify:", reply.Error)
		return errors.New(reply.Error)
	}
	return nil
}
