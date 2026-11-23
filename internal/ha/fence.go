package ha

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultFenceTimeout bounds the operator's fence command. A fence that hangs
// is a fence that failed: the move must not wait on it forever.
const DefaultFenceTimeout = 30 * time.Second

// Fencer proves the peer cannot write before an unattended promotion. Exit 0
// means the peer is down; anything else means do not promote.
type Fencer struct {
	// Command runs on the local node with {peer} substituted. It is the
	// operator's own script: an IPMI power-off, a hypervisor stop, a switch
	// port disable.
	Command string
	// Peer is the address substituted for {peer}, shell-quoted.
	Peer    string
	Timeout time.Duration
}

// Run executes the fence command.
func (f Fencer) Run(ctx context.Context) error {
	command := strings.TrimSpace(f.Command)
	if command == "" {
		return errors.New("ha: no fence command is configured")
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = DefaultFenceTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	line := strings.ReplaceAll(command, "{peer}", shellQuote(f.Peer))
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", line)
	prepareFenceCommand(cmd)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("ha: fence command timed out after %s", timeout)
	}
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = "no output"
		}
		if len(detail) > 300 {
			detail = detail[:300] + "…"
		}
		return fmt.Errorf("ha: fence command failed (%v): %s", err, detail)
	}
	return nil
}

// shellQuote makes the peer a single literal word, so a hostname from the pair
// record cannot turn into a second command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
