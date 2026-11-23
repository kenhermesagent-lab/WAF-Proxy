//go:build !linux

package ha

import "os/exec"

// prepareFenceCommand is a no-op where process groups are not set this way.
func prepareFenceCommand(*exec.Cmd) {}
