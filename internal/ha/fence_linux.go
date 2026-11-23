//go:build linux

package ha

import (
	"os/exec"
	"syscall"
)

// prepareFenceCommand runs the shell and everything it starts in one process
// group, so a timeout kills the script's children too. Killing only the shell
// leaves a sleep or an IPMI client alive and Wait blocks on its output pipes.
func prepareFenceCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
