package ha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ControlRequest is one command on the local control socket.
type ControlRequest struct {
	Command string `json:"command"`
	Force   bool   `json:"force,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
	// Role carries MASTER, BACKUP or FAULT for the keepalived notify command.
	Role string `json:"role,omitempty"`
	// TimeoutSeconds bounds a move; zero means the caller's own deadline.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// ControlReply is the answer to one command. Blocked names the preflight check
// that refused the move, so a notify script can exit non-zero with a reason.
type ControlReply struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Blocked *Check  `json:"blocked,omitempty"`
	Result  *Result `json:"result,omitempty"`
	Status  *Status `json:"status,omitempty"`
}

// ControlSocketPath is the local socket keepalived and the CLI talk to. It is
// inside the data directory by default and never on the network.
func ControlSocketPath(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("WAFPROXY_HA_CONTROL_SOCKET")); v != "" {
		return v
	}
	return filepath.Join(RoleDir(dataDir), "ha.sock")
}

// ServeControl starts the Unix socket. The file is 0600 inside a 0700 directory,
// so only root and the service account can send a move.
func ServeControl(ctx context.Context, path string, m *Manager, log *slog.Logger) (net.Listener, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ha: %s exists and is not a socket", path)
		}
		// A socket that answers belongs to a live process. Removing it would
		// steal every move from that process and leave its cleanup to unlink
		// this listener instead. Only a refused connection proves it is stale.
		conn, dialErr := net.DialTimeout("unix", path, 500*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ha: control socket %s is already in use", path)
		}
		// A refused connection is the only error that proves nobody is
		// listening. A permission or timeout error must not lead to deleting a
		// live socket this process cannot reach.
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("ha: control socket %s: %w", path, dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	bound, statErr := os.Lstat(path)
	go func() {
		<-ctx.Done()
		// Unlink before closing so another process may bind as soon as this
		// listener stops. Only remove the inode this listener created: a
		// replacement owner may already be listening at the same path.
		if statErr == nil {
			if cur, err := os.Lstat(path); err == nil && os.SameFile(bound, cur) {
				_ = os.Remove(path)
			}
		}
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleControl(conn, m, log)
		}
	}()
	return ln, nil
}

func handleControl(conn net.Conn, m *Manager, log *slog.Logger) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var req ControlRequest
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&req); err != nil {
		_ = writeReply(conn, ControlReply{OK: false, Error: "invalid request"})
		return
	}
	reply := dispatch(req, m, log)
	if err := writeReply(conn, reply); err != nil {
		log.Warn("ha control reply failed", "err", err)
	}
}

func dispatch(req ControlRequest, m *Manager, log *slog.Logger) ControlReply {
	switch strings.ToLower(strings.TrimSpace(req.Command)) {
	case "status":
		st := m.Status()
		return ControlReply{OK: true, Status: &st}
	case "failover":
		return moveReply(m, req, true)
	case "failback":
		return moveReply(m, req, false)
	case "abort":
		if err := m.Abort(); err != nil {
			return ControlReply{OK: false, Error: err.Error()}
		}
		return ControlReply{OK: true}
	case "notify":
		return notifyReply(req, m, log)
	default:
		return ControlReply{OK: false, Error: fmt.Sprintf("unknown command %q", req.Command)}
	}
}

func moveReply(m *Manager, req ControlRequest, failover bool) ControlReply {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	opts := MoveOptions{Force: req.Force, DryRun: req.DryRun}
	var res Result
	var err error
	if failover {
		res, err = m.Failover(ctx, opts)
	} else {
		res, err = m.Failback(ctx, opts)
	}
	reply := ControlReply{OK: err == nil, Result: &res}
	if err != nil {
		reply.Error = err.Error()
		var blocked *BlockedError
		if errors.As(err, &blocked) {
			check := blocked.Check
			reply.Blocked = &check
		}
	}
	return reply
}

// notifyReply maps keepalived's MASTER/BACKUP/FAULT onto a move. A refusal is
// an error, so the notify script exits non-zero and keepalived shows FAULT.
func notifyReply(req ControlRequest, m *Manager, log *slog.Logger) ControlReply {
	switch strings.ToUpper(strings.TrimSpace(req.Role)) {
	case "MASTER":
		req.Command = "failover"
		reply := moveReply(m, req, true)
		if reply.OK {
			log.Info("keepalived promoted this node")
		} else {
			log.Error("keepalived promotion refused", "err", reply.Error)
		}
		return reply
	case "BACKUP", "FAULT":
		if st := m.Status(); !st.Serving && !st.Running {
			return ControlReply{OK: true, Status: &st}
		}
		req.Command = "failback"
		reply := moveReply(m, req, false)
		if reply.OK {
			log.Info("keepalived stood this node down", "role", req.Role)
		} else {
			log.Error("keepalived step-down failed", "err", reply.Error)
		}
		return reply
	default:
		return ControlReply{OK: false, Error: fmt.Sprintf("unknown keepalived role %q (want MASTER, BACKUP or FAULT)", req.Role)}
	}
}

func writeReply(conn net.Conn, reply ControlReply) error {
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return json.NewEncoder(conn).Encode(reply)
}

// Control sends one command to a node's control socket.
func Control(ctx context.Context, path string, req ControlRequest) (ControlReply, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return ControlReply{}, fmt.Errorf("ha: control socket %s: %w", path, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return ControlReply{}, err
	}
	var reply ControlReply
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&reply); err != nil {
		return reply, err
	}
	return reply, nil
}
