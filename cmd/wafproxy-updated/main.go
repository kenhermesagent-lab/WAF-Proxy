// Command wafproxy-updated is the narrowly scoped root helper for the native
// Updates page. It listens only on a Unix socket, accepts only the compiled
// package allowlist, and runs apt without a shell.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

func main() {
	socket := flag.String("socket", updates.DefaultHelperSocket, "Unix socket path")
	flag.Parse()
	if err := run(*socket); err != nil {
		log.Fatal(err)
	}
}

func run(socket string) error {
	if err := os.MkdirAll(updates.SocketDir(socket), 0o755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	group, err := user.LookupGroup("wafproxy")
	if err != nil {
		return fmt.Errorf("lookup wafproxy group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("parse wafproxy group id: %w", err)
	}
	uid := -1
	if u, err := user.Lookup("wafproxy"); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socket, err)
	}
	defer ln.Close()
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	if err := os.Chown(socket, 0, gid); err != nil {
		return fmt.Errorf("chown helper socket: %w", err)
	}
	if err := os.Chmod(socket, 0o660); err != nil {
		return fmt.Errorf("chmod helper socket: %w", err)
	}
	log.Printf("update helper listening on %s", socket)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("accept: %v", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serve(conn, gid, uid)
		}()
	}
	wg.Wait()
	return nil
}

var aptMu sync.Mutex

func serve(conn net.Conn, gid, uid int) {
	defer conn.Close()
	if !peerAllowed(conn, gid, uid) {
		writeResponse(conn, updates.HelperResponse{Error: "caller is not the wafproxy service"})
		return
	}
	_ = conn.SetDeadline(time.Now().Add(6 * time.Minute))
	var req updates.HelperRequest
	dec := json.NewDecoder(io.LimitReader(conn, 4096))
	if err := dec.Decode(&req); err != nil {
		writeResponse(conn, updates.HelperResponse{Error: "invalid request"})
		return
	}
	switch req.Action {
	case updates.HelperActionPing:
		writeResponse(conn, updates.HelperResponse{OK: true})
	case updates.HelperActionCheck:
		aptMu.Lock()
		resp := runApt(2*time.Minute, "update", "-qq")
		aptMu.Unlock()
		writeResponse(conn, resp)
	case updates.HelperActionApply:
		if !allowedPackage(req.Package) {
			writeResponse(conn, updates.HelperResponse{Error: "package is not managed by WAF-Proxy"})
			return
		}
		aptMu.Lock()
		resp := runApt(5*time.Minute,
			"install", "--only-upgrade", "-y", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confold", "--", req.Package)
		aptMu.Unlock()
		if resp.OK {
			resp.Output = resp.Output + "\nupdated " + req.Package
		}
		writeResponse(conn, resp)
	default:
		writeResponse(conn, updates.HelperResponse{Error: "unsupported action"})
	}
}

func writeResponse(conn net.Conn, resp updates.HelperResponse) {
	_ = json.NewEncoder(conn).Encode(resp)
}

func peerAllowed(conn net.Conn, gid, uid int) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	if err := raw.Control(func(fd uintptr) {
		cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return false
	}
	if cred == nil {
		return false
	}
	return cred.Uid == 0 || int(cred.Gid) == gid || (uid >= 0 && int(cred.Uid) == uid)
}

func allowedPackage(name string) bool {
	for _, allowed := range updates.CatalogNames() {
		if name == allowed {
			return true
		}
	}
	return false
}

func runApt(timeout time.Duration, args ...string) updates.HelperResponse {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return updates.HelperResponse{Error: "apt-get is not installed"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C",
		"LANG=C",
		"HOME=/root",
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if len(output) > 16<<10 {
		output = output[:16<<10] + "\n… output truncated"
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return updates.HelperResponse{Output: output, Error: "apt-get timed out"}
		}
		return updates.HelperResponse{Output: output, Error: err.Error()}
	}
	return updates.HelperResponse{OK: true, Output: output}
}
