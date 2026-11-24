// Command wafproxy-updated is the narrowly scoped root helper for the Updates
// page. It listens only on a Unix socket, runs apt without a shell for the
// compiled package allowlist, and runs the two fixed repository scripts.
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
	gid := 0
	if raw := strings.TrimSpace(os.Getenv("WAFPROXY_UPDATE_SOCKET_GID")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return fmt.Errorf("invalid WAFPROXY_UPDATE_SOCKET_GID %q", raw)
		}
		gid = parsed
	} else {
		group, err := user.LookupGroup("wafproxy")
		if err != nil {
			return fmt.Errorf("lookup wafproxy group: %w", err)
		}
		gid, err = strconv.Atoi(group.Gid)
		if err != nil {
			return fmt.Errorf("parse wafproxy group id: %w", err)
		}
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
	if req.Action == updates.HelperActionAppUpdate {
		_ = conn.SetDeadline(time.Now().Add(20 * time.Minute))
	}
	if req.Action == updates.HelperActionAppCheck || req.Action == updates.HelperActionAppConfigure {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	}
	if req.Action == updates.HelperActionCrowdSecInstall {
		_ = conn.SetDeadline(time.Now().Add(16 * time.Minute))
	}
	if req.Action == updates.HelperActionCloudflaredInstall {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	if req.Action == updates.HelperActionCrowdSecStatus || req.Action == updates.HelperActionCrowdSecDecisions {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
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
	case updates.HelperActionAppStatus:
		st := updates.ReadAppStatus()
		writeResponse(conn, updates.HelperResponse{
			OK:             true,
			SourceDir:      st.SourceDir,
			Mode:           st.Mode,
			CheckoutExists: st.CheckoutExists,
			MissingScripts: st.MissingScripts,
		})
	case updates.HelperActionAppCheck:
		resp := runFixedScript(updates.AppCheckScript, 90*time.Second)
		writeResponse(conn, resp)
	case updates.HelperActionAppUpdate:
		// A finished run leaves its last stage behind; drop it so the first
		// poll of this run cannot report the previous one.
		updates.ClearAppProgress()
		// The script writes the stages this helper then reports, so it is told
		// the exact path instead of repeating the default.
		stageFile := map[string]string{"WAFPROXY_UPDATE_PROGRESS": updates.ProgressFile()}
		aptMu.Lock()
		resp := runFixedScriptEnv(updates.AppSelfUpdateScript, 20*time.Minute, stageFile)
		aptMu.Unlock()
		writeResponse(conn, resp)
	case updates.HelperActionAppProgress:
		percent, stage := updates.ReadAppProgress()
		writeResponse(conn, updates.HelperResponse{OK: true, Percent: percent, Stage: stage})
	case updates.HelperActionAppConfigure:
		writeResponse(conn, configureApp(req.Path))
	case updates.HelperActionCrowdSecInstall:
		env := map[string]string{}
		if req.Key != "" {
			if !updates.ValidConsoleKey(req.Key) {
				writeResponse(conn, updates.HelperResponse{Error: "invalid CrowdSec console enrollment key"})
				return
			}
			env["WAFPROXY_CONSOLE_KEY"] = req.Key
		}
		aptMu.Lock()
		resp := runFixedScriptEnv(updates.CrowdSecInstallScript, 15*time.Minute, env)
		aptMu.Unlock()
		writeResponse(conn, resp)
	case updates.HelperActionCloudflaredInstall:
		aptMu.Lock()
		resp := runFixedScript(updates.CloudflaredInstallScript, 9*time.Minute)
		aptMu.Unlock()
		writeResponse(conn, resp)
	case updates.HelperActionCrowdSecRestart:
		resp := runCommand(90*time.Second, "systemctl", "restart", "crowdsec")
		if resp.OK {
			resp.Output = "crowdsec restarted"
		}
		writeResponse(conn, resp)
	case updates.HelperActionCrowdSecEnroll:
		if !updates.ValidConsoleKey(req.Key) {
			writeResponse(conn, updates.HelperResponse{Error: "invalid CrowdSec console enrollment key"})
			return
		}
		cscli, err := exec.LookPath("cscli")
		if err != nil {
			writeResponse(conn, updates.HelperResponse{Error: "cscli is not installed on this host"})
			return
		}
		writeResponse(conn, runCommand(2*time.Minute, cscli, "console", "enroll", req.Key))
	case updates.HelperActionCrowdSecStatus:
		cscli, err := exec.LookPath("cscli")
		if err != nil {
			writeResponse(conn, updates.HelperResponse{Error: "cscli is not installed on this host"})
			return
		}
		writeResponse(conn, runCommand(20*time.Second, cscli, "console", "status"))
	case updates.HelperActionCrowdSecDecisions:
		cscli, err := exec.LookPath("cscli")
		if err != nil {
			writeResponse(conn, updates.HelperResponse{Error: "cscli is not installed on this host"})
			return
		}
		writeResponse(conn, runCommand(20*time.Second, cscli, "metrics", "show", "decisions"))
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

func runFixedScript(script string, timeout time.Duration) updates.HelperResponse {
	return runFixedScriptEnv(script, timeout, nil)
}

func runFixedScriptEnv(script string, timeout time.Duration, env map[string]string) updates.HelperResponse {
	info, err := os.Stat(script)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return updates.HelperResponse{Error: "update helper scripts are not configured; reinstall from the git checkout"}
	}
	return runCommandEnv(timeout, script, env, nil)
}

func runApt(timeout time.Duration, args ...string) updates.HelperResponse {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return updates.HelperResponse{Error: "apt-get is not installed"}
	}
	return runCommand(timeout, "apt-get", args...)
}

// runCommand runs one fixed program without a shell.
func runCommand(timeout time.Duration, name string, args ...string) updates.HelperResponse {
	return runCommandEnv(timeout, name, nil, args)
}

// runCommandEnv is runCommand with extra environment entries for the child, so a
// secret can reach the installer without appearing in the process list. Output
// keeps its tail: the installer prints its result lines last, and apt prints its
// error last.
func runCommandEnv(timeout time.Duration, name string, env map[string]string, args []string) updates.HelperResponse {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{
		"PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"HOME=/root",
		"LC_ALL=C",
		"LANG=C",
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if len(output) > 32<<10 {
		output = "… output truncated\n" + output[len(output)-(32<<10):]
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return updates.HelperResponse{Output: output, Error: name + " timed out"}
		}
		return updates.HelperResponse{Output: output, Error: err.Error()}
	}
	return updates.HelperResponse{OK: true, Output: output}
}
