package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

// updateScripts are the fixed helper scripts copied into the install's lib
// directory. Their installed names differ from the checkout's file names.
var updateScripts = []struct{ checkout, installed string }{
	{"wafproxy-self-update.sh", "self-update"},
	{"wafproxy-self-update-check.sh", "self-update-check"},
}

// configureApp records the checkout the root helper should rebuild. install.sh
// normally writes this file; the Updates page offers the same step when the
// checkout lives in another directory.
func configureApp(dir string) updates.HelperResponse {
	return configureAppAt(dir, updates.SelfUpdateConfFile(), filepath.Dir(updates.AppSelfUpdateScript))
}

func configureAppAt(dir, confPath, scriptDir string) updates.HelperResponse {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return updates.HelperResponse{Error: "a repository directory is required"}
	}
	if !filepath.IsAbs(dir) {
		return updates.HelperResponse{Error: "use the absolute path of the checkout, for example /root/WAF-Proxy-Docker"}
	}
	dir = filepath.Clean(dir)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return updates.HelperResponse{Error: dir + " is not a directory on this host"}
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return updates.HelperResponse{Error: dir + " is not a git checkout (no .git)"}
	}
	for _, script := range updateScripts {
		src := filepath.Join(dir, "deploy", script.checkout)
		if st, err := os.Stat(src); err != nil || st.IsDir() {
			return updates.HelperResponse{Error: dir + " is not a WAF-Proxy checkout: deploy/" + script.checkout + " is missing"}
		}
	}
	if remote, err := gitIn(dir, "config", "--get", "remote.origin.url"); err != nil || remote == "" {
		return updates.HelperResponse{Error: dir + " has no git origin remote, so the helper cannot pull updates"}
	}
	branch, err := gitIn(dir, "symbolic-ref", "--short", "HEAD")
	if err != nil || branch == "" {
		branch = "main"
	}
	owner := ""
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil {
			owner = u.Username
		}
	}
	mode := "native"
	if values, err := updates.ReadSelfUpdateConf(confPath); err == nil && values["WAFPROXY_UPDATE_MODE"] == "docker" {
		mode = "docker"
	}
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return updates.HelperResponse{Error: "create helper script directory: " + err.Error()}
	}
	for _, script := range updateScripts {
		data, err := os.ReadFile(filepath.Join(dir, "deploy", script.checkout))
		if err != nil {
			return updates.HelperResponse{Error: "read deploy/" + script.checkout + ": " + err.Error()}
		}
		dest := filepath.Join(scriptDir, script.installed)
		if err := os.WriteFile(dest, data, 0o755); err != nil {
			return updates.HelperResponse{Error: "install " + dest + ": " + err.Error()}
		}
		if err := os.Chmod(dest, 0o755); err != nil {
			return updates.HelperResponse{Error: "chmod " + dest + ": " + err.Error()}
		}
	}
	err = updates.WriteSelfUpdateConf(confPath, map[string]string{
		"WAFPROXY_UPDATE_SOURCE_DIR": dir,
		"WAFPROXY_UPDATE_USER":       owner,
		"WAFPROXY_UPDATE_BRANCH":     branch,
		"WAFPROXY_UPDATE_MODE":       mode,
	})
	if err != nil {
		return updates.HelperResponse{Error: "write " + confPath + ": " + err.Error()}
	}
	return updates.HelperResponse{
		OK:     true,
		Output: fmt.Sprintf("recorded %s (%s, branch %s) as the update checkout", dir, ownerOrRoot(owner), branch),
	}
}

func ownerOrRoot(owner string) string {
	if owner == "" {
		return "root"
	}
	return owner
}

// gitIn runs git against dir without a shell. safe.directory lets root inspect
// a checkout owned by the operator who runs the console.
func gitIn(dir string, args ...string) (string, error) {
	args = append([]string{"-c", "safe.directory=" + dir, "-C", dir}, args...)
	out, err := exec.Command("git", args...).Output()
	return strings.TrimSpace(string(out)), err
}
