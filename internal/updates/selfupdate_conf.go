package updates

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultSelfUpdateConf records the checkout the root helper rebuilds. It is
// written by deploy/install.sh at install time and by the helper itself when an
// operator points the Updates page at a checkout installed elsewhere.
const DefaultSelfUpdateConf = "/etc/wafproxy/self-update.conf"

// SelfUpdateConfFile returns the recorded-checkout file, overridable for tests.
func SelfUpdateConfFile() string {
	if v := osGetenv("WAFPROXY_SELF_UPDATE_CONF"); v != "" {
		return filepath.Clean(v)
	}
	return DefaultSelfUpdateConf
}

// ReadSelfUpdateConf parses the shell-style KEY="value" file. A missing file is
// an error so callers can tell "not recorded" from "recorded empty".
func ReadSelfUpdateConf(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		values[key] = value
	}
	return values, nil
}

// WriteSelfUpdateConf writes the same four keys install.sh records, atomically
// and readable by the console service.
func WriteSelfUpdateConf(path string, values map[string]string) error {
	order := []string{
		"WAFPROXY_UPDATE_SOURCE_DIR",
		"WAFPROXY_UPDATE_USER",
		"WAFPROXY_UPDATE_BRANCH",
		"WAFPROXY_UPDATE_MODE",
	}
	var body strings.Builder
	body.WriteString("# Written by WAF-Proxy: the fixed root helper rebuilds this checkout.\n")
	for _, key := range order {
		body.WriteString(key + "=" + strconv.Quote(values[key]) + "\n")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".self-update-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(body.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}
