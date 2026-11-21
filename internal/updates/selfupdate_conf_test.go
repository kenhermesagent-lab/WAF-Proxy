package updates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelfUpdateConfRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "self-update.conf")
	want := map[string]string{
		"WAFPROXY_UPDATE_SOURCE_DIR": "/opt/WAF Proxy/checkout",
		"WAFPROXY_UPDATE_USER":       "ops",
		"WAFPROXY_UPDATE_BRANCH":     "main",
		"WAFPROXY_UPDATE_MODE":       "native",
	}
	if err := WriteSelfUpdateConf(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("conf mode = %v, want 0644", info.Mode().Perm())
	}
	got, err := ReadSelfUpdateConf(path)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
}

func TestReadSelfUpdateConfMissing(t *testing.T) {
	if _, err := ReadSelfUpdateConf(filepath.Join(t.TempDir(), "absent.conf")); err == nil {
		t.Fatal("expected an error for a missing conf file")
	}
}
