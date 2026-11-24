package updates

import (
	"os"
	"path/filepath"
	"testing"
)

// The console draws its bar from this one line, so a missing file, a malformed
// one and a finished run must all be unambiguous.
func TestAppProgressFile(t *testing.T) {
	t.Setenv("WAFPROXY_UPDATE_PROGRESS", filepath.Join(t.TempDir(), "progress"))

	if percent, stage := ReadAppProgress(); percent != 0 || stage != "" {
		t.Fatalf("missing file = %d %q, want 0 \"\"", percent, stage)
	}

	if err := os.WriteFile(ProgressFile(), []byte("45|building the binaries\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if percent, stage := ReadAppProgress(); percent != 45 || stage != "building the binaries" {
		t.Fatalf("read = %d %q", percent, stage)
	}

	if err := os.WriteFile(ProgressFile(), []byte("101|past the end"), 0o644); err != nil {
		t.Fatal(err)
	}
	if percent, stage := ReadAppProgress(); percent != 0 || stage != "" {
		t.Fatalf("out-of-range read = %d %q, want 0 \"\"", percent, stage)
	}

	ClearAppProgress()
	if percent, stage := ReadAppProgress(); percent != 0 || stage != "" {
		t.Fatalf("after clear = %d %q, want 0 \"\"", percent, stage)
	}
}
