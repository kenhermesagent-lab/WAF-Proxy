package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The updater sources a library from its own directory. Every installer has to
// copy that library next to the scripts, or the update fails on the host with
// "lib missing" — which is exactly what shipped for Docker hosts until the
// library was added here. This test keeps the three installers honest instead
// of relying on someone remembering the new file.
func TestInstallersCopyEverySourcedLibrary(t *testing.T) {
	root := filepath.Join("..", "..")
	self, err := os.ReadFile(filepath.Join(root, "deploy", "wafproxy-self-update.sh"))
	if err != nil {
		t.Fatal(err)
	}
	sourced := regexp.MustCompile(`source "\$lib_dir/([^"]+)"`).FindAllStringSubmatch(string(self), -1)
	if len(sourced) == 0 {
		t.Fatal("wafproxy-self-update.sh sources no library; has the guard changed?")
	}
	for _, installer := range []string{"install.sh", "install-docker-updater.sh", "wafproxy-self-update.sh"} {
		body, err := os.ReadFile(filepath.Join(root, "deploy", installer))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range sourced {
			if !strings.Contains(string(body), m[1]) {
				t.Errorf("deploy/%s never installs %q, which self-update sources at runtime", installer, m[1])
			}
		}
	}
}
