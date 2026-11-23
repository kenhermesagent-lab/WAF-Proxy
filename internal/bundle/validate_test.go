package bundle

import (
	"strings"
	"testing"
)

func TestManifestRejectsNamesThatShareADirectory(t *testing.T) {
	sha := strings.Repeat("a", 64)
	cases := map[string]string{
		"escapes the data dir":    "../../etc",
		"collides after cleaning": "a/b",
		"empty version":           "",
	}
	for name, value := range cases {
		ref := Ref{Name: "pack", Version: "1", Rules: 1, Size: 10, SHA256: sha, Path: "packs/pack.json"}
		if strings.Contains(name, "version") {
			ref.Version = value
		} else {
			ref.Name = value
		}
		if err := validateManifest(Manifest{Sequence: 1, Bundles: []Ref{ref}}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	ok := Ref{Name: "cve-2026-11", Version: "2026.11.3", Rules: 1, Size: 10, SHA256: sha, Path: "packs/pack.json"}
	if err := validateManifest(Manifest{Sequence: 1, Bundles: []Ref{ok}}); err != nil {
		t.Fatalf("a safe name was refused: %v", err)
	}
}
