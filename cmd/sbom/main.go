// Command sbom writes a CycloneDX 1.5 document for the modules in the build.
// Output is deterministic: no timestamp or serial number, so two builds of the
// same module graph produce the same file.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
)

type module struct {
	Path    string
	Version string
	Main    bool
	Replace *module
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    metadata    `json:"metadata"`
	Components  []component `json:"components"`
}

type metadata struct {
	Component component `json:"component"`
}

func main() {
	version := flag.String("version", "", "release version to record as the application component")
	flag.Parse()
	if *version == "" {
		fmt.Fprintln(os.Stderr, "sbom: -version is required")
		os.Exit(2)
	}

	raw, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: go list: %v\n", err)
		os.Exit(1)
	}
	comps, err := components(bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}

	doc := document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: metadata{Component: component{
			Type: "application", Name: "wafproxy", Version: *version,
		}},
		Components: comps,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
}

// components reads the stream of JSON objects that `go list -m -json all`
// prints. A replaced module is listed under the version that was actually
// built, and the main module is the metadata component rather than a library.
func components(r io.Reader) ([]component, error) {
	dec := json.NewDecoder(r)
	out := []component{}
	for {
		var m module
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if m.Main {
			continue
		}
		path, version := m.Path, m.Version
		if m.Replace != nil {
			path, version = m.Replace.Path, m.Replace.Version
		}
		if path == "" || version == "" {
			continue
		}
		out = append(out, component{
			Type: "library", Name: path, Version: version,
			PURL: "pkg:golang/" + path + "@" + version,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out, nil
}
