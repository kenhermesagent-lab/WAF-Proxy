// Command openapi renders docs/openapi.yaml from the routes registered in
// internal/api/server.go. Run `go generate ./internal/api` after adding a route;
// `-check` fails when the committed file is stale.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/openapi"
)

func main() {
	src := flag.String("src", "internal/api/server.go", "route source")
	out := flag.String("out", "docs/openapi.yaml", "output file")
	versionFile := flag.String("version-file", "VERSION", "file holding the release version")
	check := flag.Bool("check", false, "verify the output is current instead of writing")
	flag.Parse()

	source, err := os.ReadFile(*src)
	if err != nil {
		fail(err)
	}
	raw, err := os.ReadFile(*versionFile)
	if err != nil {
		fail(err)
	}
	doc, err := openapi.Generate(source, strings.TrimSpace(string(raw)))
	if err != nil {
		fail(err)
	}
	if *check {
		current, err := os.ReadFile(*out)
		if err != nil || !bytes.Equal(current, doc) {
			fail(fmt.Errorf("%s is stale: run go generate ./internal/api", *out))
		}
		return
	}
	if err := os.WriteFile(*out, doc, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s\n", *out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "openapi:", err)
	os.Exit(1)
}
