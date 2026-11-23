package openapi

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestCommittedDocumentMatchesRoutes fails when a route is added or changed
// without regenerating docs/openapi.yaml.
func TestCommittedDocumentMatchesRoutes(t *testing.T) {
	src, err := os.ReadFile("../../internal/api/server.go")
	if err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(src, strings.TrimSpace(string(version)))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/openapi.yaml is stale: run go generate ./internal/api")
	}
}
