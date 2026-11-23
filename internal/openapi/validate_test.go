package openapi

import (
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// The byte comparison only proves the file is current; this checks that the
// current file is a usable OpenAPI document.
func TestCommittedDocumentValidates(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var paths []string
	for path := range doc.Paths.Map() {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	seen := map[string]string{}
	for _, path := range paths {
		item := doc.Paths.Find(path)
		for method, op := range item.Operations() {
			if op.OperationID == "" {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			if prev, ok := seen[op.OperationID]; ok {
				t.Errorf("duplicate operationId %q on %s and %s", op.OperationID, prev, key)
			}
			seen[op.OperationID] = key
		}
	}
}
