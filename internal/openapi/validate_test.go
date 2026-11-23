package openapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// The byte comparison only proves the file is current; this checks that the
// current file is a usable OpenAPI document.
func TestCommittedDocumentValidates(t *testing.T) {
	doc, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocument(doc); err != nil {
		t.Fatalf("docs/openapi.yaml: %v", err)
	}
}

// A guard is only worth having if it fails on the mistakes it exists to catch.
func TestValidationRejectsBrokenDocuments(t *testing.T) {
	cases := map[string]string{
		"missing ref": `openapi: 3.0.3
info: {title: test, version: "1"}
paths:
  /broken:
    get:
      operationId: getBroken
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: '#/components/schemas/Missing'}
`,
		"duplicate operationId": `openapi: 3.0.3
info: {title: test, version: "1"}
paths:
  /a:
    get: {operationId: same, responses: {"200": {description: ok}}}
  /b:
    get: {operationId: same, responses: {"200": {description: ok}}}
`,
	}
	for name, doc := range cases {
		if err := validateDocument([]byte(doc)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func validateDocument(data []byte) error {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return err
	}
	if err := doc.Validate(loader.Context); err != nil {
		return err
	}
	seen := map[string]string{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.OperationID == "" {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			if prev, ok := seen[op.OperationID]; ok {
				return fmt.Errorf("duplicate operationId %q on %s and %s", op.OperationID, prev, key)
			}
			seen[op.OperationID] = key
		}
	}
	return nil
}
