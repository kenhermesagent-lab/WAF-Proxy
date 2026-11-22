package main

import (
	"strings"
	"testing"
)

func TestComponentsReadsTheModuleStream(t *testing.T) {
	const stream = `{"Path":"example.com/app","Main":true,"Version":"(devel)"}
{"Path":"github.com/corazawaf/coraza/v3","Version":"v3.3.3"}
{"Path":"github.com/old/name","Version":"v1.0.0","Replace":{"Path":"github.com/new/name","Version":"v1.2.0"}}
{"Path":"example.com/local","Version":""}
`
	got, err := components(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(got), got)
	}
	if got[0].PURL != "pkg:golang/github.com/corazawaf/coraza/v3@v3.3.3" {
		t.Errorf("first component = %+v", got[0])
	}
	// The replacement is what was built, not the path in go.mod.
	if got[1].PURL != "pkg:golang/github.com/new/name@v1.2.0" {
		t.Errorf("replaced component = %+v", got[1])
	}
}
