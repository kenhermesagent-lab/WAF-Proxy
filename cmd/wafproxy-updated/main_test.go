package main

import (
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates"
)

func TestAllowedPackageUsesCatalog(t *testing.T) {
	for _, name := range updates.CatalogNames() {
		if !allowedPackage(name) {
			t.Fatalf("catalog package %q was rejected", name)
		}
	}
	if allowedPackage("nginx") || allowedPackage("-o") {
		t.Fatal("helper accepted a package outside the catalog")
	}
}
