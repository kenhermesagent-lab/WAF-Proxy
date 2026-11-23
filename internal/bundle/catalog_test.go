package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
)

func newCatalogManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCatalogBundlesAreShippedButOff keeps a release from starting to log new
// signatures without a decision, and proves the switch adds and removes rules.
func TestCatalogBundlesAreShippedButOff(t *testing.T) {
	m := newCatalogManager(t)
	if len(m.Rules()) != 0 {
		t.Fatalf("shipped packs started enabled: %d packs", len(m.Rules()))
	}
	st := m.Status()
	known := map[string]BundleStatus{}
	for _, b := range st.Bundles {
		if b.Builtin {
			known[b.Name] = b
		}
	}
	if len(known) != len(catalog) {
		t.Fatalf("catalog status lists %d packs, want %d", len(known), len(catalog))
	}
	if b := known["secret-probes"]; b.Enabled || b.Provider != CatalogProvider || b.Rules != 6 {
		t.Fatalf("secret-probes = %+v", b)
	}

	if err := m.SetEnabled("secret-probes", true); err != nil {
		t.Fatal(err)
	}
	rules := m.Rules()
	if len(rules) != 1 || rules[0].Name != "secret-probes" {
		t.Fatalf("rules after enabling = %+v", rules)
	}
	if got := m.RuleIndex(); got[990101].Provider != CatalogProvider {
		t.Fatalf("rule 990101 origin = %+v", got[990101])
	}

	if err := m.SetEnabled("secret-probes", false); err != nil {
		t.Fatal(err)
	}
	if len(m.Rules()) != 0 {
		t.Fatalf("rules after disabling = %+v", m.Rules())
	}
	if err := m.SetEnabled("never-shipped", true); err == nil {
		t.Fatal("an unknown bundle was accepted")
	}
}

// TestCatalogSwitchSurvivesRestart covers the state file: an enabled shipped
// pack is still enabled after a restart, and one that was never switched on
// stays off.
func TestCatalogSwitchSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := New(Config{Dir: dir, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnabled("scanner-tools", true); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Config{Dir: dir, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	rules := restarted.Rules()
	if len(rules) != 1 || rules[0].Name != "scanner-tools" {
		t.Fatalf("rules after restart = %+v", rules)
	}
}

// TestConsoleProvidersReplaceTheEnvironment covers the UI path: a provider
// saved from the console is validated the same way as one from the environment,
// cannot take the reserved name, and can be removed again.
func TestConsoleProvidersReplaceTheEnvironment(t *testing.T) {
	m := newCatalogManager(t)
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	list := []Provider{{
		Name: "vendor-a", URL: "https://a.example/manifest.json", PublicKey: hex.EncodeToString(pub),
	}}
	if err := m.SetProviders(list); err != nil {
		t.Fatal(err)
	}
	if !m.Enabled() || !m.HasProvider("vendor-a") {
		t.Fatalf("provider not applied: %+v", m.Status().Providers)
	}
	if got := m.Providers(); len(got) != 1 || got[0].PublicKey != hex.EncodeToString(pub) {
		t.Fatalf("providers = %+v", got)
	}

	bad := map[string][]Provider{
		"reserved name": {{Name: CatalogProvider, URL: "https://a.example/manifest.json", PublicKey: hex.EncodeToString(pub)}},
		"bad url":       {{Name: "vendor-b", URL: "ftp://a.example/manifest.json", PublicKey: hex.EncodeToString(pub)}},
		"bad key":       {{Name: "vendor-b", URL: "https://a.example/manifest.json", PublicKey: "not-a-key"}},
	}
	for name, providers := range bad {
		if err := m.SetProviders(providers); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if !m.HasProvider("vendor-a") {
		t.Fatal("a refused edit dropped the working provider")
	}

	if err := m.SetProviders(nil); err != nil {
		t.Fatal(err)
	}
	if m.Enabled() || m.HasProvider("vendor-a") {
		t.Fatal("removing the provider left it configured")
	}
}
