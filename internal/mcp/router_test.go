package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// A token minted for one site acts on that site and nowhere else, while
// list_sites still names every tenant on the install.
func TestRouterServesTheTokensSite(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	bravo, err := st.CreateSite("bravo", "Bravo", "console.bravo.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InSite(bravo.ID).CreateProxy(&model.Proxy{Hostname: "bravo.example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "app.default.example", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	bravoToken := "bravo-agent-token-that-is-long-enough"
	if _, err := st.InSite(bravo.ID).CreateMCPToken("bravo-agent", HashToken(bravoToken), Prefix(bravoToken), "admin", nil); err != nil {
		t.Fatal(err)
	}
	defaultToken := "default-agent-token-that-is-long-enough"
	if _, err := st.CreateMCPToken("default-agent", HashToken(defaultToken), Prefix(defaultToken), "admin", nil); err != nil {
		t.Fatal(err)
	}
	stored, err := st.Unscoped().MCPTokenByHash(HashToken(bravoToken))
	if err != nil || stored.Site != "bravo" {
		t.Fatalf("tenant token site = %q (%v), want bravo", stored.Site, err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewRouter(st.Unscoped(), bans, log, Options{}))
	t.Cleanup(srv.Close)

	if got := proxyHosts(t, toolResult(t, srv.URL, bravoToken, "list_proxies")); len(got) != 1 || got[0] != "bravo.example.com" {
		t.Fatalf("a tenant token listed %v, want only bravo.example.com", got)
	}
	if got := proxyHosts(t, toolResult(t, srv.URL, defaultToken, "list_proxies")); len(got) != 1 || got[0] != "app.default.example" {
		t.Fatalf("the default token listed %v, want only app.default.example", got)
	}
	if sites, ok := toolResult(t, srv.URL, bravoToken, "list_sites")["sites"].([]any); !ok || len(sites) != 2 {
		t.Fatalf("list_sites from a tenant token = %v, want both sites", sites)
	}

	// An unknown token still reaches a gateway and is refused there.
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not-a-real-agent-token")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unknown token got HTTP %d, want 401", res.StatusCode)
	}
}

func toolResult(t *testing.T, url, token, tool string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": map[string]any{}},
	})
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s returned HTTP %d", tool, res.StatusCode)
	}
	var out struct {
		Result struct {
			Structured map[string]any `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Result.Structured
}

func proxyHosts(t *testing.T, result map[string]any) []string {
	t.Helper()
	list, ok := result["proxies"].([]any)
	if !ok {
		t.Fatalf("list_proxies = %v", result)
	}
	hosts := make([]string, 0, len(list))
	for _, raw := range list {
		if m, ok := raw.(map[string]any); ok {
			if host, _ := m["hostname"].(string); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}
