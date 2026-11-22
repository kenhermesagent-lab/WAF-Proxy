package mcp

import "testing"

func TestTokenScopesLimitTools(t *testing.T) {
	h := newHarness(t)
	readToken := "read-only-agent-token-that-is-long-enough"
	if _, err := h.st.CreateMCPToken("reader", HashToken(readToken), Prefix(readToken), "admin",
		[]string{"query_logs", "get_ip_activity"}); err != nil {
		t.Fatal(err)
	}

	list := h.rpc(t, readToken, "tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, raw := range tools {
		names[raw.(map[string]any)["name"].(string)] = true
	}
	if len(names) != 2 || !names["query_logs"] || !names["get_ip_activity"] {
		t.Fatalf("a two-tool token sees %v", names)
	}

	denied := h.rpc(t, readToken, "tools/call", map[string]any{
		"name": "block_ip", "arguments": map[string]any{"ip": "203.0.113.9", "reason": "test"},
	})
	if denied["error"] == nil {
		t.Fatalf("a query_logs token called block_ip: %v", denied)
	}

	allowed := h.rpc(t, readToken, "tools/call", map[string]any{"name": "query_logs", "arguments": map[string]any{}})
	if allowed["error"] != nil {
		t.Fatalf("query_logs failed for its own token: %v", allowed)
	}

	banToken := "ban-only-agent-token-that-is-long-enough"
	if _, err := h.st.CreateMCPToken("banner", HashToken(banToken), Prefix(banToken), "admin",
		[]string{"block_ip"}); err != nil {
		t.Fatal(err)
	}
	if res := h.rpc(t, banToken, "tools/call", map[string]any{
		"name": "block_ip", "arguments": map[string]any{"ip": "203.0.113.9", "reason": "test"},
	}); res["error"] != nil {
		t.Fatalf("a block_ip token could not block: %v", res)
	}
}

func TestToolNamesMatchCatalog(t *testing.T) {
	catalog := map[string]bool{}
	for _, tool := range toolCatalog(&Gateway{}) {
		catalog[tool.Name] = true
	}
	names := ToolNames()
	if len(names) != len(catalog) {
		t.Fatalf("ToolNames has %d entries, the catalog %d", len(names), len(catalog))
	}
	for _, name := range names {
		if !catalog[name] {
			t.Fatalf("ToolNames lists %q, which is not in the catalog", name)
		}
	}
}
