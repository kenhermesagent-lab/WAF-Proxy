package mcp

import "testing"

func TestTokenScopesLimitTools(t *testing.T) {
	h := newHarness(t)
	readToken := "read-only-agent-token-that-is-long-enough"
	if _, err := h.st.CreateMCPToken("reader", HashToken(readToken), Prefix(readToken), "admin", []string{ScopeRead}); err != nil {
		t.Fatal(err)
	}

	list := h.rpc(t, readToken, "tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, raw := range tools {
		names[raw.(map[string]any)["name"].(string)] = true
	}
	if !names["query_logs"] {
		t.Fatal("a read-scoped token cannot see query_logs")
	}
	if names["block_ip"] || names["revoke_session"] {
		t.Fatalf("a read-scoped token sees write tools: %v", names)
	}

	denied := h.rpc(t, readToken, "tools/call", map[string]any{
		"name": "block_ip", "arguments": map[string]any{"ip": "203.0.113.9", "reason": "test"},
	})
	if denied["error"] == nil {
		t.Fatalf("a read-scoped token called block_ip: %v", denied)
	}

	allowed := h.rpc(t, readToken, "tools/call", map[string]any{"name": "query_logs", "arguments": map[string]any{}})
	if allowed["error"] != nil {
		t.Fatalf("query_logs failed for a read-scoped token: %v", allowed)
	}

	banToken := "ban-only-agent-token-that-is-long-enough"
	if _, err := h.st.CreateMCPToken("banner", HashToken(banToken), Prefix(banToken), "admin", []string{ScopeBan}); err != nil {
		t.Fatal(err)
	}
	if res := h.rpc(t, banToken, "tools/call", map[string]any{
		"name": "block_ip", "arguments": map[string]any{"ip": "203.0.113.9", "reason": "test"},
	}); res["error"] != nil {
		t.Fatalf("a ban-scoped token could not block: %v", res)
	}
}
