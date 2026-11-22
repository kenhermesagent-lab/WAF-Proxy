package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type harness struct {
	g     *Gateway
	srv   *httptest.Server
	st    *store.Store
	bans  *ban.Engine
	token string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := New(st, bans, log, Options{})
	token := "test-agent-token-that-is-long-enough"
	if _, err := st.CreateMCPToken("hermes", HashToken(token), Prefix(token), "admin", nil); err != nil {
		t.Fatal(err)
	}
	h := &harness{g: g, srv: httptest.NewServer(g), st: st, bans: bans, token: token}
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) rpc(t *testing.T, token, method string, params any) map[string]any {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s returned HTTP %d: %v", method, res.StatusCode, out)
	}
	return out
}

func (h *harness) call(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	raw := h.rpc(t, h.token, "tools/call", map[string]any{"name": name, "arguments": args})
	result, ok := raw["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s returned no result: %v", name, raw)
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("%s returned no structured content: %v", name, result)
	}
	return structured
}

func TestGatewayProtocolAndToolCatalog(t *testing.T) {
	h := newHarness(t)

	init := h.rpc(t, h.token, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "hermes", "version": "1"},
	})
	result := init["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocol = %v", result["protocolVersion"])
	}
	if result["serverInfo"].(map[string]any)["name"] != "wafproxy" {
		t.Fatalf("serverInfo = %v", result["serverInfo"])
	}

	discover := h.rpc(t, h.token, "server/discover", map[string]any{})
	discovered := discover["result"].(map[string]any)
	if discovered["resultType"] != "complete" || len(discovered["supportedVersions"].([]any)) != 4 {
		t.Fatalf("server/discover = %v", discovered)
	}

	list := h.rpc(t, h.token, "tools/list", map[string]any{})
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, raw := range tools {
		names[raw.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"query_logs", "block_ip", "block_username", "list_sessions", "revoke_session", "revoke_sessions_for_ip"} {
		if !names[want] {
			t.Errorf("tool %q is missing from tools/list", want)
		}
	}
}

func TestGatewayRejectsMissingTokenAndForeignOrigin(t *testing.T) {
	h := newHarness(t)
	body := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL, body)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token = %d, want 401", res.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, h.srv.URL, bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Origin", "https://attacker.example")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin = %d, want 403", res.StatusCode)
	}
}

func TestAgentCanReviewBlockAndRevoke(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	if err := h.st.InsertEvents([]model.Event{
		{TS: now.Add(-time.Minute), SrcIP: "203.0.113.9", Host: "app.example.com", Method: "GET",
			Path: "/.env", Status: 403, Action: "block", Stage: "waf", RuleID: "930100"},
		{TS: now.Add(-30 * time.Second), SrcIP: "203.0.113.9", Host: "app.example.com", Method: "GET",
			Path: "/download", Status: 200, Action: "allow", Stage: "route", BytesOut: 9_000_000},
	}); err != nil {
		t.Fatal(err)
	}

	logs := h.call(t, "query_logs", map[string]any{"src_ip": "203.0.113.9", "since_minutes": 60})
	if logs["returned"].(float64) != 2 {
		t.Fatalf("query_logs returned %v events, want 2: %v", logs["returned"], logs)
	}
	if logs["bytes_out"].(float64) != 9_000_000 {
		t.Fatalf("query_logs bytes_out = %v", logs["bytes_out"])
	}

	activity := h.call(t, "get_ip_activity", map[string]any{"ip": "203.0.113.9"})
	if activity["summary_24h"].(map[string]any)["bytes_out"].(float64) != 9_000_000 {
		t.Fatalf("get_ip_activity did not expose bytes_out: %v", activity)
	}

	blocked := h.call(t, "block_ip", map[string]any{
		"ip": "203.0.113.9", "reason": "credential scanning and bulk download", "ttl_seconds": 3600,
	})
	if blocked["status"] != "blocked" || blocked["cidr"] != "203.0.113.9/32" {
		t.Fatalf("block_ip = %v", blocked)
	}
	if _, ok := h.bans.Match(mustAddr(t, "203.0.113.9")); !ok {
		t.Fatal("block_ip did not reach the ban engine")
	}

	tooBroad := h.rpc(t, h.token, "tools/call", map[string]any{
		"name": "block_ip", "arguments": map[string]any{"ip": "0.0.0.0/0", "reason": "test"},
	})
	result := tooBroad["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("0.0.0.0/0 was accepted: %v", result)
	}

	// A gate account and two sessions let the agent target one session by ref,
	// then clear the rest by source address.
	proxyID, err := h.st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.CreateGateUser("alice", "hash", "", false); err != nil {
		t.Fatal(err)
	}
	if err := h.st.CreateGateSession("cookie-one", proxyID, "alice", "198.51.100.7", "curl/8", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.st.CreateGateSession("cookie-two", proxyID, "alice", "198.51.100.8", "curl/8", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	sessions := h.call(t, "list_sessions", map[string]any{})
	rows := sessions["sessions"].([]any)
	if len(rows) != 2 {
		t.Fatalf("list_sessions returned %d rows, want 2: %v", len(rows), sessions)
	}
	ref := rows[0].(map[string]any)["ref"].(string)
	if ref == "cookie-one" || ref == "cookie-two" {
		t.Fatal("list_sessions exposed a session cookie")
	}

	revoked := h.call(t, "revoke_session", map[string]any{"session_ref": ref, "reason": "session appears to be exfiltrating data"})
	if revoked["status"] != "revoked" {
		t.Fatalf("revoke_session = %v", revoked)
	}

	if _, err := h.st.GateUserByUsername("alice"); err != nil {
		t.Fatalf("gate user was deleted: %v", err)
	}
	blockedUser := h.call(t, "block_username", map[string]any{
		"username": "alice", "reason": "compromised account",
	})
	if blockedUser["status"] != "blocked" {
		t.Fatalf("block_username = %v", blockedUser)
	}
	if banned, _ := h.st.UsernameBanned("alice"); !banned {
		t.Fatal("block_username did not persist")
	}
	if _, ok := h.st.LookupGateSession("cookie-two", proxyID); ok {
		t.Fatal("blocked username still has a live gate session")
	}

	audit, err := h.st.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for _, a := range audit {
		actions[a.Action] = true
		if a.User != "mcp:hermes" {
			t.Errorf("audit actor = %q, want mcp:hermes", a.User)
		}
	}
	for _, want := range []string{"mcp.block_ip", "mcp.revoke_session", "mcp.block_username"} {
		if !actions[want] {
			t.Errorf("audit is missing %q: %+v", want, audit)
		}
	}
}

func TestRevokeSessionsForIPAndUnblock(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	proxyID, err := h.st.CreateProxy(&model.Proxy{Hostname: "media.example.com", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"s1", "s2", "s3"} {
		ip := "198.51.100.20"
		if id == "s3" {
			ip = "198.51.100.21"
		}
		if err := h.st.CreateGateSession(id, proxyID, "bob", ip, "ua", now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	revoked := h.call(t, "revoke_sessions_for_ip", map[string]any{
		"ip": "198.51.100.20", "reason": "all sessions from this address are hostile",
	})
	if revoked["revoked_sessions"].(float64) != 2 {
		t.Fatalf("revoke_sessions_for_ip = %v", revoked)
	}
	if _, ok := h.st.LookupGateSession("s3", proxyID); !ok {
		t.Fatal("revoked the wrong address")
	}

	if _, err := h.bans.Add("203.0.113.44", "test", "manual", "admin", time.Hour); err != nil {
		t.Fatal(err)
	}
	unblocked := h.call(t, "unblock_ip", map[string]any{"ip": "203.0.113.44", "reason": "false positive"})
	if unblocked["removed"] != true {
		t.Fatalf("unblock_ip = %v", unblocked)
	}
	if _, ok := h.bans.Match(mustAddr(t, "203.0.113.44")); ok {
		t.Fatal("unblock_ip left the ban active")
	}
}

func TestRevokedTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	tokens, err := h.st.ListMCPTokens()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Fatalf("tokens = %d", len(tokens))
	}
	if _, err := h.st.RevokeMCPToken(tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d, want 401", res.StatusCode)
	}
}

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	a, err := parseAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
