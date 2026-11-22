package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	mcpgw "github.com/kenhermesagent-lab/waf-proxy-docker/internal/mcp"
)

func TestMCPTokenCreateListAndRevoke(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)

	// A mutation without the console CSRF token must not mint an agent token.
	missing := httptest.NewRequest(http.MethodPost, "/api/mcp/tokens", strings.NewReader(`{"name":"hermes"}`))
	missing.Host = "gui.local"
	missing.RemoteAddr = "10.0.0.10:5000"
	missing.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	missingRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(missingRec, missing)
	if missingRec.Code != http.StatusForbidden {
		t.Fatalf("token create without CSRF = %d, want 403", missingRec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mcp/tokens", strings.NewReader(`{"name":"hermes","scopes":["query_logs"]}`))
	req.Host = "gui.local"
	req.RemoteAddr = "10.0.0.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("token create = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID       int64  `json:"id"`
		Token    string `json:"token"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Token) < 32 || created.Endpoint != mcpgw.Endpoint {
		t.Fatalf("unexpected token response: %+v", created)
	}
	stored, err := st.MCPTokenByHash(mcpgw.HashToken(created.Token))
	if err != nil || stored.Name != "hermes" {
		t.Fatalf("created token is not usable: %+v (%v)", stored, err)
	}
	if len(stored.Scopes) != 1 || stored.Scopes[0] != "query_logs" {
		t.Fatalf("created token scopes = %v, want [query_logs]", stored.Scopes)
	}

	// An unknown scope must not quietly widen or narrow the token.
	bad := httptest.NewRequest(http.MethodPost, "/api/mcp/tokens", strings.NewReader(`{"name":"bad","scopes":["root"]}`))
	bad.Host = "gui.local"
	bad.RemoteAddr = "10.0.0.10:5000"
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	bad.Header.Set("X-CSRF-Token", csrf)
	badRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("token create with an unknown scope = %d, want 400", badRec.Code)
	}

	// The list must not return the plaintext token or its hash.
	get := httptest.NewRequest(http.MethodGet, "/api/mcp", nil)
	get.Host = "gui.local"
	get.RemoteAddr = "10.0.0.10:5000"
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/mcp = %d: %s", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), created.Token) || strings.Contains(getRec.Body.String(), mcpgw.HashToken(created.Token)) {
		t.Fatal("GET /api/mcp exposed secret token material")
	}
	if !strings.Contains(getRec.Body.String(), `"scopes":["query_logs"]`) {
		t.Fatalf("GET /api/mcp did not report the token scopes: %s", getRec.Body.String())
	}
	var status struct {
		TokenCount int `json:"token_count"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.TokenCount != 1 {
		t.Fatalf("token_count = %d, want 1", status.TokenCount)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/mcp/tokens/"+strconv.FormatInt(created.ID, 10), nil)
	del.Host = "gui.local"
	del.RemoteAddr = "10.0.0.10:5000"
	del.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	del.Header.Set("X-CSRF-Token", csrf)
	delRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delRec, del)
	if delRec.Code != http.StatusOK {
		t.Fatalf("token revoke = %d: %s", delRec.Code, delRec.Body.String())
	}
	if _, err := st.MCPTokenByHash(mcpgw.HashToken(created.Token)); err == nil {
		t.Fatal("revoked token is still accepted")
	}
}
