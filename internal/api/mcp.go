package api

import (
	"net/http"
	"strconv"
	"strings"
	"unicode"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/mcp"
)

// getMCP reports gateway availability without ever returning a credential.
func (s *Server) getMCP(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the agent gateway") {
		return
	}
	tokens, err := s.db(r).ListMCPTokens()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	active := 0
	for i := range tokens {
		if tokens[i].RevokedAt == nil {
			active++
		}
		tokens[i].Scopes = mcp.NormalizeScopes(tokens[i].Scopes)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint":    mcp.Endpoint,
		"env_token":   s.cfg.MCPToken != "",
		"token_count": active,
		"tokens":      tokens,
		"protocols":   []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"},
	})
}

type mcpTokenBody struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// createMCPToken returns the plaintext token exactly once. Only its SHA-256
// hash is persisted, so a database copy cannot be replayed against /mcp.
func (s *Server) createMCPToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the agent gateway") {
		return
	}
	var in mcpTokenBody
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeError(w, http.StatusBadRequest, "name is required (64 characters maximum)")
		return
	}
	for _, c := range in.Name {
		if unicode.IsControl(c) {
			writeError(w, http.StatusBadRequest, "name contains a control character")
			return
		}
	}
	valid := map[string]bool{}
	for _, tool := range mcp.ToolNames() {
		valid[tool] = true
	}
	scopes := []string{}
	for _, scope := range in.Scopes {
		if !valid[scope] {
			writeError(w, http.StatusBadRequest, "unknown tool scope: "+scope)
			return
		}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		scopes = mcp.ToolNames()
	}
	token, err := wfcrypto.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot generate token")
		return
	}
	sess := sessionFrom(r)
	id, err := s.db(r).CreateMCPToken(in.Name, mcp.HashToken(token), mcp.Prefix(token), sess.Username, scopes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot store token")
		return
	}
	s.db(r).AddAudit(sess.Username, "mcp.token_create", in.Name+" "+strings.Join(scopes, ","), clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "name": in.Name, "prefix": mcp.Prefix(token),
		"token": token, "endpoint": mcp.Endpoint, "scopes": scopes,
	})
}

func (s *Server) revokeMCPToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireHostConsole(w, r, "the agent gateway") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	revoked, err := s.db(r).RevokeMCPToken(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot revoke token")
		return
	}
	if !revoked {
		writeError(w, http.StatusNotFound, "token not found or already revoked")
		return
	}
	sess := sessionFrom(r)
	s.db(r).AddAudit(sess.Username, "mcp.token_revoke", strconv.FormatInt(id, 10), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
