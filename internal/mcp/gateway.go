// Package mcp exposes a narrow, authenticated Model Context Protocol gateway
// for security operations. It deliberately has no shell, filesystem or package
// tool: every method maps to one validated store or ban-engine operation.
package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/auth"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

const (
	// Endpoint is the path operators give to an agent.
	Endpoint = "/mcp"

	// DefaultProtocol is returned when an initialize request does not pick a
	// supported version.
	DefaultProtocol = "2026-07-28"

	maxBody = 1 << 20
)

var supportedProtocols = map[string]bool{
	"2025-03-26": true,
	"2025-06-18": true,
	"2025-11-25": true,
	"2026-07-28": true,
}

// Options configures optional gateway authentication. Tokens created in the
// console are always accepted; a static environment token is useful for a
// headless install.
type Options struct {
	EnvToken string
	EnvActor string
}

// Gateway implements http.Handler for the MCP Streamable HTTP transport.
type Gateway struct {
	st       *store.Store
	bans     *ban.Engine
	log      *slog.Logger
	envToken string
	envActor string
	limiter  *auth.Limiter
	tools    []tool
	byName   map[string]tool
	now      func() time.Time
}

// New builds the gateway and its fixed tool catalog.
func New(st *store.Store, bans *ban.Engine, log *slog.Logger, opts Options) *Gateway {
	actor := strings.TrimSpace(opts.EnvActor)
	if actor == "" {
		actor = "hermes-agent"
	}
	g := &Gateway{
		st: st, bans: bans, log: log,
		envToken: strings.TrimSpace(opts.EnvToken), envActor: actor,
		limiter: auth.NewLimiter(), now: time.Now,
	}
	g.tools = toolCatalog(g)
	g.byName = make(map[string]tool, len(g.tools))
	for _, t := range g.tools {
		g.byName[t.Name] = t
	}
	return g
}

// Start prunes expired per-IP rate-limit buckets. Without it a long-running
// gateway accumulates one map entry per source address.
func (g *Gateway) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.limiter.Cleanup()
			}
		}
	}()
}

// HashToken returns the hex SHA-256 stored for an agent token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Prefix returns the non-secret display prefix for a token.
func Prefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")

	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		// 2026-07-28 removed protocol sessions; accepting DELETE keeps older
		// clients from treating teardown as an error.
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet:
		h.Set("Allow", "POST, DELETE")
		writeHTTPError(w, http.StatusMethodNotAllowed, "this MCP endpoint does not provide a standalone SSE stream")
		return
	default:
		h.Set("Allow", "POST, DELETE")
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !sameOrigin(r) {
		writeHTTPError(w, http.StatusForbidden, "cross-origin MCP requests are refused")
		return
	}
	if proto := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); proto != "" && !supportedProtocols[proto] {
		writeHTTPError(w, http.StatusBadRequest, "unsupported MCP protocol version")
		return
	}
	actor, token, ok := g.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="wafproxy-mcp"`)
		writeHTTPError(w, http.StatusUnauthorized, "a valid MCP bearer token is required")
		return
	}
	if !g.limiter.Allow("mcp:"+clientIP(r), 120, time.Minute) {
		w.Header().Set("Retry-After", "60")
		writeHTTPError(w, http.StatusTooManyRequests, "too many MCP requests")
		return
	}
	var scopes []string
	if token != nil {
		_ = g.st.TouchMCPToken(token.ID)
		scopes = NormalizeScopes(token.Scopes)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeHTTPError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeHTTPError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		writeHTTPError(w, http.StatusBadRequest, "empty request body")
		return
	}

	var req rpcRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: nil, Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32600, Message: "jsonrpc must be 2.0"}})
		return
	}

	// Notifications have no id and never receive a response body.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	result, rerr := g.dispatch(req, actor, clientIP(r), scopes)
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	writeRPC(w, http.StatusOK, resp)
}

func (g *Gateway) authenticate(r *http.Request) (string, *model.MCPToken, bool) {
	raw := bearerToken(r.Header.Get("Authorization"))
	if raw == "" {
		return "", nil, false
	}
	if g.envToken != "" && subtle.ConstantTimeCompare([]byte(raw), []byte(g.envToken)) == 1 {
		return "mcp:" + g.envActor, nil, true
	}
	t, err := g.st.MCPTokenByHash(HashToken(raw))
	if err != nil {
		return "", nil, false
	}
	return "mcp:" + t.Name, t, true
}

func bearerToken(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func sameOrigin(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (g *Gateway) dispatch(req rpcRequest, actor, ip string, scopes []string) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return g.initialize(req.Params), nil
	case "server/discover":
		return g.discover(), nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": g.toolDefinitions(scopes)}, nil
	case "tools/call":
		return g.callTool(req.Params, actor, ip, scopes)
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found"}
	}
}

func (g *Gateway) initialize(raw json.RawMessage) map[string]any {
	var in struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(raw, &in)
	protocol := strings.TrimSpace(in.ProtocolVersion)
	if !supportedProtocols[protocol] {
		protocol = DefaultProtocol
	}
	return map[string]any{
		"protocolVersion": protocol,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "wafproxy",
			"version": version.Version,
		},
		"instructions": "WAF-Proxy security operations. Read logs and activity first, then use the narrowest destructive tool with a clear reason. " +
			"block_ip and block_username accept IP addresses, CIDRs or gate usernames only; there is no shell or arbitrary command tool.",
	}
}

// discover implements the 2026-07-28 replacement for the initialize handshake.
// It also lets a modern client pick a supported version before its first tool
// call, while older clients can keep using initialize.
func (g *Gateway) discover() map[string]any {
	versions := []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}
	return map[string]any{
		"resultType":        "complete",
		"supportedVersions": versions,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"_meta":        serverMeta(),
		"instructions": "WAF-Proxy security operations. Read logs and activity first, then use the narrowest destructive tool with a clear reason.",
		"ttlMs":        3600000,
		"cacheScope":   "private",
	}
}

func (g *Gateway) toolDefinitions(scopes []string) []map[string]any {
	out := make([]map[string]any, 0, len(g.tools))
	for _, t := range g.tools {
		if !allows(scopes, t.Name) {
			continue
		}
		out = append(out, map[string]any{
			"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
		})
	}
	return out
}

func (g *Gateway) callTool(raw json.RawMessage, actor, ip string, scopes []string) (any, *rpcError) {
	var in struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&in); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid tools/call parameters"}
	}
	t, ok := g.byName[in.Name]
	if !ok {
		return nil, &rpcError{Code: -32602, Message: "unknown tool: " + in.Name}
	}
	if !allows(scopes, t.Name) {
		return nil, &rpcError{Code: -32602, Message: "agent token is not scoped for tool: " + in.Name}
	}
	if in.Arguments == nil {
		in.Arguments = map[string]any{}
	}
	result, err := t.Handler(callInfo{Actor: actor, IP: ip}, in.Arguments)
	if err != nil {
		text, _ := json.MarshalIndent(map[string]any{"error": err.Error()}, "", "  ")
		return map[string]any{
			"content":           []any{map[string]any{"type": "text", "text": string(text)}},
			"structuredContent": map[string]any{"error": err.Error()},
			"isError":           true,
			"_meta":             serverMeta(),
		}, nil
	}
	text, _ := json.MarshalIndent(result, "", "  ")
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(text)}},
		"structuredContent": result,
		"isError":           false,
		"_meta":             serverMeta(),
	}, nil
}

func serverMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/serverInfo": map[string]any{
			"name": "wafproxy", "version": version.Version,
		},
	}
}

func writeRPC(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPError(w http.ResponseWriter, status int, msg string) {
	writeRPC(w, status, map[string]any{"error": msg})
}

func (g *Gateway) audit(actor, action, detail, ip string) {
	// AddAudit deliberately has no error return; a full audit table must not
	// turn a completed revocation into a failed request.
	g.st.AddAudit(actor, action, detail, ip)
}
