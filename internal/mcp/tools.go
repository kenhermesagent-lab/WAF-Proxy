package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type callInfo struct {
	Actor string
	IP    string
}

type tool struct {
	Name        string
	Description string
	Schema      map[string]any
	Handler     func(callInfo, map[string]any) (map[string]any, error)
}

// catalogNames is what a token may be scoped to. It lists the tools rather than
// the handlers because the API validates tokens without building a gateway; a
// test keeps it equal to the catalog.
var catalogNames = []string{
	"get_security_overview", "query_logs", "list_anomalies", "get_ip_activity",
	"list_proxies", "get_proxy", "list_sites", "list_certificates", "list_waf_profiles",
	"get_stream_status", "block_ip", "unblock_ip", "list_blocks", "list_gate_users",
	"block_username", "unblock_username", "list_sessions", "revoke_session",
	"revoke_sessions_for_ip", "cut_stream_ip", "query_audit",
}

// ToolNames lists the tools an agent token can be limited to.
func ToolNames() []string { return append([]string(nil), catalogNames...) }

// Catalog lists each tool with its description for the console's token dialog
// and for API clients, so a new tool needs no frontend edit.
func Catalog() []map[string]string {
	tools := toolCatalog(&Gateway{})
	out := make([]map[string]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]string{"name": t.Name, "description": t.Description})
	}
	return out
}

// legacyScopes is what 1.24.0 wrote for its three groups. Those names are still
// in the database, so they are expanded instead of silently matching nothing.
var legacyScopes = map[string][]string{
	"read": {"get_security_overview", "query_logs", "list_anomalies", "get_ip_activity",
		"list_proxies", "list_blocks", "list_gate_users", "list_sessions"},
	"ban":     {"block_ip", "unblock_ip", "block_username", "unblock_username"},
	"session": {"revoke_session", "revoke_sessions_for_ip"},
}

// NormalizeScopes expands the legacy group names and de-duplicates the result.
func NormalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, scope := range scopes {
		if names, ok := legacyScopes[scope]; ok {
			for _, name := range names {
				add(name)
			}
			continue
		}
		add(scope)
	}
	return out
}

// allows reports whether a token may use a tool. An empty scope list means every
// tool, so tokens created before scopes existed keep their access.
func allows(scopes []string, tool string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == tool {
			return true
		}
	}
	return false
}

func toolCatalog(g *Gateway) []tool {
	return []tool{
		{
			Name: "get_security_overview",
			Description: "Summarise the current security state: active IP bans, kernel enforcement, 1h/24h traffic and block totals, " +
				"top source addresses and attack stages, active gate sessions and blocked usernames. Start here when an agent needs orientation.",
			Schema: schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.overview()
			},
		},
		{
			Name: "query_logs",
			Description: "Read recent proxy events newest first. Filter by source IP, host, action (allow/block/ban/challenge/log), " +
				"stage, or blocked_only. Use this to review a suspected address or a host before deciding on a block or session revocation.",
			Schema: schema(map[string]any{
				"src_ip":        prop("string", "Exact source IP address to inspect."),
				"host":          prop("string", "Exact proxy hostname to inspect."),
				"action":        prop("string", "Exact action: allow, block, ban, challenge or log."),
				"stage":         prop("string", "Pipeline stage, for example waf, ratelimit, gate, bot, decoy or stream."),
				"blocked_only":  prop("boolean", "Only return block, ban and challenge events."),
				"since_minutes": prop("integer", "How far back to look, 1-10080 minutes. Default 60."),
				"limit":         prop("integer", "Maximum events to return, 1-500. Default 50."),
			}),
			Handler: g.queryLogs,
		},
		{
			Name: "list_anomalies",
			Description: "Recent anomaly detections (outbound byte spike, request-rate spike, login-failure burst) with the " +
				"proxy, the value measured and its baseline. Start here when deciding whether an event needs a block.",
			Schema: schema(map[string]any{
				"limit": prop("integer", "Maximum events to return, 1-200. Default 50."),
			}),
			Handler: g.listAnomalies,
		},
		{
			Name: "get_ip_activity",
			Description: "Inspect one source address: 24h request/block/byte totals, whether it is banned, recent events, and live gate " +
				"sessions. bytes_out and the recent paths help distinguish scanning from data exfiltration before revoking sessions.",
			Schema: schema(map[string]any{
				"ip": prop("string", "IPv4 or IPv6 source address."),
			}, "ip"),
			Handler: g.ipActivity,
		},
		{
			Name:        "list_proxies",
			Description: "List configured proxy hostnames and their gate/WAF modes. Use the id or hostname to narrow query_logs.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listProxies()
			},
		},
		{
			Name: "get_proxy",
			Description: "Inspect one proxy host: gate and WAF modes, TLS certificate, WAF and access profiles, balancing and " +
				"health-check settings, in-flight limits and the upstream pool. Name it by hostname or by the id from list_proxies.",
			Schema: schema(map[string]any{
				"hostname": prop("string", "Exact proxy hostname."),
				"id":       prop("integer", "Proxy id from list_proxies."),
			}),
			Handler: g.getProxy,
		},
		{
			Name:        "list_sites",
			Description: "List the sites (tenants) this install serves, each with its console host and whether it is enabled, so a host or an event can be attributed to the site that owns it.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listSites()
			},
		},
		{
			Name:        "list_certificates",
			Description: "List TLS certificates with issuer, status, renewal mode and days until expiry. Use it before calling a TLS failure an attack, and to spot a certificate that renewal has not replaced.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listCertificates()
			},
		},
		{
			Name:        "list_waf_profiles",
			Description: "List WAF profiles with their mode, paranoia level, anomaly threshold, response inspection and body caps, so a blocked event can be read in the context of the rule set that produced it.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listWAFProfiles()
			},
		},
		{
			Name: "get_stream_status",
			Description: "Read the media relay: each service's bind state, listen address, active streams and sessions, totals and refusals, " +
				"with its busiest live sessions. An install with no relay attached reports attached=false.",
			Schema: schema(map[string]any{
				"id":    prop("string", "Only this service id, for example minecraft-java."),
				"limit": prop("integer", "Live sessions listed per service, 1-200. Default 20."),
			}),
			Handler: g.getStreamStatus,
		},
		{
			Name: "block_ip",
			Description: "Add an IP or CIDR to the kernel/proxy blacklist. reason is required for the audit trail. Defaults to a 24 hour " +
				"temporary ban; set permanent=true only for confirmed hostile infrastructure. Refuses loopback, unspecified, multicast, " +
				"link-local and dangerously broad prefixes.",
			Schema: schema(map[string]any{
				"ip":          prop("string", "IPv4/IPv6 address or CIDR, for example 203.0.113.9 or 203.0.113.0/24."),
				"reason":      prop("string", "Why this address is being blocked. Stored in the ban and the audit log."),
				"permanent":   prop("boolean", "Create a permanent ban. Default false."),
				"ttl_seconds": prop("integer", "Temporary ban lifetime, 60-31536000 seconds. Default 86400."),
			}, "ip", "reason"),
			Handler: g.blockIP,
		},
		{
			Name: "unblock_ip",
			Description: "Lift an exact IP or CIDR ban. This removes only the matching ban row; a broader covering prefix is reported but " +
				"left in place. reason is optional but recommended.",
			Schema: schema(map[string]any{
				"ip":     prop("string", "IPv4/IPv6 address or CIDR to unblock."),
				"reason": prop("string", "Why the block is being lifted."),
			}, "ip"),
			Handler: g.unblockIP,
		},
		{
			Name:        "list_blocks",
			Description: "List active IP/CIDR bans and blocked gate usernames with reasons and expiry. Use before adding a duplicate block.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listBlocks()
			},
		},
		{
			Name:        "list_gate_users",
			Description: "List access-gate usernames and whether each is currently blocked. Password hashes and TOTP secrets are never returned.",
			Schema:      schema(nil),
			Handler: func(_ callInfo, _ map[string]any) (map[string]any, error) {
				return g.listGateUsers()
			},
		},
		{
			Name: "block_username",
			Description: "Block an access-gate username and revoke its live visitor sessions. reason is required. Use this for a compromised " +
				"or abusive account; the account itself is not deleted. Set ttl_seconds for a temporary block, or leave 0 for permanent.",
			Schema: schema(map[string]any{
				"username":        prop("string", "Exact gate username to block."),
				"reason":          prop("string", "Why the username is being blocked. Stored in the block and the audit log."),
				"ttl_seconds":     prop("integer", "Temporary block lifetime in seconds; 0 means permanent. Default 0."),
				"revoke_sessions": prop("boolean", "Revoke every live session for this username. Default true."),
			}, "username", "reason"),
			Handler: g.blockUsername,
		},
		{
			Name:        "unblock_username",
			Description: "Lift an access-gate username block. Existing sessions stay revoked; the account must sign in again.",
			Schema: schema(map[string]any{
				"username": prop("string", "Exact gate username to unblock."),
				"reason":   prop("string", "Why the block is being lifted."),
			}, "username"),
			Handler: g.unblockUsername,
		},
		{
			Name: "list_sessions",
			Description: "List live access-gate visitor sessions with a non-secret ref, username, source IP, proxy hostname, user agent and " +
				"expiry. Session cookie values are never exposed.",
			Schema: schema(map[string]any{
				"limit": prop("integer", "Maximum sessions to return, 1-1000. Default 200."),
			}),
			Handler: g.listSessions,
		},
		{
			Name: "revoke_session",
			Description: "Kill one live gate session by its ref from list_sessions. Use this when a specific session is exfiltrating data or " +
				"has been taken over. reason is required for the audit trail.",
			Schema: schema(map[string]any{
				"session_ref": prop("string", "The ref value returned by list_sessions or get_ip_activity."),
				"reason":      prop("string", "Why this session is being killed."),
			}, "session_ref", "reason"),
			Handler: g.revokeSession,
		},
		{
			Name: "revoke_sessions_for_ip",
			Description: "Kill every live gate session opened from one IP address. Prefer revoke_session when a single ref is known; use this " +
				"only when all sessions from the address are considered hostile. reason is required.",
			Schema: schema(map[string]any{
				"ip":     prop("string", "IPv4 or IPv6 address whose gate sessions should be revoked."),
				"reason": prop("string", "Why every session from this address is being killed."),
			}, "ip", "reason"),
			Handler: g.revokeSessionsForIP,
		},
		{
			Name: "cut_stream_ip",
			Description: "Cut every live media-relay stream from one address. Use it for a listed session that is abusive or moving data; " +
				"block_ip remains the durable ban, this ends the connection now. reason is required for the audit trail.",
			Schema: schema(map[string]any{
				"ip":     prop("string", "IPv4 or IPv6 address whose relay streams should be cut."),
				"reason": prop("string", "Why the streams are being cut."),
			}, "ip", "reason"),
			Handler: g.cutStreamIP,
		},
		{
			Name: "query_audit",
			Description: "Read the administrator audit log newest first, including the mcp.* rows agents write. Filter by actor or by " +
				"action text to see what changed recently before attributing a change to traffic.",
			Schema: schema(map[string]any{
				"actor":  prop("string", "Only entries whose actor matches exactly."),
				"action": prop("string", "Only entries whose action contains this text, for example mcp.block."),
				"limit":  prop("integer", "Maximum entries to return, 1-200. Default 50."),
			}),
			Handler: g.queryAudit,
		},
	}
}

func schema(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(kind, description string) map[string]any {
	return map[string]any{"type": kind, "description": description}
}

func (g *Gateway) overview() (map[string]any, error) {
	now := g.now()
	oneHour, err := g.st.Summary(now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	day, err := g.st.Summary(now.Add(-24 * time.Hour))
	if err != nil {
		return nil, err
	}
	topIPs, _ := g.st.TopBy("src_ip", now.Add(-24*time.Hour), 10)
	topStages, _ := g.st.TopBy("stage", now.Add(-24*time.Hour), 10)
	recent, _, _ := g.st.QueryEvents(store.EventFilter{
		From: now.Add(-24 * time.Hour), To: now, BlockedOnly: true, Limit: 10,
	})
	sessions, _ := g.st.GateSessions(0)
	usernameBans, _ := g.st.ListUsernameBans(false)
	kernelActive, kernelReason := g.bans.KernelStatus()
	return map[string]any{
		"now":                  now.UTC(),
		"active_ip_bans":       g.bans.Count(),
		"kernel":               map[string]any{"active": kernelActive, "reason": kernelReason},
		"last_hour":            oneHour,
		"last_24h":             day,
		"top_source_ips_24h":   topIPs,
		"top_stages_24h":       topStages,
		"recent_blocked":       recent,
		"active_gate_sessions": len(sessions),
		"blocked_usernames":    usernameBans,
	}, nil
}

func (g *Gateway) queryLogs(_ callInfo, args map[string]any) (map[string]any, error) {
	now := g.now()
	minutes, err := intArg(args, "since_minutes", 60, 1, 10080)
	if err != nil {
		return nil, err
	}
	limit, err := intArg(args, "limit", 50, 1, 500)
	if err != nil {
		return nil, err
	}
	srcIP, err := stringArg(args, "src_ip", false)
	if err != nil {
		return nil, err
	}
	if srcIP != "" {
		if _, err := netip.ParseAddr(srcIP); err != nil {
			return nil, fmt.Errorf("src_ip: %w", err)
		}
	}
	host, err := stringArg(args, "host", false)
	if err != nil {
		return nil, err
	}
	action, err := stringArg(args, "action", false)
	if err != nil {
		return nil, err
	}
	stage, err := stringArg(args, "stage", false)
	if err != nil {
		return nil, err
	}
	blockedOnly, err := boolArg(args, "blocked_only", false)
	if err != nil {
		return nil, err
	}
	from := now.Add(-time.Duration(minutes) * time.Minute)
	events, total, err := g.st.QueryEvents(store.EventFilter{
		From: from, To: now, SrcIP: srcIP, Host: host, Action: action, Stage: stage,
		BlockedOnly: blockedOnly, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	var bytesOut, blocked int64
	for _, e := range events {
		bytesOut += e.BytesOut
		if e.Action == "block" || e.Action == "ban" || e.Action == "challenge" {
			blocked++
		}
	}
	return map[string]any{
		"from":             from.UTC(),
		"to":               now.UTC(),
		"total_matching":   total,
		"returned":         len(events),
		"bytes_out":        bytesOut,
		"blocked_returned": blocked,
		"events":           events,
	}, nil
}

func (g *Gateway) ipActivity(_ callInfo, args map[string]any) (map[string]any, error) {
	raw, err := stringArg(args, "ip", true)
	if err != nil {
		return nil, err
	}
	addr, err := parseAddr(raw)
	if err != nil {
		return nil, err
	}
	now := g.now()
	summary, err := g.st.IPSummary(addr.String(), now.Add(-24*time.Hour), now)
	if err != nil {
		return nil, err
	}
	events, total, err := g.st.QueryEvents(store.EventFilter{
		From: now.Add(-24 * time.Hour), To: now, SrcIP: addr.String(), Limit: 50,
	})
	if err != nil {
		return nil, err
	}
	ban := map[string]any{"active": false}
	if rec, ok := g.bans.Match(addr); ok {
		ban = map[string]any{
			"active": true, "cidr": rec.CIDR, "reason": rec.Reason, "source": rec.Source,
			"permanent": rec.Permanent, "expires_at": rec.ExpiresAt,
		}
	}
	sessions, _ := g.st.GateSessions(1000)
	onIP := make([]model.GateSession, 0)
	for _, s := range sessions {
		if s.IP == addr.String() {
			onIP = append(onIP, s)
		}
	}
	return map[string]any{
		"ip":               addr.String(),
		"summary_24h":      summary,
		"ban":              ban,
		"events":           events,
		"total_events_24h": total,
		"gate_sessions":    onIP,
	}, nil
}

func (g *Gateway) listProxies() (map[string]any, error) {
	proxies, err := g.st.ListProxies()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(proxies))
	for _, p := range proxies {
		out = append(out, map[string]any{
			"id": p.ID, "hostname": p.Hostname, "enabled": p.Enabled,
			"gate_mode": p.GateMode, "waf_mode": p.WAFMode, "maintenance": p.Maintenance,
		})
	}
	return map[string]any{"proxies": out}, nil
}

func (g *Gateway) blockIP(info callInfo, args map[string]any) (map[string]any, error) {
	raw, err := stringArg(args, "ip", true)
	if err != nil {
		return nil, err
	}
	reason, err := reasonArg(args)
	if err != nil {
		return nil, err
	}
	permanent, err := boolArg(args, "permanent", false)
	if err != nil {
		return nil, err
	}
	ttl, err := intArg(args, "ttl_seconds", 86400, 0, 31536000)
	if err != nil {
		return nil, err
	}
	if !permanent && ttl == 0 {
		ttl = 86400
	}
	p, err := parseBlockPrefix(raw)
	if err != nil {
		return nil, err
	}
	dur := time.Duration(ttl) * time.Second
	if permanent {
		dur = 0
	}
	rec, err := g.bans.Add(p.String(), reason, "mcp", info.Actor, dur)
	if err != nil {
		return nil, err
	}
	g.audit(info.Actor, "mcp.block_ip", rec.CIDR+" "+reason, info.IP)
	return map[string]any{
		"status": "blocked", "cidr": rec.CIDR, "permanent": rec.Permanent,
		"expires_at": rec.ExpiresAt, "reason": rec.Reason, "source": "mcp",
	}, nil
}

func (g *Gateway) unblockIP(info callInfo, args map[string]any) (map[string]any, error) {
	raw, err := stringArg(args, "ip", true)
	if err != nil {
		return nil, err
	}
	reason, err := stringArg(args, "reason", false)
	if err != nil {
		return nil, err
	}
	p, err := parseBlockPrefix(raw)
	if err != nil {
		return nil, err
	}
	if _, err := g.st.BanByCIDR(p.String()); errors.Is(err, store.ErrNotFound) {
		covering := map[string]any{}
		if rec, ok := g.bans.Match(p.Addr()); ok {
			covering = map[string]any{"cidr": rec.CIDR, "reason": rec.Reason, "source": rec.Source}
		}
		return map[string]any{"removed": false, "cidr": p.String(), "covering_ban": covering}, nil
	} else if err != nil {
		return nil, err
	}
	if err := g.bans.Remove(p.String()); err != nil {
		return nil, err
	}
	g.audit(info.Actor, "mcp.unblock_ip", p.String()+" "+reason, info.IP)
	return map[string]any{"removed": true, "cidr": p.String()}, nil
}

func (g *Gateway) listBlocks() (map[string]any, error) {
	bans, err := g.bans.List(false)
	if err != nil {
		return nil, err
	}
	usernames, err := g.st.ListUsernameBans(false)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ip_bans": bans, "ip_ban_count": len(bans),
		"username_bans": usernames, "username_ban_count": len(usernames),
	}, nil
}

func (g *Gateway) listGateUsers() (map[string]any, error) {
	users, err := g.st.ListGateUsers()
	if err != nil {
		return nil, err
	}
	bans, err := g.st.ListUsernameBans(false)
	if err != nil {
		return nil, err
	}
	blocked := make(map[string]model.UsernameBan, len(bans))
	for _, b := range bans {
		blocked[b.Username] = b
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		row := map[string]any{
			"id": u.ID, "username": u.Username, "totp_enabled": u.TOTPEnabled,
			"created_at": u.CreatedAt, "blocked": false,
		}
		if b, ok := blocked[u.Username]; ok {
			row["blocked"] = true
			row["block_reason"] = b.Reason
			row["block_expires_at"] = b.ExpiresAt
		}
		out = append(out, row)
	}
	return map[string]any{"users": out, "blocked_usernames": bans}, nil
}

func (g *Gateway) blockUsername(info callInfo, args map[string]any) (map[string]any, error) {
	username, err := usernameArg(args)
	if err != nil {
		return nil, err
	}
	reason, err := reasonArg(args)
	if err != nil {
		return nil, err
	}
	ttl, err := intArg(args, "ttl_seconds", 0, 0, 31536000)
	if err != nil {
		return nil, err
	}
	revoke, err := boolArg(args, "revoke_sessions", true)
	if err != nil {
		return nil, err
	}
	var expires *time.Time
	if ttl > 0 {
		t := g.now().Add(time.Duration(ttl) * time.Second)
		expires = &t
	}
	if err := g.st.AddUsernameBan(username, reason, info.Actor, expires); err != nil {
		return nil, err
	}
	var revoked int64
	if revoke {
		revoked, err = g.st.RevokeGateSessionsFor(username)
		if err != nil {
			return nil, err
		}
	}
	g.audit(info.Actor, "mcp.block_username", username+" "+reason, info.IP)
	return map[string]any{
		"status": "blocked", "username": username, "reason": reason,
		"expires_at": expires, "revoked_sessions": revoked,
	}, nil
}

func (g *Gateway) unblockUsername(info callInfo, args map[string]any) (map[string]any, error) {
	username, err := usernameArg(args)
	if err != nil {
		return nil, err
	}
	reason, err := stringArg(args, "reason", false)
	if err != nil {
		return nil, err
	}
	removed, err := g.st.RemoveUsernameBan(username)
	if err != nil {
		return nil, err
	}
	if removed {
		g.audit(info.Actor, "mcp.unblock_username", username+" "+reason, info.IP)
	}
	return map[string]any{"removed": removed, "username": username}, nil
}

func (g *Gateway) listSessions(_ callInfo, args map[string]any) (map[string]any, error) {
	limit, err := intArg(args, "limit", 200, 1, 1000)
	if err != nil {
		return nil, err
	}
	sessions, err := g.st.GateSessions(limit)
	if err != nil {
		return nil, err
	}
	total, _ := g.st.CountGateSessions()
	return map[string]any{"sessions": sessions, "returned": len(sessions), "total_active": total}, nil
}

func (g *Gateway) revokeSession(info callInfo, args map[string]any) (map[string]any, error) {
	ref, err := stringArg(args, "session_ref", true)
	if err != nil {
		return nil, err
	}
	if len(ref) != 32 || strings.Trim(ref, "0123456789abcdef") != "" {
		return nil, errors.New("session_ref must be the 32-character ref from list_sessions")
	}
	reason, err := reasonArg(args)
	if err != nil {
		return nil, err
	}
	session, err := g.st.DeleteGateSessionByRef(ref)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("session not found or already expired")
	}
	if err != nil {
		return nil, err
	}
	g.audit(info.Actor, "mcp.revoke_session", session.Username+" "+session.IP+" "+reason, info.IP)
	return map[string]any{"status": "revoked", "session": session, "reason": reason}, nil
}

func (g *Gateway) revokeSessionsForIP(info callInfo, args map[string]any) (map[string]any, error) {
	raw, err := stringArg(args, "ip", true)
	if err != nil {
		return nil, err
	}
	addr, err := parseAddr(raw)
	if err != nil {
		return nil, err
	}
	reason, err := reasonArg(args)
	if err != nil {
		return nil, err
	}
	n, err := g.st.DeleteGateSessionsForIP(addr.String())
	if err != nil {
		return nil, err
	}
	g.audit(info.Actor, "mcp.revoke_sessions_for_ip", addr.String()+" "+reason, info.IP)
	return map[string]any{"status": "revoked", "ip": addr.String(), "revoked_sessions": n, "reason": reason}, nil
}

func (g *Gateway) listSites() (map[string]any, error) {
	sites, err := g.st.ListSites()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		out = append(out, map[string]any{
			"slug": s.Slug, "name": s.Name, "console_host": s.ConsoleHost,
			"enabled": s.Enabled, "created_at": s.CreatedAt,
		})
	}
	return map[string]any{"sites": out, "current_site_id": g.st.SiteID()}, nil
}

func (g *Gateway) getProxy(_ callInfo, args map[string]any) (map[string]any, error) {
	hostname, err := stringArg(args, "hostname", false)
	if err != nil {
		return nil, err
	}
	id, err := intArg(args, "id", 0, 0, 1<<40)
	if err != nil {
		return nil, err
	}
	if (hostname == "") == (id == 0) {
		return nil, errors.New("name the proxy by exactly one of hostname or id")
	}
	proxies, err := g.st.ListProxies()
	if err != nil {
		return nil, err
	}
	var p *model.Proxy
	for i := range proxies {
		if (hostname != "" && proxies[i].Hostname == hostname) || (id != 0 && proxies[i].ID == int64(id)) {
			p = &proxies[i]
			break
		}
	}
	if p == nil {
		return nil, errors.New("proxy not found on this site")
	}
	upstreams, err := g.st.ListUpstreams(p.ID)
	if err != nil {
		return nil, err
	}
	profileNames := map[int64]string{}
	if profiles, err := g.st.ListProfiles(); err == nil {
		for _, pr := range profiles {
			profileNames[pr.ID] = pr.Name
		}
	}
	row := map[string]any{
		"id": p.ID, "hostname": p.Hostname, "enabled": p.Enabled,
		"gate_mode": p.GateMode, "waf_mode": p.WAFMode, "bot_level": p.BotLevel,
		"fingerprint": p.Fingerprint, "maintenance": p.Maintenance,
		"lb_policy": p.LBPolicy, "health_path": p.HealthPath, "health_interval": p.HealthInterval,
		"max_inflight": p.MaxInflight, "max_inflight_per_client": p.MaxInflightPerClient,
		"upstream_timeout": p.UpstreamTimeout, "retries": p.Retries, "tls_min_version": p.TLSMinVersion,
		"upstreams": upstreams,
	}
	if p.ProfileID != nil {
		row["waf_profile"] = profileNames[*p.ProfileID]
	}
	if p.CertID != nil {
		if certs, err := g.st.ListCerts(); err == nil {
			for _, c := range certs {
				if c.ID == *p.CertID {
					row["certificate"] = map[string]any{
						"id": c.ID, "domains": c.Domains, "status": c.Status,
						"source": c.Source, "expires_at": c.ExpiresAt,
					}
					break
				}
			}
		}
	}
	return row, nil
}

func (g *Gateway) listCertificates() (map[string]any, error) {
	certs, err := g.st.ListCerts()
	if err != nil {
		return nil, err
	}
	now := g.now()
	out := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		row := map[string]any{
			"id": c.ID, "domains": c.Domains, "provider": c.Provider, "source": c.Source,
			"status": c.Status, "renew_mode": c.RenewMode, "challenge": c.Challenge,
			"issued_at": c.IssuedAt, "expires_at": c.ExpiresAt, "last_error": c.LastError,
		}
		if c.ExpiresAt != nil {
			row["days_left"] = int(c.ExpiresAt.Sub(now).Hours() / 24)
		}
		out = append(out, row)
	}
	return map[string]any{"certificates": out, "count": len(out)}, nil
}

func (g *Gateway) listWAFProfiles() (map[string]any, error) {
	profiles, err := g.st.ListProfiles()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, map[string]any{
			"id": p.ID, "name": p.Name, "builtin": p.Builtin, "mode": p.Mode,
			"paranoia": p.Paranoia, "anomaly": p.Anomaly, "responses": p.Responses,
			"max_body": p.MaxBody, "max_response": p.MaxResponse,
			"allowed_methods": p.AllowedMethods, "login_paths": p.LoginPaths, "login_rps": p.LoginRPS,
		})
	}
	return map[string]any{"profiles": out, "count": len(out)}, nil
}

func (g *Gateway) getStreamStatus(_ callInfo, args map[string]any) (map[string]any, error) {
	id, err := stringArg(args, "id", false)
	if err != nil {
		return nil, err
	}
	limit, err := intArg(args, "limit", 20, 1, 200)
	if err != nil {
		return nil, err
	}
	if g.streams == nil {
		return map[string]any{"attached": false, "services": []any{}}, nil
	}
	out := make([]map[string]any, 0)
	for _, st := range g.streams.Statuses() {
		if id != "" && st.ID != id {
			continue
		}
		listed := st.Sessions
		if len(listed) > limit {
			listed = listed[:limit]
		}
		out = append(out, map[string]any{
			"id": st.ID, "label": st.Label, "bound": st.Bound, "listen_addr": st.ListenAddr,
			"protocol": st.Protocol, "port": st.Port, "upstream_base": st.UpstreamBase,
			"active": st.Active, "active_sessions": st.ActiveSessions, "total": st.Total,
			"blocked": st.Blocked, "banned": st.Banned, "refused": st.Refused,
			"bytes_in": st.BytesIn, "bytes_out": st.BytesOut, "last_error": st.LastError,
			"session_count": len(st.Sessions), "sessions": listed,
		})
	}
	return map[string]any{"attached": true, "services": out, "count": len(out)}, nil
}

func (g *Gateway) cutStreamIP(info callInfo, args map[string]any) (map[string]any, error) {
	raw, err := stringArg(args, "ip", true)
	if err != nil {
		return nil, err
	}
	reason, err := reasonArg(args)
	if err != nil {
		return nil, err
	}
	addr, err := parseAddr(raw)
	if err != nil {
		return nil, err
	}
	if g.streams == nil {
		return nil, errors.New("no media relay is attached on this node")
	}
	cut := g.streams.DropBanned(func(a netip.Addr) bool { return a == addr }, "mcp: "+reason)
	g.audit(info.Actor, "mcp.cut_stream_ip", addr.String()+" "+reason, info.IP)
	return map[string]any{"status": "cut", "ip": addr.String(), "streams_cut": cut, "reason": reason}, nil
}

func (g *Gateway) queryAudit(_ callInfo, args map[string]any) (map[string]any, error) {
	limit, err := intArg(args, "limit", 50, 1, 200)
	if err != nil {
		return nil, err
	}
	actor, err := stringArg(args, "actor", false)
	if err != nil {
		return nil, err
	}
	action, err := stringArg(args, "action", false)
	if err != nil {
		return nil, err
	}
	entries, err := g.st.ListAudit(limit)
	if err != nil {
		return nil, err
	}
	out := make([]model.AuditEntry, 0, len(entries))
	for _, e := range entries {
		if actor != "" && e.User != actor {
			continue
		}
		if action != "" && !strings.Contains(e.Action, action) {
			continue
		}
		out = append(out, e)
	}
	return map[string]any{"entries": out, "returned": len(out), "scanned": len(entries)}, nil
}

func parseAddr(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address: %w", err)
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return netip.Addr{}, errors.New("invalid IP address")
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return netip.Addr{}, errors.New("refusing to operate on loopback, unspecified, multicast or link-local addresses")
	}
	return addr, nil
}

func parseBlockPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(raw); err == nil {
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, errors.New("refusing a prefix broader than /8")
			}
			q := netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
			if q.Bits() < 8 {
				return netip.Prefix{}, errors.New("refusing a prefix broader than /8")
			}
			return q, nil
		}
		if p.Addr().Is4() && p.Bits() < 8 {
			return netip.Prefix{}, errors.New("refusing a prefix broader than /8")
		}
		if p.Addr().Is6() && p.Bits() < 16 {
			return netip.Prefix{}, errors.New("refusing a prefix broader than /16")
		}
		return p.Masked(), nil
	}
	addr, err := parseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func stringArg(args map[string]any, key string, required bool) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("%s is required", key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	s = strings.TrimSpace(s)
	if required && s == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if len(s) > 512 {
		return "", fmt.Errorf("%s is too long", key)
	}
	return s, nil
}

func reasonArg(args map[string]any) (string, error) {
	reason, err := stringArg(args, "reason", true)
	if err != nil {
		return "", err
	}
	if len(reason) > 300 {
		return "", errors.New("reason must be 300 characters or fewer")
	}
	return reason, nil
}

func usernameArg(args map[string]any) (string, error) {
	username, err := stringArg(args, "username", true)
	if err != nil {
		return "", err
	}
	if len(username) > 128 {
		return "", errors.New("username must be 128 characters or fewer")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return "", errors.New("username contains a control character")
		}
	}
	return username, nil
}

func intArg(args map[string]any, key string, fallback, min, max int) (int, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return fallback, nil
	}
	var n int
	switch t := v.(type) {
	case json.Number:
		i, err := strconv.Atoi(t.String())
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
		n = i
	case float64:
		n = int(t)
		if float64(n) != t {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
	case int:
		n = t
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d", key, min, max)
	}
	return n, nil
}

func boolArg(args map[string]any, key string, fallback bool) (bool, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return fallback, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return b, nil
}

func (g *Gateway) listAnomalies(_ callInfo, args map[string]any) (map[string]any, error) {
	limit, err := intArg(args, "limit", 50, 1, 200)
	if err != nil {
		return nil, err
	}
	events, err := g.st.ListAnomalyEvents(limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{"events": events, "count": len(events)}, nil
}
