// Package rbac defines the administrator permission model and the built-in
// roles, so the API, the store seed and the console agree on one list.
package rbac

import (
	"sort"
	"strings"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// Admin is the wildcard permission.
const Admin = "*"

// Area is one part of the console that can be granted separately. Read covers
// every GET and HEAD request; write covers everything that changes state.
type Area struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Areas is the ordered permission catalogue shown in the role editor.
var Areas = []Area{
	{"dashboard", "Dashboard and live traffic"},
	{"traffic", "Logs, analytics, IPs and audit"},
	{"policies", "Policies, bans, lists and WAF profiles"},
	{"proxies", "Proxies, routes and presets"},
	{"streaming", "Streaming forwarders"},
	{"certificates", "Certificates"},
	{"sources", "Threat feeds, CrowdSec and agents"},
	{"settings", "Settings, GeoIP, notifications and backup"},
	{"accounts", "Administrator accounts and roles"},
	{"system", "Updates and system restart"},
}

// Permission returns the "area.action" token for an area.
func Permission(area, action string) string { return area + "." + action }

// Allows reports whether a permission list grants want. A wildcard grants
// everything, and a write grant implies the matching read.
func Allows(permissions []string, want string) bool {
	for _, p := range permissions {
		if p == Admin || p == want {
			return true
		}
		if strings.HasSuffix(want, ".read") && p == strings.TrimSuffix(want, ".read")+".write" {
			return true
		}
	}
	return false
}

// Valid reports whether token is a known permission or the wildcard.
func Valid(token string) bool {
	if token == Admin {
		return true
	}
	for _, a := range Areas {
		if token == Permission(a.Key, "read") || token == Permission(a.Key, "write") {
			return true
		}
	}
	return false
}

// Normalize drops unknown entries, expands nothing and returns a sorted,
// de-duplicated list. An empty list stays empty (no access).
func Normalize(list []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, p := range list {
		p = strings.TrimSpace(p)
		if !Valid(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Parse splits a stored comma-separated permission list.
func Parse(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return Normalize(strings.Split(raw, ","))
}

// Join serialises a permission list for storage.
func Join(list []string) string { return strings.Join(Normalize(list), ",") }

func allRead() []string {
	out := make([]string, 0, len(Areas))
	for _, a := range Areas {
		out = append(out, Permission(a.Key, "read"))
	}
	return out
}

func withWrites(areas ...string) []string {
	out := allRead()
	for _, a := range areas {
		out = append(out, Permission(a, "write"))
	}
	return Normalize(out)
}

// Builtins returns the roles every installation starts with. They cannot be
// edited or deleted, so an operator always has a known-good set.
func Builtins() []model.Role {
	return []model.Role{
		{Name: "Administrator", Description: "Full access, including accounts and system settings.", Builtin: true, Permissions: []string{Admin}},
		{Name: "Operator", Description: "Runs the gateway: proxies, policies, certificates, feeds and streaming, without account or system changes.", Builtin: true,
			Permissions: withWrites("policies", "proxies", "streaming", "certificates", "sources")},
		{Name: "Read-only", Description: "Sees every page and setting but cannot change anything.", Builtin: true, Permissions: allRead()},
		{Name: "Viewer", Description: "Sees the dashboard and traffic logs only.", Builtin: true,
			Permissions: []string{Permission("dashboard", "read"), Permission("traffic", "read")}},
	}
}

// Administrator is the role name every existing account keeps after upgrade.
const Administrator = "Administrator"
