import type { IconName } from "./components/Icon";

export type NavItem = { id: string; label: string; icon: IconName; permission?: string; hint?: string };

// Grouped so the sidebar reads as a few areas instead of one long list.
// Settings and Account stay pinned at the bottom.
export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: "dashboard", permission: "dashboard.read", hint: "Live traffic and blocked requests" },
      { id: "statistics", label: "Statistics", icon: "chart", permission: "traffic.read", hint: "Traffic, outcomes and uptime" },
    ],
  },
  {
    title: "Traffic",
    items: [
      { id: "proxies", label: "Proxies", icon: "proxies", permission: "proxies.read", hint: "Sites, upstreams and certificates" },
      { id: "streaming", label: "Streaming", icon: "play", permission: "streaming.read", hint: "Media and long-lived streams" },
      { id: "policies", label: "Policies", icon: "shield", permission: "policies.read", hint: "Bans, lists and WAF profiles" },
      { id: "sources", label: "Sources", icon: "radio", permission: "sources.read", hint: "Threat feeds and agents" },
      { id: "logs", label: "Logs", icon: "logs", permission: "traffic.read", hint: "Request event log" },
    ],
  },
  {
    title: "Security",
    items: [
      { id: "anomalies", label: "Anomaly events", icon: "alert", permission: "traffic.read", hint: "Behavioural detections" },
      { id: "activity", label: "Activity", icon: "clock", permission: "traffic.read", hint: "Audited changes with diffs and rollback" },
      { id: "access", label: "Access gate", icon: "lock", permission: "policies.read", hint: "Gate accounts and TOTP" },
      { id: "intel", label: "Threat intel", icon: "intel", permission: "sources.read", hint: "Feeds and lookups" },
      { id: "crowdsec", label: "CrowdSec", icon: "crowdsec", permission: "sources.read", hint: "Community decisions" },
      { id: "certs", label: "Certificates", icon: "certificate", permission: "certificates.read", hint: "ACME and TLS" },
    ],
  },
  {
    title: "System",
    items: [
      { id: "agent", label: "AI Agent Access", icon: "terminal", permission: "settings.read", hint: "MCP endpoint and tokens" },
      { id: "notifications", label: "Notifications", icon: "mail", permission: "settings.read", hint: "Alert channels" },
      { id: "updates", label: "Updates", icon: "upload", permission: "system.read", hint: "Application and packages" },
      { id: "tailscale", label: "Tailscale", icon: "network", permission: "settings.read", hint: "Private network access" },
    ],
  },
];

export const NAV_UTILITY: NavItem[] = [
  { id: "settings", label: "Settings", icon: "settings", permission: "settings.read", hint: "Network, protection and backup" },
  { id: "account", label: "Account", icon: "user", hint: "Password, authenticator and team" },
];

export const NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), ...NAV_UTILITY];

// pageFromHash maps "#/crowdsec" to a page id. An empty or unknown hash opens
// the dashboard, so a stale bookmark still lands somewhere usable.
export function pageFromHash(hash: string): string {
  const id = hash.split("?")[0].replace(/^#\/?/, "").replace(/\/+$/, "");
  return NAV.some((n) => n.id === id) ? id : "dashboard";
}
