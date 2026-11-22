export type NavItem = { id: string; label: string; icon: string; permission?: string };

// Grouped so the sidebar reads as a few areas instead of one long list.
// Settings and Account stay pinned at the bottom.
export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: "◎", permission: "dashboard.read" },
      { id: "statistics", label: "Statistics", icon: "▤", permission: "traffic.read" },
    ],
  },
  {
    title: "Traffic",
    items: [
      { id: "proxies", label: "Proxies", icon: "⇄", permission: "proxies.read" },
      { id: "streaming", label: "Streaming", icon: "▶", permission: "streaming.read" },
      { id: "policies", label: "Policies", icon: "⛨", permission: "policies.read" },
      { id: "sources", label: "Sources", icon: "◉", permission: "sources.read" },
      { id: "logs", label: "Logs", icon: "≡", permission: "traffic.read" },
    ],
  },
  {
    title: "Security",
    items: [
      { id: "anomalies", label: "Anomaly events", icon: "⚠", permission: "traffic.read" },
      { id: "access", label: "Access gate", icon: "⚿", permission: "policies.read" },
      { id: "intel", label: "Threat intel", icon: "☣", permission: "sources.read" },
      { id: "crowdsec", label: "CrowdSec", icon: "◈", permission: "sources.read" },
      { id: "certs", label: "Certificates", icon: "▣", permission: "certificates.read" },
    ],
  },
  {
    title: "System",
    items: [
      { id: "agent", label: "AI Agent Access", icon: "⌘", permission: "settings.read" },
      { id: "notifications", label: "Notifications", icon: "✉", permission: "settings.read" },
      { id: "updates", label: "Updates", icon: "⇪", permission: "system.read" },
      { id: "tailscale", label: "Tailscale", icon: "⌁", permission: "settings.read" },
    ],
  },
];

export const NAV_UTILITY: NavItem[] = [
  { id: "settings", label: "Settings", icon: "⚙", permission: "settings.read" },
  { id: "account", label: "Account", icon: "⊙" },
];

export const NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), ...NAV_UTILITY];

// pageFromHash maps "#/crowdsec" to a page id. An empty or unknown hash opens
// the dashboard, so a stale bookmark still lands somewhere usable.
export function pageFromHash(hash: string): string {
  const id = hash.replace(/^#\/?/, "").replace(/\/+$/, "");
  return NAV.some((n) => n.id === id) ? id : "dashboard";
}
