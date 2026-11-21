export type NavItem = { id: string; label: string; icon: string };

// Grouped so the sidebar reads as a few areas instead of one long list.
// Settings and Account stay pinned at the bottom.
export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: "◎" },
      { id: "statistics", label: "Statistics", icon: "▤" },
    ],
  },
  {
    title: "Traffic",
    items: [
      { id: "proxies", label: "Proxies", icon: "⇄" },
      { id: "streaming", label: "Streaming", icon: "▶" },
      { id: "policies", label: "Policies", icon: "⛨" },
      { id: "sources", label: "Sources", icon: "◉" },
      { id: "logs", label: "Logs", icon: "≡" },
    ],
  },
  {
    title: "Security",
    items: [
      { id: "access", label: "Access gate", icon: "⚿" },
      { id: "intel", label: "Threat intel", icon: "☣" },
      { id: "crowdsec", label: "CrowdSec", icon: "◈" },
      { id: "certs", label: "Certificates", icon: "▣" },
    ],
  },
  {
    title: "System",
    items: [
      { id: "agent", label: "Agent access", icon: "⌘" },
      { id: "notifications", label: "Notifications", icon: "✉" },
      { id: "updates", label: "Updates", icon: "⇪" },
      { id: "tailscale", label: "Tailscale", icon: "⌁" },
    ],
  },
];

export const NAV_UTILITY: NavItem[] = [
  { id: "settings", label: "Settings", icon: "⚙" },
  { id: "account", label: "Account", icon: "⊙" },
];

export const NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), ...NAV_UTILITY];

// pageFromHash maps "#/crowdsec" to a page id. An empty or unknown hash opens
// the dashboard, so a stale bookmark still lands somewhere usable.
export function pageFromHash(hash: string): string {
  const id = hash.replace(/^#\/?/, "").replace(/\/+$/, "");
  return NAV.some((n) => n.id === id) ? id : "dashboard";
}
