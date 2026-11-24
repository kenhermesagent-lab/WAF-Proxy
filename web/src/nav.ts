import type { IconName } from "./components/Icon";
import { can, type Me } from "./types";

export type NavTab = { id: string; label: string; permission?: string; hostOnly?: boolean };
export type NavItem = {
  id: string;
  label: string;
  icon: IconName;
  permission?: string;
  // Roles that must not see the item even when it holds the permission,
  // because the page would act on the host rather than on its own site.
  hideFor?: string[];
  // Host-wide pages are absent on a tenant console even when its role has the
  // wildcard permission.
  hostOnly?: boolean;
  // A switch this item depends on. The item is absent until /api/me reports it,
  // so a deep link is the only way to reach the page while it is off.
  requires?: "ha_enabled";
  hint?: string;
  tabs?: NavTab[];
  defaultTab?: string;
};

export type Route = { page: string; tab: string };

// Grouped so the sidebar reads as a few areas instead of one long list.
// Settings and Account stay pinned at the bottom.
export const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: "dashboard", permission: "dashboard.read", hint: "Live traffic and blocked requests" },
      {
        id: "statistics",
        label: "Statistics",
        icon: "chart",
        permission: "traffic.read",
        hint: "Traffic, outcomes and uptime",
        defaultTab: "overview",
        tabs: [
          { id: "overview", label: "Overview" },
          { id: "traffic", label: "Traffic" },
          { id: "gate", label: "Access gate logins" },
          { id: "util", label: "Utilization" },
        ],
      },
    ],
  },
  {
    title: "Traffic",
    items: [
      {
        id: "proxies",
        label: "Proxies",
        icon: "proxies",
        permission: "proxies.read",
        hint: "Hostnames, certificates and streaming forwards",
        defaultTab: "sites",
        tabs: [
          { id: "sites", label: "Hostnames" },
          { id: "certs", label: "Certificates", permission: "certificates.read" },
          { id: "streaming", label: "Streaming", permission: "streaming.read" },
        ],
      },
      {
        id: "policies",
        label: "Policies",
        icon: "shield",
        permission: "policies.read",
        hint: "Bans, profiles and lists",
        defaultTab: "bans",
        tabs: [
          { id: "bans", label: "Bans" },
          { id: "profiles", label: "Profiles" },
          { id: "access", label: "Access profiles" },
          { id: "lists", label: "Lists" },
          { id: "bots", label: "Bot filter" },
        ],
      },
      { id: "logs", label: "Logs", icon: "logs", permission: "traffic.read", hint: "Request event log" },
    ],
  },
  {
    title: "Threat",
    items: [
      {
        id: "intel",
        label: "Threat intel",
        icon: "intel",
        permission: "sources.read",
        hint: "Feeds, lookups and CrowdSec",
        defaultTab: "feeds",
        tabs: [
          { id: "feeds", label: "Feeds" },
          { id: "lookup", label: "Lookup" },
          { id: "explorer", label: "Sources" },
          { id: "bundles", label: "Bundles", hostOnly: true },
          { id: "crowdsec", label: "CrowdSec", hostOnly: true },
        ],
      },
      { id: "anomalies", label: "Anomalies", icon: "alert", permission: "traffic.read", hint: "Behavioural detections" },
    ],
  },
  {
    title: "Access",
    items: [
      {
        id: "access",
        label: "Access gate",
        icon: "lock",
        permission: "policies.read",
        hint: "Gate accounts and identity providers",
        defaultTab: "accounts",
        tabs: [
          { id: "accounts", label: "Accounts" },
          { id: "providers", label: "Identity providers" },
        ],
      },
      { id: "activity", label: "Activity", icon: "clock", permission: "traffic.read", hint: "Audited changes with diffs and rollback" },
    ],
  },
  {
    title: "System",
    items: [
      { id: "agent", label: "Agent access", icon: "terminal", permission: "settings.read", hideFor: ["host_admin"], hint: "MCP endpoint and tokens" },
      { id: "notifications", label: "Notifications", icon: "mail", permission: "settings.read", hint: "Alert channels" },
      { id: "tailscale", label: "Tailscale", icon: "network", permission: "settings.read", hideFor: ["host_admin"], hint: "Private network access" },
      {
        id: "cloudflare",
        label: "Cloudflare",
        icon: "cloud",
        permission: "settings.read",
        hideFor: ["host_admin"],
        hint: "Public tunnel and Access",
        defaultTab: "admin",
        tabs: [
          { id: "admin", label: "Admin" },
          { id: "apps", label: "Apps" },
        ],
      },
      { id: "ha", label: "High availability", icon: "server", permission: "ha.read", requires: "ha_enabled", hideFor: ["host_admin"], hostOnly: true, hint: "Pairing, moves and witness state" },
      { id: "sites", label: "Sites", icon: "shield", permission: "sites.read", hint: "Tenants, console hosts and their hostnames" },
    ],
  },
];

export const NAV_UTILITY: NavItem[] = [
  {
    id: "settings",
    label: "Settings",
    icon: "settings",
    permission: "settings.read",
    hint: "Network, protection, backup, updates and readiness",
    defaultTab: "network",
    tabs: [
      { id: "network", label: "Network" },
      { id: "updates", label: "Updates" },
      { id: "protection", label: "Protection" },
      { id: "retention", label: "Retention" },
      { id: "ha", label: "High availability", hostOnly: true },
      { id: "backup", label: "Backup" },
      { id: "runtime", label: "Runtime" },
      { id: "geoip", label: "GeoIP" },
      { id: "threat-intel", label: "Threat intel" },
      { id: "activity", label: "Activity" },
      { id: "readiness", label: "Readiness" },
      { id: "about", label: "About" },
    ],
  },
  { id: "account", label: "Account", icon: "user", hint: "Password, authenticator and team" },
];

export const NAV: NavItem[] = [...NAV_GROUPS.flatMap((g) => g.items), ...NAV_UTILITY];

// The old page ids that the restructure folded into a parent page's tab. Kept
// so a bookmark or an in-app link written before the move still lands right.
const LEGACY_ROUTES: Record<string, Route> = {
  proxies: { page: "proxies", tab: "sites" },
  sources: { page: "intel", tab: "explorer" },
  intel: { page: "intel", tab: "feeds" },
  crowdsec: { page: "intel", tab: "crowdsec" },
  certs: { page: "proxies", tab: "certs" },
  streaming: { page: "proxies", tab: "streaming" },
  updates: { page: "settings", tab: "updates" },
  readiness: { page: "settings", tab: "readiness" },
};

// routeFromHash maps "#/intel/explorer?ip=1.2.3.4" to { page: "intel", tab:
// "explorer" }. A bare page hash opens its default tab, and an unknown tab
// falls back to it. An empty or unknown page opens the dashboard.
export function routeFromHash(hash: string): Route {
  const path = hash.split("?")[0].replace(/^#\/?/, "");
  const [id = "", wanted = ""] = path.split("/").filter(Boolean);
  const legacy = LEGACY_ROUTES[id];
  const item = NAV.find((n) => n.id === (legacy ? legacy.page : id));
  if (!item) return { page: "dashboard", tab: "" };

  const tabs = item.tabs ?? [];
  if (tabs.length === 0) return { page: item.id, tab: "" };

  const tab = tabs.some((t) => t.id === wanted)
    ? wanted
    : legacy && !wanted
      ? legacy.tab
      : item.defaultTab ?? tabs[0].id;
  return { page: item.id, tab };
}

// navAllowed is the one visibility rule for the sidebar and for a page reached
// by hash, so a hidden item and a refused deep link agree.
export function navAllowed(item: NavItem, me: Me | null): boolean {
  if (item.permission && !can(me?.permissions, item.permission)) return false;
  if ((item.hideFor ?? []).includes(me?.role ?? "")) return false;
  if (item.hostOnly && me?.site !== "default") return false;
  if (item.requires === "ha_enabled" && me?.ha_enabled !== true) return false;
  return true;
}

// tabAllowed applies the same permission and host-console rules to a tab.
export function tabAllowed(tab: NavTab, me: Me | null): boolean {
  if (tab.permission && !can(me?.permissions, tab.permission)) return false;
  if (tab.hostOnly && me?.site !== "default") return false;
  return true;
}

// href builds the canonical hash for a page and tab, so redirects and in-app
// links share one shape.
export function href(page: string, tab?: string): string {
  return `#/${page}${tab ? `/${tab}` : ""}`;
}
