// GET /api/ha. The page renders every card from this plus the diagnostics and
// the console's own action history.
export interface HAStatus {
  enabled: boolean;
  boot_enabled: boolean;
  paired: boolean;
  cluster_id?: string;
  role: string;
  state: string;
  serving: boolean;
  epoch: number;
  peer?: string;
  peer_fingerprint?: string;
  reason?: string;
  updated_at?: string;
  can_write?: boolean;
  max_failovers_per_hour?: number;
}

export interface HAEventItem {
  at: string;
  action: string;
  ok: boolean;
  error?: string;
  epoch?: number;
  duration_ms?: number;
}

export interface HADiagnostics {
  enabled: boolean;
  role: string;
  state: string;
  serving: boolean;
  epoch: number;
  peer?: string;
  outbox?: { depth: number; bytes: number; pending_by_kind?: Record<string, number>; oldest?: string };
  ack?: { seq: number; at?: string };
}

export interface SetupStatus {
  needs_setup: boolean;
  base_domain: string;
  version: string;
  geoip: boolean;
  kernel: { active: boolean; reason: string };
  wan_ip?: string;
  wan_port?: number;
  lan_ip?: string;
  gui_port?: number;
  wan_iface?: string;
  lan_iface?: string;
}

export interface UpdateAdvisory {
  id: string;
  severity: string;
  score?: string;
  summary: string;
}

export interface UpdatePackage {
  name: string;
  role?: string;
  current?: string;
  candidate?: string;
  status: string;
  severity?: string;
  security: boolean;
  advisories?: UpdateAdvisory[];
  can_update: boolean;
  note?: string;
}

export interface UpdatesSnapshot {
  available: boolean;
  reason?: string;
  platform?: string;
  container: boolean;
  checked_at?: string;
  packages: UpdatePackage[];
  advisory_error?: string;
  helper_ready: boolean;
  helper_error?: string;
  updating: boolean;
  app_version: string;
  app_commit: string;
  app_build_date: string;
  go_version: string;
  app_update_available: boolean;
  app_remote_version?: string;
  app_remote_commit?: string;
  app_remote_date?: string;
  app_remote_url?: string;
  app_remote_branch?: string;
  app_update_error?: string;
  app_update_supported: boolean;
  app_update_reason?: string;
  app_source_dir?: string;
  app_updating: boolean;
  app_last_update?: { status: string; at?: string; message?: string };
}

export interface TailscaleStatus {
  available: boolean;
  ip: string;
  error: string;
  admin_enabled: boolean;
  admin_active: boolean;
  admin_url: string;
  admin_error?: string;
  proxy_enabled: boolean;
  proxy_active: boolean;
  proxy_addr?: string;
  proxy_error?: string;
  dns_enabled: boolean;
  dns_active: boolean;
  dns_addr?: string;
  dns_error?: string;
  restart_required: boolean;
  base_domain: string;
  gui_port: number;
  wan_port: number;
}

export interface CloudflareCheck {
  id: string;
  label: string;
  ok: boolean;
  detail?: string;
}

export interface CloudflareApp {
  hostname: string;
  enabled: boolean;
  published: boolean;
  has_cert: boolean;
  service: string;
  origin_server_name: string;
  no_tls_verify: boolean;
}

export interface CloudflareAppsView {
  site: string;
  tunnel_id: string;
  connected: boolean;
  wan_port: number;
  apps: CloudflareApp[];
  checks: Record<string, CloudflareCheck[]>;
  checked: Record<string, string>;
}

export interface CloudflareStatus {
  enabled: boolean;
  installed: boolean;
  version: string;
  state: "stopped" | "starting" | "running" | "error";
  connections: number;
  error?: string;
  token_set: boolean;
  token_tail?: string;
  tunnel_id: string;
  strict_origin: boolean;
  metrics_addr: string;
  container: boolean;
  helper_ready: boolean;
  install_supported: boolean;
  install_reason?: string;
  install_running: boolean;
  install_output?: string;
  install_error?: string;
  console_host: string;
  gui_port: number;
  gui_tls: boolean;
  restart_required: boolean;
  log: string[];
  checks: CloudflareCheck[] | null;
  checks_at?: string;
}

export interface Me {
  username: string;
  csrf: string;
  version: string;
  base_domain: string;
  totp_enabled: boolean;
  email: string;
  role: string;
  permissions: string[];
  // The effective HA switch (boot switch AND stored setting) and, while it is
  // on, this node's role. The nav item and the page gate on the first.
  ha_enabled?: boolean;
  ha_role?: string;
  // The site this console was reached on, and the sites its role may switch
  // between. A host_admin has no list and no switcher.
  site?: string;
  site_name?: string;
  can_switch?: boolean;
  sites?: { slug: string; name: string; console_host: string }[];
}

// One tenant as the Sites page reads it: identity, console host and the rows
// that belong to it.
export interface Site {
  slug: string;
  name: string;
  console_host: string;
  enabled: boolean;
  created_at: string;
  current: boolean;
  hostnames: string[];
  retention_days: string;
  admins: number;
}

// One browser that skipped the authenticator because it was trusted.
export interface TrustedDevice {
  id: string;
  ua: string;
  ip: string;
  created_at: string;
  expires_at: string;
  current: boolean;
}

export interface PermissionArea {
  key: string;
  label: string;
}

export interface Role {
  id: number;
  name: string;
  description: string;
  builtin: boolean;
  permissions: string[];
}

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  role_id: number;
  role: string;
  totp_enabled: boolean;
  created_at: string;
}

// can() mirrors the server's permission check so the console hides what the
// signed-in role cannot use.
export function can(perms: string[] | undefined, permission: string): boolean {
  const list = perms ?? [];
  if (list.includes("*")) return true;
  if (list.includes(permission)) return true;
  if (permission.endsWith(".read")) return list.includes(permission.slice(0, -5) + ".write");
  return false;
}

export interface ProtectionProfile {
  id: number;
  name: string;
  builtin: boolean;
  force_https: boolean;
  hsts: boolean;
  hsts_subdomains: boolean;
  frame_options: string;
  nosniff: boolean;
  referrer_policy: string;
  csp: string;
  permissions_policy: string;
  hide_server: boolean;
}

export interface AccessRule {
  policy_id: number;
  role: "allow" | "deny" | "inherit";
}

export interface AccessProfile {
  id: number;
  name: string;
  rules: AccessRule[];
  list_ids: number[];
  waf_profile_id: number | null;
  protection_profile_id: number | null;
}

// A named blocklist or whitelist an access profile attaches as a whole.
export interface AccessList {
  id: number;
  kind: "blocklist" | "whitelist";
  name: string;
  ips: string;
  countries: string;
  created_at?: string;
}

export interface AuthProvider {
  id: number;
  name: string;
  kind: string;
  verify_url: string;
  login_url: string;
  header: string;
  has_secret: boolean;
}

export interface DeliverySummary {
  id: number;
  kind: string;
  state: "pending" | "delivered" | "failed";
  attempts: number;
  last_status: number;
  last_error?: string;
  created_at: string;
  delivered_at?: string;
}

export interface AgentLink {
  id: number;
  name: string;
  endpoint: string;
  has_secret: boolean;
  enabled: boolean;
  created_at: string;
  last_delivery?: DeliverySummary;
}

export interface AnomalyEvent {
  id: number;
  kind: string;
  proxy_id: number;
  proxy_host: string;
  window_start: string;
  window_seconds: number;
  value: number;
  baseline: number;
  detail: string;
  state: string;
  created_at: string;
  last_seen: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface AnomalyConfig {
  enabled: boolean;
  egress_mb: number;
  egress_factor: number;
  rate_rps: number;
  rate_factor: number;
  auth_burst: number;
}

export interface IntelLookup {
  ip: string;
  feed: { id: number; name: string; action: string } | null;
  ban: { cidr: string; reason: string; source: string; permanent: boolean; expires_at?: string } | null;
}

export interface Proxy {
  id: number;
  hostname: string;
  enabled: boolean;
  cert_id?: number | null;
  profile_id?: number | null;
  protection_profile_id?: number | null;
  access_profile_id?: number | null;
  auth_provider_id?: number | null;
  gate_mode: string;
  gate_totp_hint?: string;
  fingerprint: string;
  bot_level: string;
  maintenance: boolean;
  waf_mode: string;
  created_at: string;
  upstreams: Upstream[];
  routes: Route[];
  gate_users: string[];
  requests: number;
  blocked: number;
}

export interface Upstream {
  id?: number;
  url: string;
  weight: number;
  enabled: boolean;
}

export interface Route {
  id?: number;
  kind: string;
  match: string;
  target: string;
  strip_prefix: boolean;
  priority: number;
}

export interface Profile {
  id: number;
  name: string;
  builtin: boolean;
  mode: string;
  responses: string;
  paranoia: number;
  anomaly: number;
  allowed_methods: string;
  max_body: number;
  exceptions: string;
  max_response: number;
  login_paths: string;
  login_rps: number;
  login_burst: number;
  admin_paths: string;
  admin_ips: string;
  // Per-bundle mode for this profile: off, log or block. An unset bundle logs
  // only, so installing one never starts refusing traffic on its own.
  bundle_modes: Record<string, string>;
}

export interface BundleStatus {
  // The signed channel that installed the pack. Bundle names are unique across
  // providers because a profile switches them by name.
  provider?: string;
  name: string;
  version: string;
  rules: number;
  size: number;
  sha256: string;
  // A pack that ships in the binary rather than arriving from a signed
  // channel; it is listed even before an administrator enables it.
  builtin?: boolean;
  description?: string;
  enabled: boolean;
  installed_at?: string | null;
  modes: Record<string, number>;
}

export interface BundleProvider {
  name: string;
  configured: boolean;
  url?: string;
  key_id?: string;
  last_check?: string | null;
  next_check?: string | null;
  sequence: number;
  error?: string;
}

export interface BundlesSnapshot {
  // True when at least one provider can fetch; the per-provider state carries
  // the URL, key, sequence and error.
  configured: boolean;
  providers: BundleProvider[];
  bundles: BundleStatus[];
}

export interface BundleHit {
  rule_id: number;
  provider?: string;
  bundle?: string;
  version?: string;
  message: string;
  hits: number;
  addresses: number;
  // What the requests got, which can differ from the profile modes: one site
  // may block a bundle while another only logs it.
  blocked: number;
  logged: number;
  last_seen: string;
  modes: Record<string, number>;
}

export interface Preset {
  id: string;
  name: string;
  description: string;
  methods: string;
  max_body: number;
  max_response: number;
  login_paths: string;
  login_rps: number;
  login_burst: number;
  admin_paths: string;
  admin_ips: string;
  exceptions: string;
  notes: string[];
}

export interface Policy {
  id: number;
  scope: string;
  proxy_id?: number | null;
  kind: string;
  value: string;
  action: string;
  priority: number;
  enabled: boolean;
  note: string;
}

export interface PolicyPreflight {
  kind: string;
  value: string;
  hours: number;
  scanned: number;
  matched: number;
  allowed: number;
  blocked: number;
  addresses: number;
  hosts: string[];
  samples: { ts: string; src_ip: string; host: string; method: string; path: string; stage: string; action: string }[];
  notes: string[];
}

export interface Ban {
  id: number;
  cidr: string;
  reason: string;
  source: string;
  permanent: boolean;
  hits: number;
  created_by: string;
  created_at: string;
  expires_at?: string | null;
}

// Named whitelist/blocklist profiles attached to every proxy.
export interface GlobalLists {
  lists: AccessList[];
  whitelist_ids: number[];
  blocklist_ids: number[];
}

export interface ASNSuggestion {
  id: string;
  name: string;
  asns: number[];
  note: string;
}

export interface ASNRecommendations {
  hosting: ASNSuggestion;
  vpn: ASNSuggestion[];
}

export interface Feed {
  id: number;
  name: string;
  url: string;
  action: string;
  interval_s: number;
  enabled: boolean;
  builtin: boolean;
  local?: boolean;
  filename?: string;
  last_fetch?: string | null;
  last_count: number;
  state: string;
  last_error?: string;
}

export interface GeoIPStatus {
  available: boolean;
  city: boolean;
  asn: boolean;
  city_path?: string;
  asn_path?: string;
  city_updated?: string;
  asn_updated?: string;
  installing: boolean;
  last_error?: string;
  attribution: string;
}

export interface Cert {
  id: number;
  domains: string;
  provider: string;
  status: string;
  expires_at: string;
  renews_at?: string;
  renew_mode: string;
  challenge: string;
  wildcard: boolean;
  last_error?: string;
}

export interface HeaderCheck {
  setting: string;
  header: string;
  backend: string;
  profile: string;
  verdict: string;
  advice: string;
}

export interface HeaderAudit {
  proxy: string;
  upstream: string;
  status: number;
  self_signed: boolean;
  headers: Record<string, string>;
  checks: HeaderCheck[];
  summary: string[];
}

export interface Event {
  id: number;
  ts: string;
  host: string;
  src_ip: string;
  country: string;
  asn: number;
  method: string;
  path: string;
  status: number;
  bytes_in: number;
  bytes_out: number;
  latency_ms: number;
  stage: string;
  rule_id: string;
  rule_msg: string;
  action: string;
  ua: string;
}

export interface AnalyticsBucket {
  bucket: string;
  requests: number;
  success: number;
  errors: number;
  bytes_in: number;
  bytes_out: number;
}

export interface Analytics {
  from: string;
  to: string;
  totals: { requests: number; blocked: number; bytes_in: number; bytes_out: number; src_ips: number };
  series: AnalyticsBucket[];
  proxies: {
    proxy_id: number;
    host: string;
    requests: number;
    success: number;
    errors: number;
    bytes_in: number;
    bytes_out: number;
  }[];
  countries: { name: string; count: number }[];
  stages: { name: string; count: number }[];
}

export interface UptimeTarget {
  id: string;
  proxy_id: number;
  proxy_host: string;
  url: string;
  state: "up" | "down" | "unknown";
  status_code: number;
  latency_ms: number;
  last_check: string;
  last_change: string;
  error: string;
  uptime_24: number;
  checks_24: number;
}

export interface Uptime {
  process_uptime_s: number;
  targets: UptimeTarget[];
  proxies: { proxy_id: number; host: string; state: string; targets: number; up: number }[];
  checked_at: string;
}

export interface GlobePoint {
  country: string;
  host: string;
  category: string;
  count: number;
  last_seen: string;
  lat: number;
  lon: number;
}

export interface GlobeHit {
  id: number;
  ts: string;
  country: string;
  host: string;
  category: string;
  status: number;
  lat: number;
  lon: number;
}

export interface Iface {
  name: string;
  rx_bps: number;
  tx_bps: number;
  rx_pps: number;
  tx_pps: number;
  rx_total: number;
  tx_total: number;
}

export interface Flow {
  in_bps: number;
  out_bps: number;
  in_total: number;
  out_total: number;
}

export interface MetricsHistoryPoint {
  ts: number;
  wan_rx: number;
  wan_tx: number;
  lan_rx: number;
  lan_tx: number;
  proxy_rx: number;
  proxy_tx: number;
  host_rx: number;
  host_tx: number;
}

export interface Metrics {
  ts: string;
  wan: Iface;
  lan: Iface;
  history: MetricsHistoryPoint[];
  sessions: { active: number; established: number; time_wait: number; available: boolean };
  proxies: Record<string, { requests: number; blocked: number; bytes_in: number; bytes_out: number }>;
  dual_nic: boolean;
  proxy: Flow;
  host: Flow;
  inflight: number;
  max_inflight: number;
  shed: number;
}

export interface GateUser {
  id: number;
  username: string;
  totp_enabled: boolean;
  created_at: string;
}

export interface IPSummary {
  ip: string;
  country: string;
  asn: number;
  requests: number;
  blocked: number;
  bytes_out: number;
  hosts: number;
  first_seen: string;
  last_seen: string;
  banned: boolean;
  permanent: boolean;
  ban_id?: number;
  ban_reason?: string;
  ban_source?: string;
  ban_expires?: string | null;
}

export interface IPDetail {
  summary: IPSummary;
  events: Event[];
  total: number;
}

export interface StreamingSession {
  addr: string;
  port: number;
  protocol: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  started: string;
}

export interface StreamingService {
  id: string;
  label: string;
  default_port: number;
  enabled: boolean;
  listen_ip: string;
  protocol: string;
  port: number;
  port_count: number;
  upstream: string;
  upstream_port: number;
  allow: string[];
  max_conns: number;
  max_per_source: number;
  idle_seconds: number;
  max_datagram: number;
  list_ids?: number[];
  bound: boolean;
  listen_addr: string;
  upstream_base: string;
  active: number;
  active_sessions: number;
  total: number;
  blocked: number;
  banned: number;
  dropped: number;
  oversize: number;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  refused: number;
  sessions: StreamingSession[];
  last_error: string;
  default: { listen_ip: string; port: number; upstream: string; max_conns: number };
}

export interface CrowdSecStatus {
  configured: boolean;
  lapi_configured?: boolean;
  lapi?: string;
  mode?: string;
  last_poll?: string;
  last_error?: string;
  applied: number;
  config?: {
    enabled: boolean;
    url: string;
    key_set: boolean;
    attribution?: string;
  };
}

export interface CrowdSecInstall {
  supported: boolean;
  reason?: string;
  platform?: string;
  container: boolean;
  installed: boolean;
  engine_running: boolean;
  version?: string;
  console_enrolled: boolean;
  /** enrolled = accepted by the console, pending = awaiting acceptance, none, unknown */
  console_state: "enrolled" | "pending" | "none" | "unknown";
  console_detail?: string;
  console_plan?: string;
  console_capi?: string;
  console_decision?: string;
  console_decision_active: boolean;
  console_papi?: string;
  lapi: string;
  running: boolean;
  error?: string;
  output?: string;
}

export interface CrowdSecBlocklistRow {
  reason: string;
  origin: string;
  action: string;
  count: number;
}

export interface CrowdSecBlocklists {
  available: boolean;
  reason?: string;
  rows: CrowdSecBlocklistRow[];
  total: number;
  raw?: string;
}

export interface GateFailure {
  ip: string;
  username: string;
  proxy_id: number;
  proxy_host?: string;
  attempts: number;
  first: string;
  last: string;
  blocked: boolean;
  blocked_permanent: boolean;
  blocked_reason?: string;
  blocked_source?: string;
}

export interface MCPToken {
  id: number;
  name: string;
  prefix: string;
  created_by: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  scopes: string[];
}

export interface MCPStatus {
  endpoint: string;
  env_token: boolean;
  token_count: number;
  tokens: MCPToken[];
  protocols: string[];
}

export interface AuditEntry {
  id: number;
  ts: string;
  user: string;
  action: string;
  detail: string;
  ip: string;
  entity?: string;
}

export interface AuditSnapshot {
  audit_id: number;
  entity: string;
  entity_id: number;
  before?: string;
  after?: string;
}

export interface SimStage {
  stage: string;
  verdict: string;
  reason?: string;
  rule_ids?: string[];
  skipped?: string;
}

export interface SimMatch {
  rule_id: number;
  message: string;
  severity: number;
  disruptive: boolean;
}

export interface SimException {
  profile_id: number;
  profile: string;
  rule_id: number;
  other_hosts: string[];
}

export interface SimResult {
  verdict: { action: string; stage: string; rule: string; reason: string; status: number };
  stages: SimStage[];
  matches: SimMatch[];
  upstream?: string;
  route?: string;
  truncated: boolean;
  notes: string[];
  exception?: SimException;
}
