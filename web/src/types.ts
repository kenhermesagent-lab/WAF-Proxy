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

export interface Me {
  username: string;
  csrf: string;
  version: string;
  base_domain: string;
  totp_enabled: boolean;
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

export interface AccessProfile {
  id: number;
  name: string;
  policy_ids: number[];
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

export interface AgentLink {
  id: number;
  name: string;
  endpoint: string;
  has_secret: boolean;
  enabled: boolean;
  created_at: string;
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
  paranoia: number;
  anomaly: number;
  allowed_methods: string;
  max_body: number;
  exceptions: string;
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
  wildcard: boolean;
  last_error?: string;
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

export interface StreamingService {
  id: string;
  label: string;
  default_port: number;
  enabled: boolean;
  listen_ip: string;
  port: number;
  upstream: string;
  allow: string[];
  max_conns: number;
  bound: boolean;
  listen_addr: string;
  active: number;
  total: number;
  blocked: number;
  banned: number;
  dropped: number;
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
}
