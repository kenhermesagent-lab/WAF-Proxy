package store

// TableClass says how a table crosses the HA link. The snapshot encoder and the
// classification test read the same map, so a new table cannot be forgotten.
type TableClass string

const (
	// ClassReplicated is configuration: sent whole, applied transactionally.
	ClassReplicated TableClass = "replicated"
	// ClassStreamed is per-row state: sessions, bans, audit, alerts.
	ClassStreamed TableClass = "streamed"
	// ClassLocal is node-local history or bookkeeping and never leaves the node.
	ClassLocal TableClass = "local"
)

// TableClasses covers every table the schema creates.
var TableClasses = map[string]TableClass{
	// Configuration.
	"sites":               ClassReplicated,
	"site_settings":       ClassReplicated,
	"settings":            ClassReplicated,
	"users":               ClassReplicated,
	"roles":               ClassReplicated,
	"profiles":            ClassReplicated,
	"protection_profiles": ClassReplicated,
	"access_profiles":     ClassReplicated,
	"access_lists":        ClassReplicated,
	"proxies":             ClassReplicated,
	"upstreams":           ClassReplicated,
	"routes":              ClassReplicated,
	"certificates":        ClassReplicated,
	"dns_credentials":     ClassReplicated,
	"auth_providers":      ClassReplicated,
	"console_auth":        ClassReplicated,
	"feeds":               ClassReplicated,
	"policies":            ClassReplicated,
	"gate_users":          ClassReplicated,
	"gate_acl":            ClassReplicated,
	"mcp_tokens":          ClassReplicated,
	"agent_links":         ClassReplicated,
	"invites":             ClassReplicated,
	"log_views":           ClassReplicated,
	"log_views_sites":     ClassReplicated,
	"audit_snapshots":     ClassReplicated,
	// The last good vulnerability snapshot travels with the configuration, so
	// a promoted standby does not answer "unknown" until its first sync.
	"vuln_sources":   ClassReplicated,
	"scan_schedules": ClassReplicated,

	// Streamed per-record state.
	"sessions":         ClassStreamed,
	"trusted_devices":  ClassStreamed,
	"password_resets":  ClassStreamed,
	"gate_sessions":    ClassStreamed,
	"gate_failures":    ClassStreamed,
	"username_bans":    ClassStreamed,
	"bans":             ClassStreamed,
	"audit":            ClassStreamed,
	"alerts":           ClassStreamed,
	"agent_deliveries": ClassStreamed,
	"anomaly_events":   ClassStreamed,

	// Node-local history and bookkeeping. The outbox is a node's own stream;
	// sending it in a snapshot would duplicate every pending change.
	// Scan evidence is this node's own history, like the event log; findings
	// will travel with the configuration that produced them.
	"scan_runs":     ClassLocal,
	"scan_evidence": ClassLocal,
	"schema_meta":   ClassLocal,
	"admin_prefs":   ClassLocal,
	"events":        ClassLocal,
	"flows":         ClassLocal,
	"utilization":   ClassLocal,
	"ha_outbox":     ClassLocal,
	"ha_peer_ack":   ClassLocal,
	"ha_applied":    ClassLocal,
}

// ClassOf reports the class of a table.
func ClassOf(table string) (TableClass, bool) {
	c, ok := TableClasses[table]
	return c, ok
}
