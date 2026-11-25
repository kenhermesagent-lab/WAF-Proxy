package model

import "time"

// ScanRun is one execution of the security scanner against one hostname.
type ScanRun struct {
	ID        int64      `json:"id"`
	SiteID    int64      `json:"site_id"`
	Target    string     `json:"target"`
	Trigger   string     `json:"trigger"`
	Actor     string     `json:"actor"`
	Path      string     `json:"path"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Verdicts  string     `json:"verdicts,omitempty"`
	Skipped   string     `json:"skipped_reason,omitempty"`
	AgentNode string     `json:"agent_node,omitempty"`
}

// ScanEvidence is one probe's verdict. It keeps hashes and a redacted request
// line, never a credential or a response body.
type ScanEvidence struct {
	RunID      int64   `json:"run_id"`
	Seq        int     `json:"seq"`
	Stage      string  `json:"stage"`
	Class      string  `json:"class"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Verdict    string  `json:"verdict"`
	WANStatus  int     `json:"wan_status"`
	UpStatus   int     `json:"upstream_status"`
	WANHash    string  `json:"wan_hash,omitempty"`
	UpHash     string  `json:"upstream_hash,omitempty"`
	Similarity float64 `json:"similarity,omitempty"`
	Detail     string  `json:"detail,omitempty"`
	Note       string  `json:"note,omitempty"`
}

// ScanSchedule is one site's scan cadence and triggers. Signature is what the
// last run recorded, so the next tick can skip a site that has not changed.
type ScanSchedule struct {
	SiteID    int64    `json:"site_id"`
	Cadence   string   `json:"cadence"`
	Hour      int      `json:"hour"`
	Day       int      `json:"day"`
	Enabled   bool     `json:"enabled"`
	Triggers  []string `json:"triggers,omitempty"`
	Signature string   `json:"-"`
	UpdatedBy string   `json:"updated_by,omitempty"`
}

// ScanFinding is one issue a scan proved, or could not rule out. Key is stable
// across runs so a finding can be tracked as new, still open or resolved
// without diffing evidence rows.
type ScanFinding struct {
	Key            string   `json:"key"`
	SiteID         int64    `json:"site_id,omitempty"`
	Target         string   `json:"target,omitempty"`
	Stage          string   `json:"stage"`
	Class          string   `json:"class"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss,omitempty"`
	Exploitation   string   `json:"exploitation,omitempty"`
	CVEIDs         []string `json:"cve_ids,omitempty"`
	Product        string   `json:"product,omitempty"`
	Version        string   `json:"version,omitempty"`
	Recommendation string   `json:"recommendation"`
	Note           string   `json:"note,omitempty"`
	// State is open, accepted or resolved. FirstSeen survives every merge.
	State     string    `json:"state,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
}
